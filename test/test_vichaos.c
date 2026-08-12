/*
 * test_vichaos.c — unit tests for the ViChaos v2 library.
 *
 * Covers:
 *   - single-shot round-trips (empty, small, large)
 *   - streaming round-trips (chunked, constant memory)
 *   - cross-compat: single-shot encrypt -> streaming decrypt and vice versa
 *   - negative cases: wrong password, tampered ciphertext, bad header,
 *     unsupported version, invalid arguments, invalid options
 *
 * Build:  gcc -Wall -Wextra -O2 -I../include test_vichaos.c ../libvichaos.a -lcrypto -o test_vichaos
 * Run:    ./test_vichaos
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vichaos.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg) do {                                               \
    checks++;                                                               \
    if (cond) {                                                             \
        printf("  PASS: %s\n", msg);                                        \
    } else {                                                                \
        printf("  FAIL: %s\n", msg);                                        \
        failures++;                                                         \
    }                                                                       \
} while (0)

/* Deterministic pseudo-random fill (not crypto RNG; just test data). */
static void fill_pattern(uint8_t *buf, size_t len, uint32_t seed) {
    uint32_t x = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < len; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        buf[i] = (uint8_t)(x & 0xFF);
    }
}

/* ------------------------------------------------------------------ */
/* Single-shot round-trip                                              */
/* ------------------------------------------------------------------ */

static void test_single_shot_roundtrip(size_t len, const char *label) {
    printf("== single-shot round-trip (%s, %zu bytes) ==\n", label, len);

    uint8_t *plain = malloc(len ? len : 1);
    fill_pattern(plain, len, (uint32_t)(len + 1));

    uint8_t *enc = NULL;
    size_t enc_len = 0;
    vichaos_result_t r = vichaos_encrypt(plain, len, "test-password",
                                         strlen("test-password"), NULL,
                                         &enc, &enc_len);
    CHECK(r == VICHAOS_SUCCESS, "encrypt returns OK");
    if (r != VICHAOS_SUCCESS) { free(plain); return; }

    CHECK(enc_len == len + VICHAOS_OVERHEAD, "output length = len + overhead");
    CHECK(memcmp(enc, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN) == 0,
          "magic header present");
    CHECK(enc[VICHAOS_FORMAT_MAGIC_LEN] == VICHAOS_PAYLOAD_VERSION,
          "version byte = 2");

    uint8_t *dec = NULL;
    size_t dec_len = 0;
    r = vichaos_decrypt(enc, enc_len, "test-password",
                        strlen("test-password"), NULL, &dec, &dec_len);
    CHECK(r == VICHAOS_SUCCESS, "decrypt returns OK");
    if (r == VICHAOS_SUCCESS) {
        CHECK(dec_len == len, "decrypted length matches");
        CHECK(memcmp(dec, plain, len) == 0, "decrypted content matches");
        vichaos_free(dec);
    }

    vichaos_free(enc);
    free(plain);
}

/* ------------------------------------------------------------------ */
/* Streaming round-trip                                                */
/* ------------------------------------------------------------------ */

static void test_stream_roundtrip(size_t len, size_t chunk, const char *label) {
    printf("== streaming round-trip (%s, %zu bytes, chunk %zu) ==\n",
           label, len, chunk);

    uint8_t *plain = malloc(len ? len : 1);
    fill_pattern(plain, len, (uint32_t)(len ^ chunk));

    /* --- Encrypt --- */
    uint8_t header[VICHAOS_HEADER_OVERHEAD];
    size_t header_len = 0;
    vichaos_stream_t *s = vichaos_stream_encrypt_init("password",
                                                      strlen("password"), NULL,
                                                      header, &header_len);
    CHECK(s != NULL, "stream encrypt init");
    if (s == NULL) { free(plain); return; }
    CHECK(header_len == VICHAOS_HEADER_OVERHEAD, "header length correct");

    size_t enc_cap = len + VICHAOS_OVERHEAD;
    uint8_t *enc = malloc(enc_cap);
    memcpy(enc, header, header_len);
    size_t enc_pos = header_len;

    size_t off = 0;
    vichaos_result_t r = VICHAOS_SUCCESS;
    while (off < len) {
        size_t n = (len - off < chunk) ? (len - off) : chunk;
        size_t out_len = 0;
        r = vichaos_stream_encrypt_update(s, plain + off, n,
                                          enc + enc_pos, &out_len);
        if (r != VICHAOS_SUCCESS) break;
        enc_pos += out_len;
        off += n;
    }
    CHECK(r == VICHAOS_SUCCESS, "stream encrypt updates OK");

    uint8_t tag[VICHAOS_TAG_SIZE];
    size_t tag_len = 0;
    r = vichaos_stream_encrypt_final(s, tag, &tag_len);
    CHECK(r == VICHAOS_SUCCESS, "stream encrypt final OK");
    CHECK(tag_len == VICHAOS_TAG_SIZE, "tag length correct");
    memcpy(enc + enc_pos, tag, tag_len);
    enc_pos += tag_len;
    CHECK(enc_pos == len + VICHAOS_OVERHEAD, "total encrypted length correct");

    /* --- Decrypt --- */
    s = vichaos_stream_decrypt_init("password", strlen("password"), enc,
                                    VICHAOS_HEADER_OVERHEAD, NULL);
    CHECK(s != NULL, "stream decrypt init");
    if (s == NULL) { vichaos_free(enc); free(plain); return; }

    uint8_t *dec = malloc(len ? len : 1);
    size_t dec_pos = 0;
    size_t cipher_len = len; /* ciphertext == plaintext length for GCM */
    off = 0;
    r = VICHAOS_SUCCESS;
    while (off < cipher_len) {
        size_t n = (cipher_len - off < chunk) ? (cipher_len - off) : chunk;
        size_t out_len = 0;
        r = vichaos_stream_decrypt_update(s, enc + VICHAOS_HEADER_OVERHEAD + off,
                                          n, dec + dec_pos, &out_len);
        if (r != VICHAOS_SUCCESS) break;
        dec_pos += out_len;
        off += n;
    }
    CHECK(r == VICHAOS_SUCCESS, "stream decrypt updates OK");

    r = vichaos_stream_decrypt_final(s, enc + enc_pos - VICHAOS_TAG_SIZE,
                                     VICHAOS_TAG_SIZE);
    CHECK(r == VICHAOS_SUCCESS, "stream decrypt final (auth) OK");
    if (r == VICHAOS_SUCCESS) {
        CHECK(dec_pos == len, "stream decrypted length matches");
        CHECK(memcmp(dec, plain, len) == 0, "stream decrypted content matches");
    }

    free(dec);
    vichaos_free(enc);
    free(plain);
}

/* ------------------------------------------------------------------ */
/* Cross-compat: single-shot encrypt -> streaming decrypt              */
/* ------------------------------------------------------------------ */

static void test_cross_compat(void) {
    printf("== cross-compat: single-shot encrypt -> streaming decrypt ==\n");

    const size_t len = 5000;
    uint8_t *plain = malloc(len);
    fill_pattern(plain, len, 0xABCD);

    uint8_t *enc = NULL;
    size_t enc_len = 0;
    vichaos_result_t r = vichaos_encrypt(plain, len, "pw", 2, NULL,
                                         &enc, &enc_len);
    CHECK(r == VICHAOS_SUCCESS, "single-shot encrypt OK");

    vichaos_stream_t *s = vichaos_stream_decrypt_init("pw", 2, enc,
                                                      VICHAOS_HEADER_OVERHEAD,
                                                      NULL);
    CHECK(s != NULL, "stream decrypt init on single-shot payload");

    uint8_t *dec = malloc(len);
    size_t dec_pos = 0;
    size_t off = 0;
    while (off < len) {
        size_t n = (len - off < 777) ? (len - off) : 777;
        size_t out_len = 0;
        r = vichaos_stream_decrypt_update(s, enc + VICHAOS_HEADER_OVERHEAD + off,
                                          n, dec + dec_pos, &out_len);
        if (r != VICHAOS_SUCCESS) break;
        dec_pos += out_len;
        off += n;
    }
    CHECK(r == VICHAOS_SUCCESS, "stream decrypt updates OK");
    r = vichaos_stream_decrypt_final(s, enc + enc_len - VICHAOS_TAG_SIZE,
                                     VICHAOS_TAG_SIZE);
    CHECK(r == VICHAOS_SUCCESS, "stream decrypt final OK");
    CHECK(dec_pos == len && memcmp(dec, plain, len) == 0,
          "cross-compat content matches");

    free(dec);
    vichaos_free(enc);
    free(plain);
}

/* ------------------------------------------------------------------ */
/* Negative cases                                                      */
/* ------------------------------------------------------------------ */

static void test_negative(void) {
    printf("== negative cases ==\n");

    uint8_t plain[64];
    fill_pattern(plain, sizeof(plain), 42);

    uint8_t *enc = NULL;
    size_t enc_len = 0;
    vichaos_result_t r = vichaos_encrypt(plain, sizeof(plain), "pw",
                                         strlen("pw"), NULL, &enc, &enc_len);
    CHECK(r == VICHAOS_SUCCESS, "setup: encrypt OK");

    /* Wrong password */
    uint8_t *dec = NULL;
    size_t dec_len = 0;
    r = vichaos_decrypt(enc, enc_len, "wrong", 5, NULL, &dec, &dec_len);
    CHECK(r == VICHAOS_ERR_AUTH_FAIL, "wrong password -> AUTH_FAIL");
    CHECK(dec == NULL, "no output on auth failure");

    /* Tampered ciphertext byte */
    uint8_t *tampered = malloc(enc_len);
    memcpy(tampered, enc, enc_len);
    tampered[VICHAOS_HEADER_OVERHEAD + 5] ^= 0x01;
    r = vichaos_decrypt(tampered, enc_len, "pw", strlen("pw"), NULL,
                        &dec, &dec_len);
    CHECK(r == VICHAOS_ERR_AUTH_FAIL, "tampered ciphertext -> AUTH_FAIL");
    free(tampered);

    /* Tampered header (AAD) */
    uint8_t *tampered_hdr = malloc(enc_len);
    memcpy(tampered_hdr, enc, enc_len);
    tampered_hdr[0] ^= 0x01; /* corrupt magic */
    r = vichaos_decrypt(tampered_hdr, enc_len, "pw", strlen("pw"), NULL,
                        &dec, &dec_len);
    CHECK(r == VICHAOS_ERR_INVALID_PARAM, "corrupt magic -> INVALID_PARAM");
    free(tampered_hdr);

    /* Unsupported version */
    uint8_t *bad_ver = malloc(enc_len);
    memcpy(bad_ver, enc, enc_len);
    bad_ver[VICHAOS_FORMAT_MAGIC_LEN] = 99;
    r = vichaos_decrypt(bad_ver, enc_len, "pw", strlen("pw"), NULL,
                        &dec, &dec_len);
    CHECK(r == VICHAOS_ERR_VERSION_MISMATCH, "bad version -> VERSION_MISMATCH");
    free(bad_ver);

    /* Too short */
    r = vichaos_decrypt(enc, VICHAOS_OVERHEAD - 1, "pw", strlen("pw"), NULL,
                        &dec, &dec_len);
    CHECK(r == VICHAOS_ERR_INVALID_PARAM, "too short -> INVALID_PARAM");

    /* Invalid arguments */
    r = vichaos_encrypt(NULL, 10, "pw", strlen("pw"), NULL, &enc, &enc_len);
    CHECK(r == VICHAOS_ERR_NULL_PTR, "NULL data -> NULL_PTR");
    r = vichaos_encrypt(plain, sizeof(plain), NULL, 0, NULL, &enc, &enc_len);
    CHECK(r == VICHAOS_ERR_NULL_PTR, "NULL password -> NULL_PTR");
    r = vichaos_encrypt(plain, sizeof(plain), "pw", strlen("pw"), NULL,
                        NULL, &enc_len);
    CHECK(r == VICHAOS_ERR_NULL_PTR, "NULL output -> NULL_PTR");

    /* Invalid options */
    vichaos_options_t opts;
    vichaos_options_init(&opts);
    opts.kdf_iter = 1; /* below minimum */
    r = vichaos_encrypt(plain, sizeof(plain), "pw", strlen("pw"), &opts,
                                     &enc, &enc_len);
    CHECK(r == VICHAOS_ERR_INVALID_PARAM, "kdf_iter below min -> INVALID_PARAM");

    opts.kdf_iter = VICHAOS_MAX_KDF_ITER + 1;
    r = vichaos_encrypt(plain, sizeof(plain), "pw", strlen("pw"), &opts,
                                     &enc, &enc_len);
    CHECK(r == VICHAOS_ERR_INVALID_PARAM, "kdf_iter above max -> INVALID_PARAM");

    /* Custom kdf_iter round-trip */
    opts.kdf_iter = 200000;
    r = vichaos_encrypt(plain, sizeof(plain), "pw", strlen("pw"), &opts,
                                     &enc, &enc_len);
    CHECK(r == VICHAOS_SUCCESS, "custom kdf_iter encrypt OK");
    r = vichaos_decrypt(enc, enc_len, "pw", strlen("pw"), &opts,
                                     &dec, &dec_len);
    CHECK(r == VICHAOS_SUCCESS && dec_len == sizeof(plain) &&
          memcmp(dec, plain, sizeof(plain)) == 0,
          "custom kdf_iter round-trip OK");
    vichaos_free(dec);
    vichaos_free(enc);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("ViChaos v2 unit tests\n");
    printf("=====================\n\n");

    test_single_shot_roundtrip(0, "empty");
    test_single_shot_roundtrip(1, "1 byte");
    test_single_shot_roundtrip(100, "100 bytes");
    test_single_shot_roundtrip(1000000, "1 MiB");

    test_stream_roundtrip(0, 1024, "empty");
    test_stream_roundtrip(1, 1, "1 byte, chunk 1");
    test_stream_roundtrip(100000, 4096, "100 KiB, chunk 4 KiB");
    test_stream_roundtrip(3000000, 1000000, "3 MiB, chunk 1 MiB");

    test_cross_compat();
    test_negative();

    printf("\n=====================\n");
    printf("Total checks: %d, failures: %d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}