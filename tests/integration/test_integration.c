// ViChaos v3 — Integration tests (single-shot, streaming, cross-compat)
#include "../../include/vichaos.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg) do { checks++; if (cond) { printf("  PASS: %s\n", msg); } else { printf("  FAIL: %s\n", msg); failures++; } } while(0)

static void test_single_shot_roundtrip(size_t len, const char *label) {
    printf("== single-shot round-trip (%s, %zu bytes) ==\n", label, len);

    uint8_t *plain = malloc(len ? len : 1);
    memset(plain, 0xCD, len);

    uint8_t *enc = NULL;
    size_t enc_len = 0;
    vichaos_result_t r = vichaos_encrypt(plain, len, "testpw", 6, NULL, &enc, &enc_len);
    CHECK(r == VICHAOS_SUCCESS, "encrypt returns OK");
    if (r != VICHAOS_SUCCESS) { free(plain); return; }

    CHECK(enc_len == len + VICHAOS_OVERHEAD, "output length = len + overhead");
    CHECK(memcmp(enc, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN) == 0,
          "magic header present");
    CHECK(enc[VICHAOS_FORMAT_MAGIC_LEN] == VICHAOS_PAYLOAD_VERSION,
          "version byte correct");

    uint8_t *dec = NULL;
    size_t dec_len = 0;
    r = vichaos_decrypt(enc, enc_len, "testpw", 6, NULL, &dec, &dec_len);
    CHECK(r == VICHAOS_SUCCESS, "decrypt returns OK");
    if (r == VICHAOS_SUCCESS) {
        CHECK(dec_len == len, "decrypted length matches");
        if (len > 0) {
            CHECK(memcmp(dec, plain, len) == 0, "decrypted content matches");
        }
        free(dec);
    }

    free(enc);
    free(plain);
}

static void test_cross_compat(void) {
    printf("== cross-compat: single-shot encrypt -> stream decrypt ==\n");
    const char *plain = "cross-compat data";

    uint8_t *enc = NULL;
    size_t enc_len = 0;
    vichaos_result_t r = vichaos_encrypt((const uint8_t *)plain, strlen(plain),
                                         "pw", 2, NULL, &enc, &enc_len);
    CHECK(r == VICHAOS_SUCCESS, "single-shot encrypt OK");
    if (r != VICHAOS_SUCCESS) return;

    uint8_t header[VICHAOS_HEADER_OVERHEAD];
    memcpy(header, enc, VICHAOS_HEADER_OVERHEAD);

    vichaos_stream_t *s = vichaos_stream_decrypt_init("pw", 2, header, sizeof(header), NULL);
    CHECK(s != NULL, "stream decrypt init from single-shot header");
    if (!s) { free(enc); return; }

    const uint8_t *ct = enc + VICHAOS_HEADER_OVERHEAD;
    size_t ct_len = enc_len - VICHAOS_OVERHEAD;
    uint8_t *out = malloc(ct_len);
    size_t out_len = 0;
    vichaos_stream_decrypt_update(s, ct, ct_len, out, &out_len);

    const uint8_t *tag = enc + enc_len - VICHAOS_TAG_SIZE;
    r = vichaos_stream_decrypt_final(s, tag, VICHAOS_TAG_SIZE);
    CHECK(r == VICHAOS_SUCCESS, "stream decrypt final OK");
    CHECK(out_len == strlen(plain), "stream decrypted length matches");
    CHECK(memcmp(out, plain, strlen(plain)) == 0, "stream decrypted content matches");

    free(out);
    free(enc);
}

static void test_negative(void) {
    printf("== negative tests ==\n");
    uint8_t *out = NULL; size_t out_len = 0;
    vichaos_result_t r = VICHAOS_SUCCESS;

    r = vichaos_encrypt(NULL, 10, "pw", 2, NULL, &out, &out_len);
    CHECK(r == VICHAOS_ERR_NULL_PTR, "NULL data -> NULL_PTR");

    r = vichaos_encrypt((const uint8_t *)"a", 1, NULL, 0, NULL, &out, &out_len);
    CHECK(r == VICHAOS_ERR_NULL_PTR, "NULL password -> NULL_PTR");

    r = vichaos_decrypt((const uint8_t *)"short", 5, "pw", 2, NULL, &out, &out_len);
    CHECK(r == VICHAOS_ERR_BUFFER_TOO_SMALL, "too short payload -> BUFFER_TOO_SMALL");

    uint8_t bad[64];
    memset(bad, 0xAB, sizeof(bad));
    r = vichaos_decrypt(bad, sizeof(bad), "pw", 2, NULL, &out, &out_len);
    CHECK(r == VICHAOS_ERR_INVALID_PARAM, "random bytes -> INVALID_PARAM");

    vichaos_options_t opts;
    vichaos_options_init(&opts);
    opts.kdf_iter = 50;
    r = vichaos_encrypt((const uint8_t *)"a", 1, "pw", 2, &opts, &out, &out_len);
    CHECK(r == VICHAOS_ERR_INVALID_PARAM, "kdf_iter too low -> INVALID_PARAM");

    opts.kdf_iter = 200000000;
    r = vichaos_encrypt((const uint8_t *)"a", 1, "pw", 2, &opts, &out, &out_len);
    CHECK(r == VICHAOS_ERR_INVALID_PARAM, "kdf_iter too high -> INVALID_PARAM");
}

int main(void) {
    printf("ViChaos v3 integration tests\n");
    printf("===========================\n\n");

    test_single_shot_roundtrip(0, "empty");
    test_single_shot_roundtrip(1, "1 byte");
    test_single_shot_roundtrip(1024, "1 KiB");
    test_cross_compat();
    test_negative();

    printf("\n===========================\n");
    printf("Total checks: %d, failures: %d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
