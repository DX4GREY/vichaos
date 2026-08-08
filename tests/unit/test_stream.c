#include <stdlib.h>
// ViChaos v3 — Unit tests for streaming module
#include "../../include/vichaos.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg) do { checks++; if (cond) { printf("  PASS: %s\n", msg); } else { printf("  FAIL: %s\n", msg); failures++; } } while(0)

static void test_stream_roundtrip(const char *label, size_t len, size_t chunk) {
    printf("== stream roundtrip (%s, %zu bytes, chunk %zu) ==\n", label, len, chunk);

    uint8_t *plain = (len > 0) ? (uint8_t *)malloc(len) : NULL;
    if (plain) memset(plain, 0xAB, len);

    vichaos_options_t opts;
    vichaos_options_init(&opts);
    opts.chunk_size = (uint32_t)chunk;

    uint8_t header[VICHAOS_HEADER_OVERHEAD];
    size_t header_len = 0;
    vichaos_stream_t *s = vichaos_stream_encrypt_init("testpw", 6, &opts, header, &header_len);
    CHECK(s != NULL, "stream encrypt init");
    if (!s) { if (plain) free(plain); return; }

    uint8_t *ct = NULL;
    size_t total_ct = 0;
    if (len > 0) ct = (uint8_t *)malloc(len + 16);

    for (size_t off = 0; off < len; off += chunk) {
        size_t n = (len - off > chunk) ? chunk : (len - off);
        size_t out_len = 0;
        vichaos_result_t r = vichaos_stream_encrypt_update(s, plain ? plain + off : NULL, n,
                                                            ct ? ct + total_ct : NULL, &out_len);
        CHECK(r == VICHAOS_SUCCESS, "stream encrypt update");
        total_ct += out_len;
    }

    uint8_t tag[VICHAOS_TAG_SIZE];
    size_t tag_len = 0;
    vichaos_result_t r = vichaos_stream_encrypt_final(s, tag, &tag_len);
    CHECK(r == VICHAOS_SUCCESS, "stream encrypt final");
    s = NULL;

    /* decrypt */
    s = vichaos_stream_decrypt_init("testpw", 6, header, header_len, &opts);
    CHECK(s != NULL, "stream decrypt init");
    if (!s) { if (ct) free(ct); if (plain) free(plain); return; }

    uint8_t *recovered = NULL;
    if (len > 0) recovered = (uint8_t *)malloc(len);
    size_t rec_off = 0;

    for (size_t off = 0; off < total_ct; off += chunk) {
        size_t n = (total_ct - off > chunk) ? chunk : (total_ct - off);
        size_t out_len = 0;
        r = vichaos_stream_decrypt_update(s, ct ? ct + off : NULL, n,
                                          recovered ? recovered + rec_off : NULL, &out_len);
        CHECK(r == VICHAOS_SUCCESS, "stream decrypt update");
        rec_off += out_len;
    }

    r = vichaos_stream_decrypt_final(s, tag, tag_len);
    CHECK(r == VICHAOS_SUCCESS, "stream decrypt final (auth)");

    if (len > 0) {
        CHECK(memcmp(recovered, plain, len) == 0, "recovered plaintext matches");
    }

    if (ct) free(ct);
    if (recovered) free(recovered);
    if (plain) free(plain);
}

static void test_stream_wrong_password(void) {
    printf("== test_stream_wrong_password ==\n");
    uint8_t header[VICHAOS_HEADER_OVERHEAD];
    size_t header_len = 0;
    vichaos_stream_t *s = vichaos_stream_encrypt_init("correct", 7, NULL, header, &header_len);
    CHECK(s != NULL, "encrypt init");
    if (!s) return;

    uint8_t out[64]; size_t out_len = 0;
    vichaos_stream_encrypt_update(s, (const uint8_t *)"data", 4, out, &out_len);
    uint8_t tag[VICHAOS_TAG_SIZE]; size_t tag_len = 0;
    vichaos_stream_encrypt_final(s, tag, &tag_len);

    s = vichaos_stream_decrypt_init("wrong", 5, header, header_len, NULL);
    CHECK(s != NULL, "decrypt init with wrong pw");
    if (s) {
        uint8_t pt[64]; size_t pt_len = 0;
        vichaos_stream_decrypt_update(s, out, out_len, pt, &pt_len);
        vichaos_result_t r = vichaos_stream_decrypt_final(s, tag, tag_len);
        CHECK(r == VICHAOS_ERR_AUTH_FAIL, "wrong password -> AUTH_FAIL");
    }
}

int main(void) {
    printf("ViChaos v3 stream unit tests\n");
    printf("============================\n\n");

    test_stream_roundtrip("empty", 0, 1024);
    test_stream_roundtrip("tiny", 1, 1);
    test_stream_roundtrip("small", 100, 16);
    test_stream_roundtrip("medium", 65536, 4096);
    test_stream_wrong_password();

    printf("\n============================\n");
    printf("Total checks: %d, failures: %d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
