// ViChaos v3 — Unit tests for cipher module
#include "../../include/vichaos.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg) do { checks++; if (cond) { printf("  PASS: %s\n", msg); } else { printf("  FAIL: %s\n", msg); failures++; } } while(0)

static void test_encrypt_decrypt_roundtrip(void) {
    printf("== test_encrypt_decrypt_roundtrip ==\n");
    const char *plain = "Hello, ViChaos v3!";
    uint8_t key[VICHAOS_KEY_SIZE];
    uint8_t iv[VICHAOS_IV_SIZE];
    uint8_t ct[256];
    uint8_t tag[VICHAOS_TAG_SIZE];
    uint8_t pt[256];

    memset(key, 0xAB, sizeof(key));
    memset(iv, 0xCD, sizeof(iv));

    vichaos_result_t r = vichaos_cipher_encrypt(key, iv,
                                                (const uint8_t *)plain, strlen(plain),
                                                NULL, 0, ct, tag);
    CHECK(r == VICHAOS_SUCCESS, "encrypt returns OK");

    memset(pt, 0, sizeof(pt));
    r = vichaos_cipher_decrypt(key, iv, ct, strlen(plain), NULL, 0, tag, pt);
    CHECK(r == VICHAOS_SUCCESS, "decrypt returns OK");
    CHECK(memcmp(pt, plain, strlen(plain)) == 0, "plaintext matches");
}

static void test_auth_fail(void) {
    printf("== test_auth_fail ==\n");
    uint8_t key[VICHAOS_KEY_SIZE] = {0};
    uint8_t iv[VICHAOS_IV_SIZE] = {0};
    uint8_t ct[16] = {0};
    uint8_t tag[VICHAOS_TAG_SIZE] = {0xFF};
    uint8_t pt[16];

    vichaos_result_t r = vichaos_cipher_decrypt(key, iv, ct, 16, NULL, 0, tag, pt);
    CHECK(r == VICHAOS_ERR_AUTH_FAIL, "tampered tag -> AUTH_FAIL");
}

static void test_null_params(void) {
    printf("== test_null_params ==\n");
    uint8_t key[VICHAOS_KEY_SIZE];
    uint8_t iv[VICHAOS_IV_SIZE];
    uint8_t ct[1], tag[VICHAOS_TAG_SIZE], pt[1];
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    CHECK(vichaos_cipher_encrypt(NULL, iv, (const uint8_t *)"a", 1, NULL, 0, ct, tag) == VICHAOS_ERR_NULL_PTR,
          "NULL key -> NULL_PTR");
    CHECK(vichaos_cipher_decrypt(NULL, iv, ct, 0, NULL, 0, tag, pt) == VICHAOS_ERR_NULL_PTR,
          "NULL key decrypt -> NULL_PTR");
}

int main(void) {
    printf("ViChaos v3 cipher unit tests\n");
    printf("============================\n\n");

    test_encrypt_decrypt_roundtrip();
    test_auth_fail();
    test_null_params();

    printf("\n============================\n");
    printf("Total checks: %d, failures: %d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
