// ViChaos v3 — Unit tests for KDF module
#include "../../include/vichaos.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg) do { checks++; if (cond) { printf("  PASS: %s\n", msg); } else { printf("  FAIL: %s\n", msg); failures++; } } while(0)

static void test_derive_valid(void) {
    printf("== test_derive_valid ==\n");
    uint8_t key[VICHAOS_KEY_SIZE] = {0};
    uint8_t salt[VICHAOS_SALT_SIZE] = {0};
    vichaos_result_t r = vichaos_kdf_derive("password", 8, salt, VICHAOS_DEFAULT_KDF_ITER, key);
    CHECK(r == VICHAOS_SUCCESS, "valid derive returns OK");
    CHECK(memset(key, 0, sizeof(key)), "key buffer written");
}

static void test_derive_null_params(void) {
    printf("== test_derive_null_params ==\n");
    uint8_t key[VICHAOS_KEY_SIZE] = {0};
    CHECK(vichaos_kdf_derive(NULL, 8, (const uint8_t *)key, 100, key) == VICHAOS_ERR_NULL_PTR,
          "NULL password -> NULL_PTR");
}

static void test_derive_invalid_iter(void) {
    printf("== test_derive_invalid_iter ==\n");
    uint8_t key[VICHAOS_KEY_SIZE] = {0};
    uint8_t salt[VICHAOS_SALT_SIZE] = {0};
    CHECK(vichaos_kdf_derive("pw", 2, salt, 50, key) == VICHAOS_ERR_INVALID_PARAM,
          "iter below min -> INVALID_PARAM");
    CHECK(vichaos_kdf_derive("pw", 2, salt, 200000000, key) == VICHAOS_ERR_INVALID_PARAM,
          "iter above max -> INVALID_PARAM");
}

int main(void) {
    printf("ViChaos v3 KDF unit tests\n");
    printf("========================\n\n");

    test_derive_valid();
    test_derive_null_params();
    test_derive_invalid_iter();

    printf("\n========================\n");
    printf("Total checks: %d, failures: %d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
