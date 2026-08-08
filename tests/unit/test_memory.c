// ViChaos v3 — Unit tests for memory management
#include "../../include/vichaos.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg) do { checks++; if (cond) { printf("  PASS: %s\n", msg); } else { printf("  FAIL: %s\n", msg); failures++; } } while(0)

static void test_secure_zeroize(void) {
    printf("== test_secure_zeroize ==\n");
    uint8_t buf[32];
    memset(buf, 0xFF, sizeof(buf));
    vichaos_secure_zeroize(buf, sizeof(buf));
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf); i++) { if (buf[i] != 0) { all_zero = 0; break; } }
    CHECK(all_zero, "secure_zeroize clears buffer");
}

static void test_secure_memcmp_equal(void) {
    printf("== test_secure_memcmp_equal ==\n");
    uint8_t a[16] = {1,2,3,4,5}, b[16] = {1,2,3,4,5};
    CHECK(vichaos_secure_memcmp(a, b, 5) == 0, "equal buffers return 0");
}

static void test_secure_memcmp_neq(void) {
    printf("== test_secure_memcmp_neq ==\n");
    uint8_t a[16] = {1,2,3,4,5}, b[16] = {1,2,3,4,6};
    CHECK(vichaos_secure_memcmp(a, b, 5) != 0, "different buffers return non-zero");
}

static void test_secure_alloc_free(void) {
    printf("== test_secure_alloc_free ==\n");
    void *p = vichaos_secure_alloc(64);
    CHECK(p != NULL, "secure_alloc returns non-NULL");
    memset(p, 0xAB, 64);
    vichaos_secure_free(p, 64);
    CHECK(1, "secure_free does not crash");
}

static void test_buffer_ops(void) {
    printf("== test_buffer_ops ==\n");
    vichaos_buffer_t buf;
    vichaos_result_t r = vichaos_buffer_init(&buf, 256);
    CHECK(r == VICHAOS_SUCCESS, "buffer init OK");

    uint8_t data[] = {1,2,3,4};
    r = vichaos_buffer_append(&buf, data, sizeof(data));
    CHECK(r == VICHAOS_SUCCESS, "buffer append OK");
    CHECK(buf.len == sizeof(data), "buffer length updated");

    r = vichaos_buffer_append(&buf, data, sizeof(data));
    CHECK(r == VICHAOS_SUCCESS, "second append OK");

    vichaos_buffer_cleanup(&buf);
    CHECK(buf.data == NULL, "buffer cleanup clears data");
}

int main(void) {
    printf("ViChaos v3 memory unit tests\n");
    printf("==========================\n\n");

    test_secure_zeroize();
    test_secure_memcmp_equal();
    test_secure_memcmp_neq();
    test_secure_alloc_free();
    test_buffer_ops();

    printf("\n==========================\n");
    printf("Total checks: %d, failures: %d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
