// ViChaos v3 — Unit tests for error handling
#include "../../include/vichaos.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg) do { checks++; if (cond) { printf("  PASS: %s\n", msg); } else { printf("  FAIL: %s\n", msg); failures++; } } while(0)

int main(void) {
    printf("ViChaos v3 error handling tests\n");
    printf("================================\n\n");

    const char *s = vichaos_strerror(VICHAOS_SUCCESS);
    CHECK(s != NULL, "strerror(SUCCESS) non-NULL");
    CHECK(strcmp(s, "Success") == 0, "strerror(SUCCESS) == 'Success'");

    s = vichaos_strerror(VICHAOS_ERR_AUTH_FAIL);
    CHECK(s != NULL, "strerror(AUTH_FAIL) non-NULL");

    s = vichaos_strerror(VICHAOS_ERR_MEMORY_ALLOC);
    CHECK(s != NULL, "strerror(MEMORY_ALLOC) non-NULL");

    s = vichaos_strerror(9999);
    CHECK(s != NULL, "strerror(unknown) non-NULL");

    printf("\n================================\n");
    printf("Total checks: %d, failures: %d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
