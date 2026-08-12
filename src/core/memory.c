#define _GNU_SOURCE
// ViChaos v3 — Secure memory management
#include "../../include/vichaos.h"
#include <stdlib.h>
#include <string.h>

#if defined(__STDC_LIB_EXT1__)
    #define VICHAOS_HAS_SECURE_ZERO 1
#elif defined(__linux__) && defined(__GLIBC__)
    #include <strings.h>
    #define VICHAOS_HAS_SECURE_ZERO 1
#elif defined(_WIN32)
    #include <windows.h>
    #define VICHAOS_HAS_SECURE_ZERO 1
#else
    #define VICHAOS_HAS_SECURE_ZERO 0
#endif

void *vichaos_secure_alloc(size_t size) {
    if (size == 0) return NULL;
    void *ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

void vichaos_secure_free(void *ptr, size_t size) {
    if (ptr && size > 0) {
        vichaos_secure_zeroize(ptr, size);
    }
    free(ptr);
}

void vichaos_secure_zeroize(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
#if VICHAOS_HAS_SECURE_ZERO
    #if defined(__STDC_LIB_EXT1__)
        memset_s(ptr, len, 0, len);
    #elif defined(__linux__) && defined(__GLIBC__)
        explicit_bzero(ptr, len);
    #elif defined(_WIN32)
        SecureZeroMemory(ptr, len);
    #else
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (len--) *p++ = 0;
    #endif
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
#endif
}

int vichaos_secure_memcmp(const void *a, const void *b, size_t len) {
    const volatile unsigned char *pa = (const volatile unsigned char *)a;
    const volatile unsigned char *pb = (const volatile unsigned char *)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }
    return (int)diff;
}

void vichaos_free(void *ptr) {
    free(ptr);
}

vichaos_result_t vichaos_buffer_init(vichaos_buffer_t *buf, size_t capacity) {
    if (!buf || capacity == 0) return VICHAOS_ERR_NULL_PTR;
    buf->data = (uint8_t *)vichaos_secure_alloc(capacity);
    if (!buf->data) return VICHAOS_ERR_MEMORY_ALLOC;
    buf->len = 0;
    buf->capacity = capacity;
    buf->canary = 0xDEADBEEF;
    return VICHAOS_SUCCESS;
}

vichaos_result_t vichaos_buffer_append(vichaos_buffer_t *buf,
                                       const uint8_t *data,
                                       size_t len) {
    if (!buf || !data) return VICHAOS_ERR_NULL_PTR;
    if (buf->canary != 0xDEADBEEF) return VICHAOS_ERR_INVALID_PARAM;
    /* Guard against integer overflow: validate before summing buf->len + len. */
    if (len > buf->capacity || buf->len > buf->capacity - len) {
        return VICHAOS_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return VICHAOS_SUCCESS;
}

void vichaos_buffer_cleanup(vichaos_buffer_t *buf) {
    if (!buf) return;
    if (buf->canary == 0xDEADBEEF && buf->data) {
        vichaos_secure_zeroize(buf->data, buf->capacity);
        free(buf->data);
    }
    buf->data = NULL;
    buf->len = 0;
    buf->capacity = 0;
    buf->canary = 0;
}
