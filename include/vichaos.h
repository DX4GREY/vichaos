#ifndef VICHAOS_H
#define VICHAOS_H

#include <stdint.h>
#include <stddef.h>

#define VICHAOS_MAGIC "ViChaos-Dx4"
#define VICHAOS_MAGIC_LEN 11
#define VICHAOS_SALT_SIZE 16
#define VICHAOS_HMAC_SIZE 32
#define VICHAOS_KDF_ITER 100000

typedef enum {
    VICHAOS_OK = 0,
    VICHAOS_INVALID_HEADER,
    VICHAOS_HMAC_MISMATCH,
    VICHAOS_MEMORY_ERROR,
    VICHAOS_CRYPTO_ERROR
} vichaos_result_t;

// Core functions
vichaos_result_t vichaos_encrypt(
    const uint8_t* data,
    size_t data_len,
    const char* password,
    uint8_t** output,
    size_t* output_len
);

vichaos_result_t vichaos_decrypt(
    const uint8_t* data,
    size_t data_len,
    const char* password,
    uint8_t** output,
    size_t* output_len
);

// Helper functions
const char* vichaos_error_string(vichaos_result_t result);
void vichaos_free(void* ptr);

#endif // VICHAOS_H
