#include "vichaos.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

#define MAGIC_HEADER "ViChaos-Dx4"
#define MAGIC_HEADER_LEN 11
#define SALT_SIZE 16
#define HMAC_SIZE 32
#define KDF_ITER 100000

// Helper function to expand the key
void expand_key(const uint8_t *key, size_t key_len, uint8_t *k_star, size_t data_len) {
    for (size_t i = 0; i < data_len; i++) {
        k_star[i] = (key[i % key_len] + i*i + 3*i) % 256;
    }
}

// Permutation functions
uint8_t permute(uint8_t x, size_t i, uint8_t ki) {
    return (x + (i * ki)) % 256;
}

uint8_t inverse_permute(uint8_t c, size_t i, uint8_t ki) {
    return (c - (i * ki)) % 256;
}

// Key derivation function
void derive_key(const char *password, const uint8_t *salt, uint8_t *key) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), 
                     salt, SALT_SIZE, 
                     KDF_ITER, 
                     EVP_sha256(), 
                     32, key);
}

// Encryption function
vichaos_result_t vichaos_encrypt(const uint8_t *data, size_t data_len, const char *password, 
                          uint8_t **output, size_t *output_len) {
    // Generate salt
    uint8_t salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        return -1;
    }
    
    // Derive key
    uint8_t key[32];
    derive_key(password, salt, key);
    
    // Prepare full data (magic header + actual data)
    size_t full_data_len = MAGIC_HEADER_LEN + data_len;
    uint8_t *full_data = malloc(full_data_len);
    if (!full_data) return -1;
    
    memcpy(full_data, MAGIC_HEADER, MAGIC_HEADER_LEN);
    memcpy(full_data + MAGIC_HEADER_LEN, data, data_len);
    
    // Expand key
    uint8_t *k_star = malloc(full_data_len);
    if (!k_star) {
        free(full_data);
        return -1;
    }
    expand_key(key, 32, k_star, full_data_len);
    
    // Encrypt
    uint8_t *encrypted = malloc(full_data_len);
    if (!encrypted) {
        free(full_data);
        free(k_star);
        return -1;
    }
    
    for (size_t i = 0; i < full_data_len; i++) {
        uint8_t v = (full_data[i] + k_star[i]) % 256;
        uint8_t x = v ^ k_star[(i + 1) % full_data_len];
        encrypted[i] = permute(x, i, k_star[i]);
    }
    
    // Calculate HMAC
    uint8_t hmac[HMAC_SIZE];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), key, 32, encrypted, full_data_len, hmac, &hmac_len);
    
    // Prepare final output
    *output_len = MAGIC_HEADER_LEN + SALT_SIZE + HMAC_SIZE + full_data_len;
    *output = malloc(*output_len);
    if (!*output) {
        free(full_data);
        free(k_star);
        free(encrypted);
        return -1;
    }
    
    uint8_t *ptr = *output;
    memcpy(ptr, MAGIC_HEADER, MAGIC_HEADER_LEN);
    ptr += MAGIC_HEADER_LEN;
    memcpy(ptr, salt, SALT_SIZE);
    ptr += SALT_SIZE;
    memcpy(ptr, hmac, HMAC_SIZE);
    ptr += HMAC_SIZE;
    memcpy(ptr, encrypted, full_data_len);
    
    // Cleanup
    free(full_data);
    free(k_star);
    free(encrypted);
    
    return 0;
}

// Decryption function
vichaos_result_t vichaos_decrypt(const uint8_t *data, size_t data_len, const char *password, 
                         uint8_t **output, size_t *output_len) {
    // Check magic header
    if (data_len < MAGIC_HEADER_LEN || memcmp(data, MAGIC_HEADER, MAGIC_HEADER_LEN) != 0) {
        return -1;
    }
    
    // Extract components
    if (data_len < MAGIC_HEADER_LEN + SALT_SIZE + HMAC_SIZE) {
        return -1;
    }
    
    const uint8_t *salt = data + MAGIC_HEADER_LEN;
    const uint8_t *hmac_expected = salt + SALT_SIZE;
    const uint8_t *cipher_bytes = hmac_expected + HMAC_SIZE;
    size_t cipher_len = data_len - (MAGIC_HEADER_LEN + SALT_SIZE + HMAC_SIZE);
    
    // Derive key
    uint8_t key[32];
    derive_key(password, salt, key);
    
    // Verify HMAC
    uint8_t hmac_actual[HMAC_SIZE];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), key, 32, cipher_bytes, cipher_len, hmac_actual, &hmac_len);
    
    if (CRYPTO_memcmp(hmac_actual, hmac_expected, HMAC_SIZE) != 0) {
        return -1;
    }
    
    // Expand key
    uint8_t *k_star = malloc(cipher_len);
    if (!k_star) {
        return -1;
    }
    expand_key(key, 32, k_star, cipher_len);
    
    // Decrypt
    uint8_t *decrypted = malloc(cipher_len);
    if (!decrypted) {
        free(k_star);
        return -1;
    }
    
    for (size_t i = 0; i < cipher_len; i++) {
        uint8_t x = inverse_permute(cipher_bytes[i], i, k_star[i]);
        uint8_t v = x ^ k_star[(i + 1) % cipher_len];
        decrypted[i] = (v - k_star[i]) % 256;
    }
    
    // Verify magic header in decrypted data
    if (cipher_len < MAGIC_HEADER_LEN || memcmp(decrypted, MAGIC_HEADER, MAGIC_HEADER_LEN) != 0) {
        free(k_star);
        free(decrypted);
        return -1;
    }
    
    // Prepare output
    *output_len = cipher_len - MAGIC_HEADER_LEN;
    *output = malloc(*output_len);
    if (!*output) {
        free(k_star);
        free(decrypted);
        return -1;
    }
    
    memcpy(*output, decrypted + MAGIC_HEADER_LEN, *output_len);
    
    // Cleanup
    free(k_star);
    free(decrypted);
    
    return 0;
}

const char* vichaos_error_string(vichaos_result_t result) {
    switch(result) {
        case VICHAOS_OK: return "Success";
        case VICHAOS_INVALID_HEADER: return "Invalid header";
        case VICHAOS_HMAC_MISMATCH: return "HMAC verification failed";
        case VICHAOS_MEMORY_ERROR: return "Memory allocation error";
        case VICHAOS_CRYPTO_ERROR: return "Cryptographic operation failed";
        default: return "Unknown error";
    }
}

void vichaos_free(void* ptr) {
    free(ptr);
}