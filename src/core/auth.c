// ViChaos v3 — Authentication tag helpers
#include "../../include/vichaos.h"
#include <string.h>
#include <stdlib.h>

vichaos_result_t vichaos_auth_generate(const uint8_t *key,
                                       size_t key_len,
                                       const uint8_t *data,
                                       size_t data_len,
                                       uint8_t tag[VICHAOS_TAG_SIZE]) {
    if (!key || key_len != VICHAOS_KEY_SIZE || (!data && data_len > 0) || !tag) {
        return VICHAOS_ERR_NULL_PTR;
    }
    uint8_t iv[VICHAOS_IV_SIZE] = {0};
    uint8_t *ct = NULL;
    if (data_len > 0) {
        ct = (uint8_t *)malloc(data_len);
        if (!ct) return VICHAOS_ERR_MEMORY_ALLOC;
    }
    vichaos_result_t r = vichaos_cipher_encrypt(key, iv, data, data_len, NULL, 0, ct, tag);
    if (ct) {
        vichaos_secure_zeroize(ct, data_len);
        free(ct);
    }
    return r;
}

vichaos_result_t vichaos_auth_verify(const uint8_t *key,
                                     size_t key_len,
                                     const uint8_t *data,
                                     size_t data_len,
                                     const uint8_t tag[VICHAOS_TAG_SIZE]) {
    if (!key || key_len != VICHAOS_KEY_SIZE || (!data && data_len > 0) || !tag) {
        return VICHAOS_ERR_NULL_PTR;
    }
    uint8_t iv[VICHAOS_IV_SIZE] = {0};
    uint8_t *pt = NULL;
    if (data_len > 0) {
        pt = (uint8_t *)malloc(data_len);
        if (!pt) return VICHAOS_ERR_MEMORY_ALLOC;
    }
    vichaos_result_t r = vichaos_cipher_decrypt(key, iv, data, data_len, NULL, 0, tag, pt);
    if (pt) {
        vichaos_secure_zeroize(pt, data_len);
        free(pt);
    }
    return r;
}
