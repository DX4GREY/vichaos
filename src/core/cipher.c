// ViChaos v3 — AES-256-GCM encrypt/decrypt
#include "../../include/vichaos.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>

vichaos_result_t vichaos_cipher_encrypt(const uint8_t key[VICHAOS_KEY_SIZE],
                                        const uint8_t iv[VICHAOS_IV_SIZE],
                                        const uint8_t *plaintext,
                                        size_t plaintext_len,
                                        const uint8_t *aad,
                                        size_t aad_len,
                                        uint8_t *ciphertext,
                                        uint8_t tag[VICHAOS_TAG_SIZE]) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, final_len = 0;
    vichaos_result_t result = VICHAOS_SUCCESS;

    if (!key || !iv || (!plaintext && plaintext_len > 0) || (!ciphertext && plaintext_len > 0) || !tag) {
        return VICHAOS_ERR_NULL_PTR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { result = VICHAOS_ERR_CIPHER_INIT; goto cleanup; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        result = VICHAOS_ERR_CIPHER_INIT; goto cleanup;
    }

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
            result = VICHAOS_ERR_ENCRYPT_FAIL; goto cleanup;
        }
    }

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
            result = VICHAOS_ERR_ENCRYPT_FAIL; goto cleanup;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len) != 1) {
        result = VICHAOS_ERR_ENCRYPT_FAIL; goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, VICHAOS_TAG_SIZE, tag) != 1) {
        result = VICHAOS_ERR_ENCRYPT_FAIL; goto cleanup;
    }

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return result;
}

vichaos_result_t vichaos_cipher_decrypt(const uint8_t key[VICHAOS_KEY_SIZE],
                                        const uint8_t iv[VICHAOS_IV_SIZE],
                                        const uint8_t *ciphertext,
                                        size_t ciphertext_len,
                                        const uint8_t *aad,
                                        size_t aad_len,
                                        const uint8_t tag[VICHAOS_TAG_SIZE],
                                        uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, final_len = 0;
    vichaos_result_t result = VICHAOS_SUCCESS;

    if (!key || !iv || (!ciphertext && ciphertext_len > 0) || !tag || (!plaintext && ciphertext_len > 0)) {
        return VICHAOS_ERR_NULL_PTR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { result = VICHAOS_ERR_CIPHER_INIT; goto cleanup; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        result = VICHAOS_ERR_CIPHER_INIT; goto cleanup;
    }

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
            result = VICHAOS_ERR_DECRYPT_FAIL; goto cleanup;
        }
    }

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
            result = VICHAOS_ERR_DECRYPT_FAIL; goto cleanup;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, VICHAOS_TAG_SIZE, (void *)tag) != 1) {
        result = VICHAOS_ERR_DECRYPT_FAIL; goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) <= 0) {
        result = VICHAOS_ERR_AUTH_FAIL; goto cleanup;
    }

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return result;
}
