// --------------------------------- ABOUT -------------------------------------
// Original Author: Dx4 (DX4GREY)
// Repository: [https://github.com/DX4GREY](https://github.com/DX4GREY)
// License: MIT (see end of file)
//
// ViChaos v2 — Single-shot encryption (AES-256-GCM)
// -----------------------------------------------------------------------------

#include "vichaos.h"
#include "vichaos_internal.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------------- */
/* Public: encryption                                                         */
/* ------------------------------------------------------------------------- */

vichaos_result_t vichaos_encrypt(const uint8_t *data,
                                 size_t data_len,
                                 const char *password,
                                 size_t password_len,
                                 const vichaos_options_t *options,
                                 uint8_t **output,
                                 size_t *output_len) {

    vichaos_result_t result = VICHAOS_SUCCESS;
    vichaos_options_t defaults;

    if (output == NULL || output_len == NULL || password == NULL ||
        (data == NULL && data_len > 0)) {
        return VICHAOS_ERR_NULL_PTR;
    }

    *output = NULL;
    *output_len = 0;

    /* Options may be NULL -> use defaults. */
    if (options == NULL) {
        vichaos_options_init(&defaults);
        options = &defaults;
    }
    if (!validate_options(options, &result)) {
        return result;
    }

    /* Guard against size_t overflow in output length computation. */
    if (data_len > (size_t)-1 - VICHAOS_OVERHEAD) {
        return VICHAOS_ERR_INVALID_PARAM;
    }
    const size_t out_len = data_len + VICHAOS_OVERHEAD;

    uint8_t *out = malloc(out_len);
    if (out == NULL) {
        return VICHAOS_ERR_MEMORY_ALLOC;
    }

    /* ---- Assemble header: magic + version ---- */
    uint8_t *ptr = out;
    memcpy(ptr, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN);
    ptr += VICHAOS_FORMAT_MAGIC_LEN;
    *ptr++ = VICHAOS_PAYLOAD_VERSION;
    const uint8_t *salt = ptr;
    void *salt_dst = ptr;
    ptr += VICHAOS_SALT_SIZE;
    const uint8_t *iv = ptr;
    void *iv_dst = ptr;
    ptr += VICHAOS_IV_SIZE;
    uint8_t *ciphertext = ptr;
    uint8_t *tag = out + out_len - VICHAOS_TAG_SIZE;

    /* ---- Random salt + IV ---- */
    if (RAND_bytes(salt_dst, VICHAOS_SALT_SIZE) != 1 ||
        RAND_bytes(iv_dst, VICHAOS_IV_SIZE) != 1) {
        result = VICHAOS_ERR_OPENSSL;
        goto fail;
    }

    /* ---- Derive key ---- */
    uint8_t key[VICHAOS_KEY_SIZE];
    result = derive_key(password, password_len, salt, options->kdf_iter, key);
    if (result != VICHAOS_SUCCESS) {
        goto fail;
    }

    /* ---- AES-256-GCM encrypt ---- */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OPENSSL_cleanse(key, sizeof(key));
        result = VICHAOS_ERR_OPENSSL;
        goto fail;
    }

    int len = 0;
    int final_len = 0;

    /* VICHAOS_IV_SIZE (12) is the GCM default IV length, so the
     * EVP_CTRL_GCM_SET_IVLEN call is omitted to save a ctrl round-trip. */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        result = VICHAOS_ERR_OPENSSL;
        goto cleanup_ctx;
    }

    /* Authenticate magic + version (AAD). */
    if (EVP_EncryptUpdate(ctx, NULL, &len,
                          (const unsigned char *)out,
                          VICHAOS_HEADER_OVERHEAD) != 1) {
        result = VICHAOS_ERR_OPENSSL;
        goto cleanup_ctx;
    }

    /* Encrypt data (GCM updates do not expand size). */
    if (data_len > 0 &&
        EVP_EncryptUpdate(ctx, ciphertext, &len, data, (int)data_len) != 1) {
        result = VICHAOS_ERR_OPENSSL;
        goto cleanup_ctx;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len) != 1) {
        result = VICHAOS_ERR_OPENSSL;
        goto cleanup_ctx;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, VICHAOS_TAG_SIZE,
                            tag) != 1) {
        result = VICHAOS_ERR_OPENSSL;
        goto cleanup_ctx;
    }

cleanup_ctx:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    if (result == VICHAOS_SUCCESS) {
        *output = out;
        *output_len = out_len;
        return VICHAOS_SUCCESS;
    }

fail:
    OPENSSL_cleanse(out, out_len);
    free(out);
    return result;
}

// -----------------------------------------------------------------------------
// MIT License
//
// Copyright (c) 2026 DX4GREY
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// -----------------------------------------------------------------------------