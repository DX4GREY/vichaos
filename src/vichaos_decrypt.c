// --------------------------------- ABOUT -------------------------------------
// Original Author: Dx4 (DX4GREY)
// Repository: [https://github.com/DX4GREY](https://github.com/DX4GREY)
// License: MIT (see end of file)
//
// ViChaos v2 — Single-shot decryption (AES-256-GCM)
// -----------------------------------------------------------------------------

#include "vichaos.h"
#include "vichaos_internal.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------------- */
/* Public: decryption                                                         */
/* ------------------------------------------------------------------------- */

vichaos_result_t vichaos_decrypt(const uint8_t *data,
                                 size_t data_len,
                                 const char *password,
                                 size_t password_len,
                                 const vichaos_options_t *options,
                                 uint8_t **output,
                                 size_t *output_len) {

    vichaos_result_t result = VICHAOS_SUCCESS;
    vichaos_options_t defaults;

    if (output == NULL || output_len == NULL || password == NULL ||
        (data == NULL && data_len > 0) || data == NULL) {
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

    /* Minimal framing check. */
    if (data_len < VICHAOS_OVERHEAD) {
        return VICHAOS_ERR_INVALID_PARAM;
    }

    /* ---- Verify magic + version ---- */
    if (memcmp(data, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN) != 0) {
        return VICHAOS_ERR_INVALID_PARAM;
    }
    if (data[VICHAOS_FORMAT_MAGIC_LEN] != VICHAOS_PAYLOAD_VERSION) {
        return VICHAOS_ERR_VERSION_MISMATCH;
    }

    const uint8_t *salt = data + VICHAOS_FORMAT_MAGIC_LEN + 1;
    const uint8_t *iv = salt + VICHAOS_SALT_SIZE;
    const uint8_t *ciphertext = iv + VICHAOS_IV_SIZE;
    const size_t plaintext_len = data_len - VICHAOS_OVERHEAD;
    const uint8_t *tag = data + data_len - VICHAOS_TAG_SIZE;

    /* ---- Derive key ---- */
    uint8_t key[VICHAOS_KEY_SIZE];
    result = derive_key(password, password_len, salt, options->kdf_iter, key);
    if (result != VICHAOS_SUCCESS) {
        return result;
    }

    /* ---- AES-256-GCM decrypt ---- */
    uint8_t *plaintext = NULL;
    if (plaintext_len > 0) {
        plaintext = malloc(plaintext_len);
        if (plaintext == NULL) {
            OPENSSL_cleanse(key, sizeof(key));
            return VICHAOS_ERR_MEMORY_ALLOC;
        }
    }
    /* EVP_DecryptFinal_ex requires a non-NULL output buffer even for
     * empty plaintext; use a scratch buffer in that case. */
    uint8_t scratch[32];
    int len = 0;
    int final_len = 0;
    uint8_t *final_out = (plaintext_len > 0) ? (plaintext + len) : scratch;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OPENSSL_cleanse(key, sizeof(key));
        free(plaintext);
        return VICHAOS_ERR_OPENSSL;
    }

    /* VICHAOS_IV_SIZE (12) is the GCM default IV length, so the
     * EVP_CTRL_GCM_SET_IVLEN call is omitted to save a ctrl round-trip. */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        result = VICHAOS_ERR_OPENSSL;
        goto cleanup;
    }

    /* Authenticate magic + version (AAD). */
    if (EVP_DecryptUpdate(ctx, NULL, &len, data,
                          VICHAOS_HEADER_OVERHEAD) != 1) {
        result = VICHAOS_ERR_OPENSSL;
        goto cleanup;
    }

    if (plaintext_len > 0 &&
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
                          (int)plaintext_len) != 1) {
        result = VICHAOS_ERR_OPENSSL;
        goto cleanup;
    }

    /* Set expected tag before final. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, VICHAOS_TAG_SIZE,
                            (void *)tag) != 1) {
        result = VICHAOS_ERR_OPENSSL;
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, final_out, &final_len) <= 0) {
        result = VICHAOS_ERR_AUTH_FAIL;
        goto cleanup;
    }

    *output = plaintext;
    *output_len = plaintext_len;
    plaintext = NULL; /* ownership transferred */

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(scratch, sizeof(scratch));
    if (plaintext != NULL) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        free(plaintext);
    }
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