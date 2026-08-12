// --------------------------------- ABOUT -------------------------------------
// Original Author: Dx4 (DX4GREY)
// Repository: [https://github.com/DX4GREY](https://github.com/DX4GREY)
// License: MIT (see end of file)
//
// ViChaos v2 — Core helpers: validation, key derivation, options, error strings
// -----------------------------------------------------------------------------

#include "vichaos.h"
#include "vichaos_internal.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* ------------------------------------------------------------------------- */

int validate_options(const vichaos_options_t *options,
                     vichaos_result_t *err) {
    if (options == NULL) {
        if (err) *err = VICHAOS_ERR_NULL_PTR;
        return 0;
    }
    if (options->kdf_iter < VICHAOS_MIN_KDF_ITER ||
        options->kdf_iter > VICHAOS_MAX_KDF_ITER) {
        if (err) *err = VICHAOS_ERR_INVALID_PARAM;
        return 0;
    }
    return 1;
}

vichaos_result_t derive_key(const char *password,
                            size_t password_len,
                            const uint8_t *salt,
                            uint32_t kdf_iter,
                            uint8_t key[VICHAOS_KEY_SIZE]) {
    if (password == NULL || salt == NULL || key == NULL) {
        return VICHAOS_ERR_NULL_PTR;
    }
    if (password_len == 0) password_len = strlen(password);

    if (PKCS5_PBKDF2_HMAC(password, (int)password_len,
                          salt, VICHAOS_SALT_SIZE,
                          (int)kdf_iter,
                          EVP_sha256(),
                          VICHAOS_KEY_SIZE, key) != 1) {
        return VICHAOS_ERR_KDF_FAIL;
    }
    return VICHAOS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Public: options init                                                       */
/* ------------------------------------------------------------------------- */

void vichaos_options_init(vichaos_options_t *options) {
    if (options) {
        options->kdf_iter = VICHAOS_DEFAULT_KDF_ITER;
    }
}

/* ------------------------------------------------------------------------- */
/* Public: defaults & helpers                                                 */
/* ------------------------------------------------------------------------- */

const char *vichaos_strerror(vichaos_result_t result) {
    switch (result) {
        case VICHAOS_SUCCESS:             return "Success";
        case VICHAOS_ERR_NULL_PTR:        return "NULL pointer passed to non-nullable parameter";
        case VICHAOS_ERR_INVALID_KEY:     return "Invalid key";
        case VICHAOS_ERR_INVALID_IV:      return "Invalid IV";
        case VICHAOS_ERR_INVALID_TAG:     return "Invalid authentication tag";
        case VICHAOS_ERR_CIPHER_INIT:     return "Cipher initialization failed";
        case VICHAOS_ERR_ENCRYPT_FAIL:    return "Encryption operation failed";
        case VICHAOS_ERR_DECRYPT_FAIL:    return "Decryption operation failed";
        case VICHAOS_ERR_AUTH_FAIL:       return "Authentication tag verification failed";
        case VICHAOS_ERR_MEMORY_ALLOC:    return "Memory allocation failed";
        case VICHAOS_ERR_IO_READ:         return "File/stream read error";
        case VICHAOS_ERR_IO_WRITE:        return "File/stream write error";
        case VICHAOS_ERR_KDF_FAIL:        return "PBKDF2 key derivation failed";
        case VICHAOS_ERR_VERSION_MISMATCH: return "Unsupported payload version";
        case VICHAOS_ERR_BUFFER_TOO_SMALL: return "Output buffer capacity insufficient";
        case VICHAOS_ERR_INVALID_PARAM:   return "Invalid parameter value";
        case VICHAOS_ERR_OPENSSL:         return "OpenSSL cryptographic operation failed";
        case VICHAOS_ERR_UNKNOWN:         return "Unknown error";
        default:                          return "Unknown error";
    }
}

void vichaos_free(void *ptr) {
    free(ptr);
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