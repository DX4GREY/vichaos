// --------------------------------- ABOUT -------------------------------------
// Original Author: Dx4 (DX4GREY)
// Repository: [https://github.com/DX4GREY](https://github.com/DX4GREY)
// License: MIT (see end of file)
//
// ViChaos v2 — Core helpers: validation, key derivation, options, error strings
// -----------------------------------------------------------------------------

#include "vichaos.h"
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
        if (err) *err = VICHAOS_INVALID_ARGUMENT;
        return 0;
    }
    if (options->kdf_iter < VICHAOS_MIN_KDF_ITER ||
        options->kdf_iter > VICHAOS_MAX_KDF_ITER) {
        if (err) *err = VICHAOS_INVALID_ARGUMENT;
        return 0;
    }
    return 1;
}

vichaos_result_t derive_key(const char *password,
                            const uint8_t *salt,
                            uint32_t kdf_iter,
                            uint8_t key[VICHAOS_KEY_SIZE]) {
    if (password == NULL || salt == NULL || key == NULL) {
        return VICHAOS_INVALID_ARGUMENT;
    }

    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                          salt, VICHAOS_SALT_SIZE,
                          (int)kdf_iter,
                          EVP_sha256(),
                          VICHAOS_KEY_SIZE, key) != 1) {
        return VICHAOS_CRYPTO_ERROR;
    }
    return VICHAOS_OK;
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

const char *vichaos_error_string(vichaos_result_t result) {
    switch (result) {
        case VICHAOS_OK:                return "Success";
        case VICHAOS_INVALID_ARGUMENT:  return "Invalid argument";
        case VICHAOS_INVALID_HEADER:    return "Invalid header";
        case VICHAOS_UNSUPPORTED_VERSION: return "Unsupported payload version";
        case VICHAOS_HMAC_MISMATCH:     return "Authentication tag verification failed";
        case VICHAOS_MEMORY_ERROR:      return "Memory allocation error";
        case VICHAOS_CRYPTO_ERROR:      return "Cryptographic operation failed";
        default:                        return "Unknown error";
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