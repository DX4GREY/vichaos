// ViChaos v3 — PBKDF2 key derivation
#include "../../include/vichaos.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

vichaos_result_t vichaos_kdf_derive(const char *password,
                                    size_t password_len,
                                    const uint8_t salt[VICHAOS_SALT_SIZE],
                                    uint32_t kdf_iter,
                                    uint8_t key[VICHAOS_KEY_SIZE]) {
    if (!password || !salt || !key) return VICHAOS_ERR_NULL_PTR;
    if (password_len == 0) password_len = strlen(password);
    if (kdf_iter < VICHAOS_MIN_KDF_ITER || kdf_iter > VICHAOS_MAX_KDF_ITER) {
        return VICHAOS_ERR_INVALID_PARAM;
    }
    if (PKCS5_PBKDF2_HMAC(password, (int)password_len,
                          salt, VICHAOS_SALT_SIZE,
                          (int)kdf_iter,
                          EVP_sha256(),
                          VICHAOS_KEY_SIZE, key) != 1) {
        return VICHAOS_ERR_KDF_FAIL;
    }
    return VICHAOS_SUCCESS;
}
