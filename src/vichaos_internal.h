// -----------------------------------------------------------------------------
// ViChaos — Internal helpers shared by the legacy (v2-style) modules.
//
// These are NOT part of the public v3 API declared in include/vichaos.h.
// They exist so the legacy single-shot / streaming modules can share
// validation and key-derivation helpers without implicit-declaration errors.
// -----------------------------------------------------------------------------

#ifndef VICHAOS_INTERNAL_H
#define VICHAOS_INTERNAL_H

#include "vichaos.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Validate a vichaos_options_t instance.
 * @param options Options to validate (may not be NULL).
 * @param err     Optional: receives the specific error code on failure.
 * @return 1 if valid, 0 otherwise.
 */
int validate_options(const vichaos_options_t *options, vichaos_result_t *err);

/**
 * @brief Derive an AES-256 key from a password via PBKDF2-HMAC-SHA256.
 * @param password     Password bytes.
 * @param password_len Password length in bytes (0 = NUL-terminated).
 * @param salt         PBKDF2 salt.
 * @param kdf_iter     Iteration count.
 * @param key          Output: VICHAOS_KEY_SIZE-byte derived key.
 */
vichaos_result_t derive_key(const char *password,
                            size_t password_len,
                            const uint8_t *salt,
                            uint32_t kdf_iter,
                            uint8_t key[VICHAOS_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* VICHAOS_INTERNAL_H */
