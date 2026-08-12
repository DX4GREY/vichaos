// ViChaos v3 — CLI Utilities Header
#ifndef VICHAOS_CLI_UTILS_H
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#define VICHAOS_CLI_UTILS_H

#include "../../include/vichaos.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Prompt user for a password from terminal without echo.
 *
 * @param prompt Prompt string (e.g., "Enter password: ")
 * @param buf Output buffer for password
 * @param buf_size Capacity of output buffer
 * @param confirm Non-zero to prompt twice and confirm match (for encryption)
 * @return 0 on success, non-zero on failure.
 */
int vichaos_cli_read_password_terminal(const char *prompt, char *buf, size_t buf_size, int confirm);

/**
 * @brief Obtain password from CLI option, keyfile, environment, or interactive prompt.
 *
 * Priority order:
 * 1. opt_pass (if provided)
 * 2. keyfile (if provided; '-' means stdin)
 * 3. env_var (if set in environment, defaults to VICHAOS_PASSPHRASE)
 * 4. Interactive terminal prompt (if stdin is a TTY)
 *
 * @param opt_pass Direct password string from CLI argument (may be NULL)
 * @param keyfile Path to keyfile or '-' for stdin (may be NULL)
 * @param env_name Name of env var to check (if NULL, checks VICHAOS_PASSPHRASE)
 * @param is_encrypt Non-zero if encrypting (triggers password confirmation on prompt)
 * @param out_pass Output buffer to receive password
 * @param out_size Size of out_pass buffer
 * @return 0 on success, non-zero on failure.
 */
int vichaos_cli_get_password(const char *opt_pass,
                            const char *keyfile,
                            const char *env_name,
                            int is_encrypt,
                            char *out_pass,
                            size_t out_size);

/**
 * @brief Render a progress bar to stderr.
 *
 * @param current Bytes processed so far
 * @param total Total bytes to process
 * @param label Task label (e.g., "Encrypting")
 */
void vichaos_cli_print_progress(size_t current, size_t total, const char *label);

/**
 * @brief Print technical information about a ViChaos payload header.
 *
 * @param input_path Path to the ViChaos encrypted file
 * @return 0 on success, non-zero on failure.
 */
int vichaos_cli_inspect_file(const char *input_path);

#ifdef __cplusplus
}
#endif

#endif /* VICHAOS_CLI_UTILS_H */
