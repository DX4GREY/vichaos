// ViChaos v3 — CLI Utilities Implementation
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "cli_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <termios.h>
#define HAS_TERMIOS 1
#else
#define HAS_TERMIOS 0
#endif

static void strip_newline(char *str) {
    if (!str) return;
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

int vichaos_cli_read_password_terminal(const char *prompt, char *buf, size_t buf_size, int confirm) {
    if (!buf || buf_size == 0) return -1;
    memset(buf, 0, buf_size);

    int is_tty = isatty(STDIN_FILENO);

    if (is_tty) {
#if HAS_TERMIOS
        struct termios old_t, new_t;
        char pass1[1024] = {0};
        char pass2[1024] = {0};

        if (buf_size > sizeof(pass1)) buf_size = sizeof(pass1);

        for (;;) {
            fprintf(stderr, "%s", prompt ? prompt : "Enter password: ");
            fflush(stderr);

            if (tcgetattr(STDIN_FILENO, &old_t) != 0) {
                if (!fgets(buf, (int)buf_size, stdin)) return -1;
                strip_newline(buf);
                return 0;
            }

            new_t = old_t;
            new_t.c_lflag &= (tcflag_t)~(ECHO | ECHOE | ECHOK | ECHONL);
            tcsetattr(STDIN_FILENO, TCSANOW, &new_t);

            char *p1 = fgets(pass1, (int)sizeof(pass1), stdin);
            tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
            fprintf(stderr, "\n");

            if (!p1) {
                vichaos_secure_zeroize(pass1, sizeof(pass1));
                return -1;
            }
            strip_newline(pass1);

            if (confirm) {
                fprintf(stderr, "Confirm password: ");
                fflush(stderr);

                tcsetattr(STDIN_FILENO, TCSANOW, &new_t);
                char *p2 = fgets(pass2, (int)sizeof(pass2), stdin);
                tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
                fprintf(stderr, "\n");

                if (!p2) {
                    vichaos_secure_zeroize(pass1, sizeof(pass1));
                    vichaos_secure_zeroize(pass2, sizeof(pass2));
                    return -1;
                }
                strip_newline(pass2);

                if (strcmp(pass1, pass2) != 0) {
                    fprintf(stderr, "Error: Passwords do not match. Please try again.\n");
                    vichaos_secure_zeroize(pass1, sizeof(pass1));
                    vichaos_secure_zeroize(pass2, sizeof(pass2));
                    continue;
                }
                vichaos_secure_zeroize(pass2, sizeof(pass2));
            }

            snprintf(buf, buf_size, "%s", pass1);
            vichaos_secure_zeroize(pass1, sizeof(pass1));
            return 0;
        }
#else
        fprintf(stderr, "%s", prompt ? prompt : "Enter password: ");
        fflush(stderr);
        if (!fgets(buf, (int)buf_size, stdin)) return -1;
        strip_newline(buf);
        return 0;
#endif
    } else {
        // Not a TTY (pipe or redirection)
        if (!fgets(buf, (int)buf_size, stdin)) return -1;
        strip_newline(buf);
        return 0;
    }
}

int vichaos_cli_get_password(const char *opt_pass,
                            const char *keyfile,
                            const char *env_name,
                            int is_encrypt,
                            char *out_pass,
                            size_t out_size) {
    if (!out_pass || out_size == 0) return -1;
    memset(out_pass, 0, out_size);

    // 1. Direct CLI option password
    if (opt_pass && strlen(opt_pass) > 0) {
        if (isatty(STDIN_FILENO)) {
            fprintf(stderr, "Warning: Passing passwords on command line is insecure (visible in process list).\n");
        }
        snprintf(out_pass, out_size, "%s", opt_pass);
        return 0;
    }

    // 2. Keyfile (path or '-' for stdin)
    if (keyfile && strlen(keyfile) > 0) {
        FILE *kf = NULL;
        if (strcmp(keyfile, "-") == 0) {
            kf = stdin;
        } else {
            kf = fopen(keyfile, "rb");
            if (!kf) {
                fprintf(stderr, "Error: Cannot open keyfile '%s'\n", keyfile);
                return -1;
            }
        }

        if (!fgets(out_pass, (int)out_size, kf)) {
            fprintf(stderr, "Error: Failed to read key from keyfile '%s'\n", keyfile);
            if (kf != stdin) fclose(kf);
            return -1;
        }
        if (kf != stdin) fclose(kf);

        strip_newline(out_pass);
        return 0;
    }

    // 3. Environment Variable
    const char *env_var_to_check = env_name ? env_name : "VICHAOS_PASSPHRASE";
    const char *env_val = getenv(env_var_to_check);
    if (env_val && strlen(env_val) > 0) {
        snprintf(out_pass, out_size, "%s", env_val);
        return 0;
    }

    // 4. Interactive Terminal Prompt
    const char *prompt = is_encrypt ? "Enter passphrase to encrypt: " : "Enter passphrase to decrypt: ";
    return vichaos_cli_read_password_terminal(prompt, out_pass, out_size, is_encrypt);
}

void vichaos_cli_print_progress(size_t current, size_t total, const char *label) {
    if (total == 0) return;
    int bar_width = 30;
    double ratio = (double)current / (double)total;
    if (ratio > 1.0) ratio = 1.0;
    int pos = (int)(ratio * (double)bar_width);

    fprintf(stderr, "\r%s [", label ? label : "Processing");
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) fprintf(stderr, "=");
        else if (i == pos) fprintf(stderr, ">");
        else fprintf(stderr, " ");
    }
    fprintf(stderr, "] %3.0f%% (%zu / %zu bytes)", ratio * 100.0, current, total);
    fflush(stderr);
    if (current >= total) {
        fprintf(stderr, "\n");
    }
}

int vichaos_cli_inspect_file(const char *input_path) {
    if (!input_path) {
        fprintf(stderr, "Error: No input file specified.\n");
        return 1;
    }

    FILE *in = fopen(input_path, "rb");
    if (!in) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", input_path);
        return 1;
    }

    if (fseek(in, 0, SEEK_END) != 0) {
        fclose(in);
        fprintf(stderr, "Error: Seek failed on '%s'\n", input_path);
        return 1;
    }

    long file_size = ftell(in);
    fseek(in, 0, SEEK_SET);

    if (file_size < (long)(VICHAOS_HEADER_OVERHEAD + VICHAOS_TAG_SIZE)) {
        fclose(in);
        fprintf(stderr, "Error: File '%s' is not a valid ViChaos payload (too small, size = %ld bytes).\n", input_path, file_size);
        return 1;
    }

    vichaos_payload_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), in) != sizeof(hdr)) {
        fclose(in);
        fprintf(stderr, "Error: Failed to read header from '%s'\n", input_path);
        return 1;
    }
    fclose(in);

    vichaos_result_t res = vichaos_payload_validate(&hdr);
    int is_valid = (res == VICHAOS_SUCCESS);

    printf("====================================================\n");
    printf(" ViChaos Encrypted Payload Inspection\n");
    printf("====================================================\n");
    printf(" File Path        : %s\n", input_path);
    printf(" File Size        : %ld bytes\n", file_size);
    printf(" Status           : %s\n", is_valid ? "VALID ViChaos Payload" : "INVALID / Corrupted Payload");
    printf("----------------------------------------------------\n");
    printf(" Magic Bytes      : %.7s\n", hdr.magic);
    printf(" Format Version   : 0x%02X (v%u)\n", hdr.version, (unsigned)hdr.version);
    printf(" Salt (16 bytes)  : ");
    for (int i = 0; i < VICHAOS_SALT_SIZE; ++i) {
        printf("%02x", hdr.salt[i]);
    }
    printf("\n");
    printf(" IV (12 bytes)    : ");
    for (int i = 0; i < VICHAOS_IV_SIZE; ++i) {
        printf("%02x", hdr.iv[i]);
    }
    printf("\n");
    printf(" Header Size      : %u bytes\n", (unsigned)VICHAOS_HEADER_OVERHEAD);
    printf(" Auth Tag Size    : %u bytes\n", (unsigned)VICHAOS_TAG_SIZE);
    long cipher_size = file_size - (long)VICHAOS_HEADER_OVERHEAD - (long)VICHAOS_TAG_SIZE;
    printf(" Ciphertext Size  : %ld bytes\n", cipher_size >= 0 ? cipher_size : 0);
    printf("====================================================\n");

    return is_valid ? 0 : 1;
}
