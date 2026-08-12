// ViChaos v3 — Unified Command Line Interface
#include "../../include/vichaos.h"
#include "cli_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

// Forward declarations for functions defined in encrypt.c and decrypt.c
int vichaos_cli_encrypt_file_opts(const char *input_path,
                                  const char *output_path,
                                  const char *password,
                                  uint32_t kdf_iter,
                                  int show_progress);

int vichaos_cli_decrypt_file_opts(const char *input_path,
                                  const char *output_path,
                                  const char *password,
                                  int show_progress);

static void print_main_usage(const char *prog) {
    printf("ViChaos v%s — High-Security File Encryption Tool\n", VICHAOS_VERSION_STRING);
    printf("Usage: %s <command> [options] [arguments...]\n\n", prog);
    printf("Available Commands:\n");
    printf("  enc, encrypt   Encrypt a file with AES-256-GCM + PBKDF2\n");
    printf("  dec, decrypt   Decrypt and authenticate a ViChaos encrypted file\n");
    printf("  info, inspect  Inspect header metadata of an encrypted file\n");
    printf("  version        Show library and build version information\n");
    printf("  help           Show this help message\n\n");
    printf("Run '%s <command> --help' for command-specific options.\n", prog);
}

static int handle_version(void) {
    printf("vichaos CLI v%s\n", VICHAOS_VERSION_STRING);
    printf("Library Version: %d.%d.%d\n", VICHAOS_VERSION_MAJOR, VICHAOS_VERSION_MINOR, VICHAOS_VERSION_PATCH);
    printf("Hardware AES Acceleration (AES-NI): %s\n", vichaos_hardware_aes_supported() ? "Available" : "Not Available");
    return 0;
}

static int handle_encrypt(int argc, char **argv) {
    const char *input = NULL;
    const char *output = NULL;
    const char *opt_pass = NULL;
    const char *keyfile = NULL;
    const char *env_name = NULL;
    uint32_t kdf_iter = 0;
    int show_progress = 0;

    static struct option long_options[] = {
        {"input",    required_argument, 0, 'i'},
        {"output",   required_argument, 0, 'o'},
        {"password", required_argument, 0, 'p'},
        {"keyfile",  required_argument, 0, 'k'},
        {"env",      required_argument, 0, 'e'},
        {"iter",     required_argument, 0, 1001},
        {"progress", no_argument,       0, 1002},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:p:k:e:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': input = optarg; break;
            case 'o': output = optarg; break;
            case 'p': opt_pass = optarg; break;
            case 'k': keyfile = optarg; break;
            case 'e': env_name = optarg; break;
            case 1001: kdf_iter = (uint32_t)strtoul(optarg, NULL, 10); break;
            case 1002: show_progress = 1; break;
            case 'h':
                printf("Usage: vichaos enc [options] <input_file> <output_file>\n");
                printf("Options:\n");
                printf("  -i, --input <file>     Input plaintext file\n");
                printf("  -o, --output <file>    Output encrypted file\n");
                printf("  -p, --password <pass>  Passphrase (warning: insecure on command line)\n");
                printf("  -k, --keyfile <file>   File containing passphrase (or '-' for stdin)\n");
                printf("  -e, --env <var>        Environment variable for passphrase (default: VICHAOS_PASSPHRASE)\n");
                printf("      --iter <N>         PBKDF2 iteration count (default: 600000)\n");
                printf("      --progress         Show progress bar\n");
                return 0;
            default:
                return 1;
        }
    }

    if (!input && optind < argc) input = argv[optind++];
    if (!output && optind < argc) output = argv[optind++];
    if (!opt_pass && optind < argc) opt_pass = argv[optind++];

    if (!input || !output) {
        fprintf(stderr, "Error: Missing input or output file path.\n");
        fprintf(stderr, "Usage: vichaos enc -i <input> -o <output> or vichaos enc <input> <output>\n");
        return 1;
    }

    char pass_buf[1024];
    if (vichaos_cli_get_password(opt_pass, keyfile, env_name, 1, pass_buf, sizeof(pass_buf)) != 0) {
        return 1;
    }

    int res = vichaos_cli_encrypt_file_opts(input, output, pass_buf, kdf_iter, show_progress);
    vichaos_secure_zeroize(pass_buf, sizeof(pass_buf));
    return res;
}

static int handle_decrypt(int argc, char **argv) {
    const char *input = NULL;
    const char *output = NULL;
    const char *opt_pass = NULL;
    const char *keyfile = NULL;
    const char *env_name = NULL;
    int show_progress = 0;

    static struct option long_options[] = {
        {"input",    required_argument, 0, 'i'},
        {"output",   required_argument, 0, 'o'},
        {"password", required_argument, 0, 'p'},
        {"keyfile",  required_argument, 0, 'k'},
        {"env",      required_argument, 0, 'e'},
        {"progress", no_argument,       0, 1002},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:p:k:e:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': input = optarg; break;
            case 'o': output = optarg; break;
            case 'p': opt_pass = optarg; break;
            case 'k': keyfile = optarg; break;
            case 'e': env_name = optarg; break;
            case 1002: show_progress = 1; break;
            case 'h':
                printf("Usage: vichaos dec [options] <input_file> <output_file>\n");
                printf("Options:\n");
                printf("  -i, --input <file>     Input encrypted file\n");
                printf("  -o, --output <file>    Output decrypted file\n");
                printf("  -p, --password <pass>  Passphrase (warning: insecure on command line)\n");
                printf("  -k, --keyfile <file>   File containing passphrase (or '-' for stdin)\n");
                printf("  -e, --env <var>        Environment variable for passphrase (default: VICHAOS_PASSPHRASE)\n");
                printf("      --progress         Show progress bar\n");
                return 0;
            default:
                return 1;
        }
    }

    if (!input && optind < argc) input = argv[optind++];
    if (!output && optind < argc) output = argv[optind++];
    if (!opt_pass && optind < argc) opt_pass = argv[optind++];

    if (!input || !output) {
        fprintf(stderr, "Error: Missing input or output file path.\n");
        fprintf(stderr, "Usage: vichaos dec -i <input> -o <output> or vichaos dec <input> <output>\n");
        return 1;
    }

    char pass_buf[1024];
    if (vichaos_cli_get_password(opt_pass, keyfile, env_name, 0, pass_buf, sizeof(pass_buf)) != 0) {
        return 1;
    }

    int res = vichaos_cli_decrypt_file_opts(input, output, pass_buf, show_progress);
    vichaos_secure_zeroize(pass_buf, sizeof(pass_buf));
    return res;
}

static int handle_info(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: vichaos info <encrypted_file>\n");
        return 1;
    }
    return vichaos_cli_inspect_file(argv[1]);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_main_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "enc") == 0 || strcmp(cmd, "encrypt") == 0) {
        return handle_encrypt(argc - 1, argv + 1);
    } else if (strcmp(cmd, "dec") == 0 || strcmp(cmd, "decrypt") == 0) {
        return handle_decrypt(argc - 1, argv + 1);
    } else if (strcmp(cmd, "info") == 0 || strcmp(cmd, "inspect") == 0) {
        return handle_info(argc - 1, argv + 1);
    } else if (strcmp(cmd, "version") == 0 || strcmp(cmd, "-v") == 0 || strcmp(cmd, "--version") == 0) {
        return handle_version();
    } else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        print_main_usage(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        print_main_usage(argv[0]);
        return 1;
    }
}
