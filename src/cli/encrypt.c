// ViChaos v3 — CLI encrypt file utility
#include "../../include/vichaos.h"
#include "cli_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static int fail(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    return 1;
}

int vichaos_cli_encrypt_file_opts(const char *input_path,
                                  const char *output_path,
                                  const char *password,
                                  uint32_t kdf_iter,
                                  int show_progress) {
    FILE *in = NULL, *out = NULL;
    vichaos_stream_t *s = NULL;
    uint8_t header[VICHAOS_HEADER_OVERHEAD];
    size_t header_len = 0;
    uint8_t in_buf[VICHAOS_STREAM_CHUNK];
    uint8_t out_buf[VICHAOS_STREAM_CHUNK + 16];
    size_t n = 0;
    vichaos_result_t res = VICHAOS_SUCCESS;
    int ret = 1;

    if (!input_path || !output_path || !password) return fail("invalid arguments");

    in = fopen(input_path, "rb");
    if (!in) return fail("cannot open input file");

    long file_size = 0;
    if (fseek(in, 0, SEEK_END) == 0) {
        file_size = ftell(in);
        fseek(in, 0, SEEK_SET);
    }

    out = fopen(output_path, "wb");
    if (!out) { fclose(in); return fail("cannot open output file"); }

    vichaos_options_t options;
    vichaos_options_init(&options);
    if (kdf_iter > 0) {
        options.kdf_iter = kdf_iter;
    }

    s = vichaos_stream_encrypt_init(password, strlen(password), &options, header, &header_len);
    if (!s) { fclose(in); fclose(out); return fail("stream init failed"); }

    if (fwrite(header, 1, header_len, out) != header_len) {
        perror("write header"); goto cleanup;
    }

    size_t bytes_processed = 0;
    while ((n = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
        size_t out_len = 0;
        res = vichaos_stream_encrypt_update(s, in_buf, n, out_buf, &out_len);
        if (res != VICHAOS_SUCCESS) { fail(vichaos_strerror(res)); goto cleanup; }
        if (fwrite(out_buf, 1, out_len, out) != out_len) {
            perror("write ciphertext"); goto cleanup;
        }
        bytes_processed += n;
        if (show_progress && file_size > 0) {
            vichaos_cli_print_progress(bytes_processed, (size_t)file_size, "Encrypting");
        }
    }
    if (ferror(in)) { perror("read input"); goto cleanup; }

    {
        uint8_t tag[VICHAOS_TAG_SIZE];
        size_t tag_len = 0;
        res = vichaos_stream_encrypt_final(s, tag, &tag_len);
        if (res != VICHAOS_SUCCESS) { fail(vichaos_strerror(res)); s = NULL; goto cleanup; }
        s = NULL;
        if (fwrite(tag, 1, tag_len, out) != tag_len) {
            perror("write tag"); goto cleanup;
        }
    }

    if (show_progress && file_size > 0 && bytes_processed < (size_t)file_size) {
        vichaos_cli_print_progress((size_t)file_size, (size_t)file_size, "Encrypting");
    }

    ret = 0;
cleanup:
    s = NULL; // already freed by final
    if (in) fclose(in);
    if (out) fclose(out);
    return ret;
}

int vichaos_cli_encrypt_file(const char *input_path,
                             const char *output_path,
                             const char *password) {
    return vichaos_cli_encrypt_file_opts(input_path, output_path, password, 0, 0);
}

#ifndef VICHAOS_UNIFIED_CLI
static void print_usage(const char *prog) {
    printf("Usage: %s [options] <input_file> <output_file> [password]\n", prog);
    printf("       %s [options] -i <input_file> -o <output_file>\n", prog);
    printf("\nOptions:\n");
    printf("  -i, --input <file>     Input plaintext file\n");
    printf("  -o, --output <file>    Output encrypted file\n");
    printf("  -p, --password <pass>  Passphrase (warning: insecure on command line)\n");
    printf("  -k, --keyfile <file>   File containing passphrase (or '-' for stdin)\n");
    printf("  -e, --env <var>        Environment variable for passphrase (default: VICHAOS_PASSPHRASE)\n");
    printf("      --iter <N>         PBKDF2 iteration count (default: 600000)\n");
    printf("      --progress         Show progress bar\n");
    printf("  -h, --help             Show this help screen\n");
}

int main(int argc, char **argv) {
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

    int opt;
    optind = 1;
    while ((opt = getopt_long(argc, argv, "i:o:p:k:e:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': input = optarg; break;
            case 'o': output = optarg; break;
            case 'p': opt_pass = optarg; break;
            case 'k': keyfile = optarg; break;
            case 'e': env_name = optarg; break;
            case 1001: kdf_iter = (uint32_t)strtoul(optarg, NULL, 10); break;
            case 1002: show_progress = 1; break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    // Handle positional arguments if not specified via flags
    if (!input && optind < argc) {
        input = argv[optind++];
    }
    if (!output && optind < argc) {
        output = argv[optind++];
    }
    if (!opt_pass && optind < argc) {
        opt_pass = argv[optind++];
    }

    if (!input || !output) {
        print_usage(argv[0]);
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
#endif
