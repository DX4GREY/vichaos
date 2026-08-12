// ViChaos v3 — CLI decrypt file utility
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

int vichaos_cli_decrypt_file_opts(const char *input_path,
                                  const char *output_path,
                                  const char *password,
                                  int show_progress) {
    FILE *in = NULL, *out = NULL;
    char tmp_path[4096];
    vichaos_stream_t *s = NULL;
    uint8_t header[VICHAOS_HEADER_OVERHEAD];
    long file_size = 0, cipher_len = 0;
    uint8_t in_buf[VICHAOS_STREAM_CHUNK];
    uint8_t out_buf[VICHAOS_STREAM_CHUNK];
    size_t n = 0;
    vichaos_result_t res = VICHAOS_SUCCESS;
    int ret = 1;

    if (!input_path || !output_path || !password) return fail("invalid arguments");

    in = fopen(input_path, "rb");
    if (!in) return fail("cannot open input file");

    if (fseek(in, 0, SEEK_END) != 0 || (file_size = ftell(in)) < 0) {
        perror("seek input"); fclose(in); return 1;
    }
    if (fseek(in, 0, SEEK_SET) != 0) { perror("seek input"); fclose(in); return 1; }

    if (file_size < (long)(VICHAOS_HEADER_OVERHEAD + VICHAOS_TAG_SIZE)) {
        fclose(in); return fail("file too short or invalid ViChaos format");
    }

    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", output_path) >= (int)sizeof(tmp_path)) {
        fclose(in); return fail("output path too long");
    }

    out = fopen(tmp_path, "wb");
    if (!out) { perror("open temp"); fclose(in); return 1; }

    if (fread(header, 1, sizeof(header), in) != sizeof(header)) {
        fail("missing header"); goto cleanup;
    }

    s = vichaos_stream_decrypt_init(password, strlen(password), header, sizeof(header), NULL);
    if (!s) { fail("invalid header/version or wrong password"); goto cleanup; }

    cipher_len = file_size - (long)VICHAOS_HEADER_OVERHEAD - (long)VICHAOS_TAG_SIZE;
    long total_cipher = cipher_len;
    size_t bytes_processed = 0;

    while (cipher_len > 0) {
        size_t want = (cipher_len > (long)sizeof(in_buf)) ? sizeof(in_buf) : (size_t)cipher_len;
        n = fread(in_buf, 1, want, in);
        if (n == 0) { if (ferror(in)) perror("read ciphertext"); else fail("unexpected EOF"); goto cleanup; }
        {
            size_t out_len = 0;
            res = vichaos_stream_decrypt_update(s, in_buf, n, out_buf, &out_len);
            if (res != VICHAOS_SUCCESS) { fail(vichaos_strerror(res)); goto cleanup; }
            if (fwrite(out_buf, 1, out_len, out) != out_len) {
                perror("write plaintext"); goto cleanup;
            }
        }
        cipher_len -= (long)n;
        bytes_processed += n;
        if (show_progress && total_cipher > 0) {
            vichaos_cli_print_progress(bytes_processed, (size_t)total_cipher, "Decrypting");
        }
    }

    {
        uint8_t tag[VICHAOS_TAG_SIZE];
        if (fread(tag, 1, sizeof(tag), in) != sizeof(tag)) {
            fail("missing auth tag"); goto cleanup;
        }
        res = vichaos_stream_decrypt_final(s, tag, sizeof(tag));
        if (res != VICHAOS_SUCCESS) { fail(vichaos_strerror(res)); goto cleanup; }
        s = NULL;
    }

    if (show_progress && total_cipher > 0 && bytes_processed < (size_t)total_cipher) {
        vichaos_cli_print_progress((size_t)total_cipher, (size_t)total_cipher, "Decrypting");
    }

    fclose(in); in = NULL;
    fclose(out); out = NULL;
    if (rename(tmp_path, output_path) != 0) { perror("rename output"); return 1; }

    printf("Decrypted successfully to %s (authenticated).\n", output_path);
    ret = 0;

cleanup:
    s = NULL; // already freed by final
    if (in) fclose(in);
    if (out) { fclose(out); remove(tmp_path); }
    return ret;
}

int vichaos_cli_decrypt_file(const char *input_path,
                             const char *output_path,
                             const char *password) {
    return vichaos_cli_decrypt_file_opts(input_path, output_path, password, 0);
}

#ifndef VICHAOS_UNIFIED_CLI
static void print_usage(const char *prog) {
    printf("Usage: %s [options] <input_file> <output_file> [password]\n", prog);
    printf("       %s [options] -i <input_file> -o <output_file>\n", prog);
    printf("\nOptions:\n");
    printf("  -i, --input <file>     Input encrypted file\n");
    printf("  -o, --output <file>    Output decrypted file\n");
    printf("  -p, --password <pass>  Passphrase (warning: insecure on command line)\n");
    printf("  -k, --keyfile <file>   File containing passphrase (or '-' for stdin)\n");
    printf("  -e, --env <var>        Environment variable for passphrase (default: VICHAOS_PASSPHRASE)\n");
    printf("      --progress         Show progress bar\n");
    printf("  -h, --help             Show this help screen\n");
}

int main(int argc, char **argv) {
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

    int opt;
    optind = 1;
    while ((opt = getopt_long(argc, argv, "i:o:p:k:e:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': input = optarg; break;
            case 'o': output = optarg; break;
            case 'p': opt_pass = optarg; break;
            case 'k': keyfile = optarg; break;
            case 'e': env_name = optarg; break;
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
    if (vichaos_cli_get_password(opt_pass, keyfile, env_name, 0, pass_buf, sizeof(pass_buf)) != 0) {
        return 1;
    }

    int res = vichaos_cli_decrypt_file_opts(input, output, pass_buf, show_progress);
    vichaos_secure_zeroize(pass_buf, sizeof(pass_buf));
    return res;
}
#endif
