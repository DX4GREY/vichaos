// ViChaos v3 — CLI encrypt file utility
#include "../../include/vichaos.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    return 1;
}

int vichaos_cli_encrypt_file(const char *input_path,
                             const char *output_path,
                             const char *password) {
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

    out = fopen(output_path, "wb");
    if (!out) { fclose(in); return fail("cannot open output file"); }

    s = vichaos_stream_encrypt_init(password, strlen(password), NULL, header, &header_len);
    if (!s) { fclose(in); fclose(out); return fail("stream init failed"); }

    if (fwrite(header, 1, header_len, out) != header_len) {
        perror("write header"); goto cleanup;
    }

    while ((n = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
        size_t out_len = 0;
        res = vichaos_stream_encrypt_update(s, in_buf, n, out_buf, &out_len);
        if (res != VICHAOS_SUCCESS) { fail(vichaos_strerror(res)); goto cleanup; }
        if (fwrite(out_buf, 1, out_len, out) != out_len) {
            perror("write ciphertext"); goto cleanup;
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

    ret = 0;
cleanup:
    s = NULL; // already freed by final
    if (in) fclose(in);
    if (out) fclose(out);
    return ret;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input> <output> <password>\n", argv[0]);
        return 1;
    }
    return vichaos_cli_encrypt_file(argv[1], argv[2], argv[3]);
}
