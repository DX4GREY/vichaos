// ViChaos v3 — CLI decrypt file utility
#include "../../include/vichaos.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    return 1;
}

int vichaos_cli_decrypt_file(const char *input_path,
                             const char *output_path,
                             const char *password) {
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
        fclose(in); return fail("file too short");
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
    if (!s) { fail("invalid header/version/password"); goto cleanup; }

    cipher_len = file_size - (long)VICHAOS_HEADER_OVERHEAD - (long)VICHAOS_TAG_SIZE;

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

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input> <output> <password>\n", argv[0]);
        return 1;
    }
    return vichaos_cli_decrypt_file(argv[1], argv[2], argv[3]);
}
