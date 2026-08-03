/*
 * encrypt_file.c — stream-encrypt a file using the ViChaos v2 streaming API.
 *
 * Uses constant memory: the file is processed in chunks
 * (VICHAOS_STREAM_CHUNK = 1 MiB) regardless of file size.
 *
 * Usage: encrypt_file <input_file> <output_file> <password>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vichaos.h>

static int fail(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input_file> <output_file> <password>\n", argv[0]);
        return 1;
    }

    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        perror("Failed to open input file");
        return 1;
    }

    FILE *out = fopen(argv[2], "wb");
    if (!out) {
        perror("Failed to open output file");
        fclose(in);
        return 1;
    }

    /* ---- Init stream; write fixed 37-byte header ---- */
    uint8_t header[VICHAOS_HEADER_OVERHEAD];
    size_t header_len = 0;
    vichaos_stream_t *s = vichaos_stream_encrypt_init(argv[3], NULL,
                                                      header, &header_len);
    if (s == NULL) {
        fclose(in);
        fclose(out);
        return fail("stream init failed (RNG / KDF / memory)");
    }

    if (fwrite(header, 1, header_len, out) != header_len) {
        perror("Failed to write header");
        fclose(in);
        fclose(out);
        return 1;
    }

    /* ---- Process file in chunks ---- */
    uint8_t in_buf[VICHAOS_STREAM_CHUNK];
    uint8_t out_buf[VICHAOS_STREAM_CHUNK + 16]; /* EVP block margin */
    size_t n;
    vichaos_result_t res = VICHAOS_OK;

    while ((n = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
        size_t out_len = 0;
        res = vichaos_stream_encrypt_update(s, in_buf, n, out_buf, &out_len);
        if (res != VICHAOS_OK) {
            fprintf(stderr, "Encrypt failed: %s\n", vichaos_error_string(res));
            fclose(in);
            fclose(out);
            return 1;
        }
        if (fwrite(out_buf, 1, out_len, out) != out_len) {
            perror("Failed to write output");
            fclose(in);
            fclose(out);
            return 1;
        }
    }
    if (ferror(in)) {
        perror("Failed to read input");
        fclose(in);
        fclose(out);
        return 1;
    }

    /* ---- Finalize; write trailing 16-byte auth tag ---- */
    uint8_t tag[VICHAOS_TAG_SIZE];
    size_t tag_len = 0;
    res = vichaos_stream_encrypt_final(s, tag, &tag_len);
    if (res != VICHAOS_OK) {
        fprintf(stderr, "Finalize failed: %s\n", vichaos_error_string(res));
        fclose(in);
        fclose(out);
        return 1;
    }
    if (fwrite(tag, 1, tag_len, out) != tag_len) {
        perror("Failed to write auth tag");
        fclose(in);
        fclose(out);
        return 1;
    }

    fclose(in);
    fclose(out);

    printf("File encrypted successfully (constant memory streaming).\n");
    return 0;
}