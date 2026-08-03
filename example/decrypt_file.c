/*
 * decrypt_file.c — stream-decrypt a file using the ViChaos v2 streaming API.
 *
 * Uses constant memory: the file is processed in chunks
 * (VICHAOS_STREAM_CHUNK = 1 MiB) regardless of file size.
 *
 * IMPORTANT: streaming decryption releases plaintext chunks BEFORE the final
 * auth tag is verified. To avoid exposing unauthenticated data, we write to a
 * temporary file and only rename it into place after the tag verifies.
 *
 * Usage: decrypt_file <encrypted_file> <output_file> <password>
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
        fprintf(stderr, "Usage: %s <encrypted_file> <output_file> <password>\n", argv[0]);
        return 1;
    }

    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        perror("Failed to open input file");
        return 1;
    }

    /* Determine payload size: header + ciphertext + 16-byte tag. */
    if (fseek(in, 0, SEEK_END) != 0) {
        perror("fseek failed");
        fclose(in);
        return 1;
    }
    long file_size = ftell(in);
    if (file_size < (long)(VICHAOS_HEADER_OVERHEAD + VICHAOS_TAG_SIZE)) {
        fclose(in);
        return fail("file too short: missing header or auth tag");
    }
    if (fseek(in, 0, SEEK_SET) != 0) {
        perror("fseek failed");
        fclose(in);
        return 1;
    }

    /* Write to a temp file first; rename only after auth succeeds. */
    char tmp_path[4096];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", argv[2]) >= (int)sizeof(tmp_path)) {
        fclose(in);
        return fail("output path too long");
    }

    FILE *out = fopen(tmp_path, "wb");
    if (!out) {
        perror("Failed to open temporary output file");
        fclose(in);
        return 1;
    }

    /* ---- Read fixed 37-byte header ---- */
    uint8_t header[VICHAOS_HEADER_OVERHEAD];
    if (fread(header, 1, sizeof(header), in) != sizeof(header)) {
        fclose(in);
        fclose(out);
        remove(tmp_path);
        return fail("file too short: missing header");
    }

    vichaos_stream_t *s = vichaos_stream_decrypt_init(argv[3], header,
                                                      sizeof(header), NULL);
    if (s == NULL) {
        fclose(in);
        fclose(out);
        remove(tmp_path);
        return fail("invalid header / version / options");
    }

    /* ---- Stream-decrypt ciphertext (file_size - header - tag bytes) ---- */
    long cipher_len = file_size - (long)VICHAOS_HEADER_OVERHEAD - (long)VICHAOS_TAG_SIZE;

    uint8_t in_buf[VICHAOS_STREAM_CHUNK];
    uint8_t out_buf[VICHAOS_STREAM_CHUNK + 16]; /* EVP block margin */
    vichaos_result_t res = VICHAOS_OK;

    while (cipher_len > 0) {
        size_t want = (cipher_len > (long)sizeof(in_buf))
                          ? sizeof(in_buf)
                          : (size_t)cipher_len;
        size_t n = fread(in_buf, 1, want, in);
        if (n == 0) {
            if (ferror(in)) perror("Failed to read input");
            else fprintf(stderr, "Error: unexpected end of file\n");
            fclose(in);
            fclose(out);
            remove(tmp_path);
            return 1;
        }

        size_t out_len = 0;
        res = vichaos_stream_decrypt_update(s, in_buf, n, out_buf, &out_len);
        if (res != VICHAOS_OK) {
            fprintf(stderr, "Decrypt failed: %s\n", vichaos_error_string(res));
            fclose(in);
            fclose(out);
            remove(tmp_path);
            return 1;
        }
        if (fwrite(out_buf, 1, out_len, out) != out_len) {
            perror("Failed to write output");
            fclose(in);
            fclose(out);
            remove(tmp_path);
            return 1;
        }
        cipher_len -= (long)n;
    }

    /* ---- Read trailing 16-byte auth tag ---- */
    uint8_t tag[VICHAOS_TAG_SIZE];
    if (fread(tag, 1, sizeof(tag), in) != sizeof(tag)) {
        fclose(in);
        fclose(out);
        remove(tmp_path);
        return fail("file too short: missing auth tag");
    }

    /* ---- Finalize: verify auth tag ---- */
    res = vichaos_stream_decrypt_final(s, tag, sizeof(tag));
    if (res != VICHAOS_OK) {
        fprintf(stderr, "Authentication failed: %s\n", vichaos_error_string(res));
        fclose(in);
        fclose(out);
        remove(tmp_path);
        return 1;
    }

    fclose(in);
    fclose(out);

    /* Only now expose the plaintext. */
    if (rename(tmp_path, argv[2]) != 0) {
        perror("Failed to finalize output file");
        remove(tmp_path);
        return 1;
    }

    printf("File decrypted successfully to %s (authenticated).\n", argv[2]);
    return 0;
}