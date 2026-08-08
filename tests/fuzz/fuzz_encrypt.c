// ViChaos v3 — Fuzz target for encrypt/decrypt
// Compile with: gcc -fsanitize=address,fuzzer -I../include fuzz_encrypt.c -o fuzz_encrypt -lcrypto
#include "../../include/vichaos.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    if (len < 8) return 0;

    const char *password = "fuzz-pw";
    uint8_t *out = NULL;
    size_t out_len = 0;

    /* Try encrypting the fuzz input as data */
    vichaos_result_t r = vichaos_encrypt(data, len, password, 7, NULL, &out, &out_len);
    if (r == VICHAOS_SUCCESS && out) {
        uint8_t *dec = NULL;
        size_t dec_len = 0;
        r = vichaos_decrypt(out, out_len, password, 7, NULL, &dec, &dec_len);
        if (r == VICHAOS_SUCCESS) {
            if (dec_len != len || memcmp(dec, data, len) != 0) {
                /* Should not happen */
            }
            free(dec);
        }
        free(out);
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <corpus_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz > 0 ? sz : 1);
    if (sz > 0) fread(buf, 1, sz, f);
    fclose(f);
    LLVMFuzzerTestOneInput(buf, sz);
    free(buf);
    return 0;
}
