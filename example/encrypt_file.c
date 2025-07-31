#include <stdio.h>
#include <stdlib.h>
#include <vichaos.h>

int main(int argc, char** argv) {
    if (argc != 4) {
        printf("Usage: %s <input_file> <output_file> <password>\n", argv[0]);
        return 1;
    }

    // Baca file input
    FILE* in = fopen(argv[1], "rb");
    fseek(in, 0, SEEK_END);
    long size = ftell(in);
    fseek(in, 0, SEEK_SET);

    uint8_t* data = malloc(size);
    fread(data, 1, size, in);
    fclose(in);

    // Enkripsi
    uint8_t* encrypted;
    size_t encrypted_len;
    vichaos_result_t res = vichaos_encrypt(data, size, argv[3], &encrypted, &encrypted_len);
    
    free(data);
    
    if (res != VICHAOS_OK) {
        printf("Error: %s\n", vichaos_error_string(res));
        return 1;
    }

    // Tulis file output
    FILE* out = fopen(argv[2], "wb");
    fwrite(encrypted, 1, encrypted_len, out);
    fclose(out);
    
    vichaos_free(encrypted);
    
    printf("File encrypted successfully!\n");
    return 0;
}