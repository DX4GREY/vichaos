#include <stdio.h>
#include <stdlib.h>
#include <vichaos.h>

int main(int argc, char** argv) {
    if (argc != 4) {
        printf("Usage: %s <encrypted_file> <output_file> <password>\n", argv[0]);
        return 1;
    }

    // Read encrypted file
    FILE* in = fopen(argv[1], "rb");
    if (!in) {
        perror("Failed to open input file");
        return 1;
    }

    fseek(in, 0, SEEK_END);
    long size = ftell(in);
    fseek(in, 0, SEEK_SET);

    uint8_t* encrypted_data = malloc(size);
    if (!encrypted_data) {
        perror("Memory allocation failed");
        fclose(in);
        return 1;
    }

    if (fread(encrypted_data, 1, size, in) != size) {
        perror("Failed to read input file");
        free(encrypted_data);
        fclose(in);
        return 1;
    }
    fclose(in);

    // Decrypt
    uint8_t* decrypted;
    size_t decrypted_len;
    vichaos_result_t res = vichaos_decrypt(encrypted_data, size, argv[3], &decrypted, &decrypted_len);
    
    free(encrypted_data);
    
    if (res != VICHAOS_OK) {
        printf("Decryption failed: %s\n", vichaos_error_string(res));
        return 1;
    }

    // Write output file
    FILE* out = fopen(argv[2], "wb");
    if (!out) {
        perror("Failed to open output file");
        vichaos_free(decrypted);
        return 1;
    }

    if (fwrite(decrypted, 1, decrypted_len, out) != decrypted_len) {
        perror("Failed to write output file");
        fclose(out);
        vichaos_free(decrypted);
        return 1;
    }
    fclose(out);
    
    vichaos_free(decrypted);
    
    printf("File decrypted successfully to %s\n", argv[2]);
    return 0;
}