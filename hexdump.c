#include "hexdump.h"

// Function to print a hexdump of the received data
void hexdump(const uint8_t *data, size_t length) {
    printf("Length: %zu\n", length);
    for (size_t i = 0; i < length; i += 16) {
        // Print the address
        printf("%08zx | ", i);

        // Print hex values
        for (size_t j = i; j < i + 16; ++j) {
            if (j < length) {
                printf("%02X ", data[j]);
            } else {
                printf("   ");
            }
        }

        // Print ASCII representation
        printf("| ");
        for (size_t j = i; j < i + 16 && j < length; ++j) {
            if (isprint(data[j])) {
                printf("%c", data[j]);
            } else {
                printf(".");
            }
        }

        // Newline for the next line
        printf("\n");
    }
}
