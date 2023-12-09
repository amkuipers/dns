#include "hexdump.h"

// Function to print a hexdump of the received data
void hexdump(const uint8_t *data, size_t length) {
    printf("\n           ------------------------------------------------");
    printf("\n  0x%04zx / 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F \\ ASCII\n", length);
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
