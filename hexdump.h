#ifndef HEXDUMP_H
#define HEXDUMP_H

// Include necessary libraries
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <ctype.h>

// Function declaration
void hexdump(const uint8_t *data, size_t length);

#endif // HEXDUMP_H