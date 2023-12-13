#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>

void base64_encode(const unsigned char *bytes_to_encode, unsigned int in_len, char *out);

#endif // BASE64_H