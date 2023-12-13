#ifndef PRINT_H
#define PRINT_H

#include <stdlib.h>

#include "base64.h"
#include "dnstypes.h"
#include "hexdump.h"
#include "timestamp.h"


#define CONSUME_8BIT(x) (x = packet[offset++]);
#define CONSUME_16BIT(x) (x = (packet[offset] << 8) | packet[offset + 1]); offset += 2;
#define CONSUME_32BIT(x) (x = (packet[offset] << 24) | (packet[offset + 1] << 16) | (packet[offset + 2] << 8) | packet[offset + 3]); offset += 4;

// Print from the response the domain name starting at p, using domain name pointers
// msg is the start of the DNS message
// p is the start of the domain name
// end is the end of the DNS message
// returns the end of the domain name
unsigned char *print_name(
		const unsigned char *msg,
        const unsigned char *p, 
        const unsigned char *end
        ) ;

// Print from the response the domain name(s) starting at p, using domain name pointers, inc hexdump
unsigned char *print_names(
		const unsigned char *msg,
        const unsigned char *p, 
        const unsigned char *end
		);

// Print chain of Pascal strings from the response starting at p
// p points to the length byte of the string that follows
// returns the length processed
int print_domain(unsigned char *p);


void print_packet_info(unsigned char* packet);

// Print the DNS request or response
// length is the length of the response
void print_packet(unsigned char *response, int length);

#endif // PRINT_H