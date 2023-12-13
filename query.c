
#include "query.h"

// Construct a DNS query
// query: the query buffer (will be updated)
// queryLen: the length of the query buffer (will be updated)
// hostname: the hostname to query
// query_type: the query type (A, MX, etc.) as integer
void constructDNSQuery(unsigned char *query, int *queryLen, char *hostname, int query_type) {
  // Header section
  // ID (client supplied)
  query[(*queryLen)++] = 0x12; 
  query[(*queryLen)++] = 0x34;
  // QR, Opcode, AA, TC, RD
  query[(*queryLen)++] = 0x01; // recursion desired
  // RA, Z, RCODE
  query[(*queryLen)++] = 0x00;
  // QDCOUNT
  query[(*queryLen)++] = 0x00;
  query[(*queryLen)++] = 0x01; // 1 question
  // ANCOUNT
  query[(*queryLen)++] = 0x00;
  query[(*queryLen)++] = 0x00;
  // NSCOUNT
  query[(*queryLen)++] = 0x00;
  query[(*queryLen)++] = 0x00;
  // ARCOUNT
  query[(*queryLen)++] = 0x00;
  query[(*queryLen)++] = 0x00;

  // Question section
  // QNAME
  int i;
  int j = 0;
  for (i = 0; i < strlen(hostname); i++) {
    if (hostname[i] == '.') {
      query[(*queryLen)++] = i - j;
      for (; j < i; j++) {
        query[(*queryLen)++] = hostname[j];
      }
      j++;
    }
  }
  query[(*queryLen)++] = i - j;
  for (; j < i; j++) {
    query[(*queryLen)++] = hostname[j];
  }

  // add 0 to terminate the QNAME
  query[(*queryLen)++] = 0x00;

  // QTYPE
  query[(*queryLen)++] = (query_type >> 8) & 0xff;
  query[(*queryLen)++] = query_type & 0xff;

  // QCLASS
  query[(*queryLen)++] = 0x00;
  query[(*queryLen)++] = 0x01;

  return;
}
