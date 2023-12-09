#ifndef DNSTYPES_H
#define DNSTYPES_H

#include <string.h>

// Struct declaration
typedef struct {
  int type;
  char* name;
} DNSMap;

// Array declaration
extern DNSMap dnsMap[];

char* get_type(int type);
int get_type_int(char* name);

#endif // DNSTYPES_H