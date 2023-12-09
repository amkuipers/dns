#ifndef QUERY_H
#define QUERY_H

#include <string.h>

void constructDNSQuery(unsigned char *query, int *queryLen, char *hostname, int query_type);

#endif // QUERY_H