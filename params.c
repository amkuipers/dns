#include "params.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "dnstypes.h"


// parse command line arguments
struct dns_params parse_args(int argc, char *argv[]) {
  struct dns_params params;

  if (argc < 2) {
    printf("Usage: %s hostname [dnstype] [ut] [dnsserverIP]\n", argv[0]);
    printf("  dnstype    : record type, default is txt, comma separated\n");
    printf("  ut         : tcp, default is udp\n");
    printf("  dnsserverIP: IP address, default is 8.8.8.8\n");
    exit(1);
  }

  params.hostname = argv[1];
  if (strlen(params.hostname) > 255) {
    fprintf(stderr, "[-] Hostname too long.");
    exit(1);
  }

  if (argc >= 3) {
    params.dns_type = argv[2];
    // uppercase  
    for (int i = 0; params.dns_type[i]; i++) {
      params.dns_type[i] = toupper(params.dns_type[i]);
    }
  } else {
    params.dns_type = "TXT";
  }

  // map dns_type tokens to int array
  params.dns_types_len = 0;
  char *token = strtok(params.dns_type, ",");
  while (token != NULL) {
    int type = get_type_int(token);
    if (type < 0) {
      fprintf(stderr, "[-] Invalid DNS record type %s\n", token);
      exit(1);
    }
    // check length
    if (params.dns_types_len >= MAX_DNS_TYPES) {
      fprintf(stderr, "[-] Too many DNS record types > %d\n", MAX_DNS_TYPES);
      exit(1);
    }
    params.dns_types[params.dns_types_len++] = type;
    token = strtok(NULL, ",");
  }
  // print dns_types
  printf("[+] DNS record types:\n");
  for (int i = 0; i < params.dns_types_len; i++) {
    printf("[+]    Record: %3d = %s\n", params.dns_types[i], get_type(params.dns_types[i]));
  } 
  // minimum 1 type
  if (params.dns_types_len < 1) {
    fprintf(stderr, "[-] No DNS record types specified \n");
    exit(1);
  }
 

  params.useTCP = 0;
  if (argc >= 4) {
    params.tcp_udp = argv[3];
    // case insensitive compare (might not be portable)
    if (strcasecmp(params.tcp_udp, "tcp") == 0) {
      params.useTCP = 1;
    } else if (strcasecmp(params.tcp_udp, "udp") == 0) {
      params.useTCP = 0;
    } else {
      fprintf(stderr, "[-] Invalid socket type %s\n", params.tcp_udp);
      exit(1);
    }
  } else {
    // default is UDP
    params.useTCP = 0;
  }

  if (argc == 5) {
    params.dns_server = argv[4];
  } else {
    // Google DNS is the default
    // Must be an IP address
    params.dns_server = "8.8.8.8";
  }

  params.serverPort = 53;

  return params;
  }
