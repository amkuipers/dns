#include "params.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dnstypes.h"


// Reverse an IP address for the PTR record
char* reverseIP(const char *ip) {
    // Split the IP address into segments
    char *segments[4];
    char *token = strtok((char*)ip, ".");
    int i = 0;

    while (token != NULL) {
        segments[i++] = token;
        token = strtok(NULL, ".");
    }

    // Reverse the order of the segments
    for (int j = 0; j < i / 2; j++) {
        char *temp = segments[j];
        segments[j] = segments[i - j - 1];
        segments[i - j - 1] = temp;
    }

    // Create a dynamically allocated string for the reversed IP address
    char *reversedIP = (char*)malloc(strlen(ip) + 1);
    sprintf(reversedIP, "%s.%s.%s.%s", segments[0], segments[1], segments[2], segments[3]);

    return reversedIP;
}



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
    
    // check for the PTR record type
    // assume that the hostname is an IP address
    if (type == 12) {
      // construct the arpa name
      params.arpa_name = malloc(strlen(params.hostname) + 13 + 1);
      strcpy(params.arpa_name, "");
      // reverse the ip address
      char *reversedIP = reverseIP(params.hostname);
      strcat(params.arpa_name, reversedIP);
      strcat(params.arpa_name, ".in-addr.arpa");
      free(reversedIP);
      printf("[+] PTR record requested, arpa name: %s\n", params.arpa_name);
    }

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

    // lookup ip address of dns_server name
    struct hostent *host;
    struct in_addr **addr_list;
    int i;
    host = gethostbyname(params.dns_server);
    if (host == NULL) {
      fprintf(stderr, "[-] Failed to lookup DNS server %s\n", params.dns_server);
      exit(1);
    }
    //params.dns_server = inet_ntoa(*(struct in_addr *)host->h_addr_list[0]);

    // print information about this host:
    printf("[+] DNS server official name is: %s\n", host->h_name);
    printf("[+] DNS server IP addresses: ");
    addr_list = (struct in_addr **)host->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++) {
        printf("%s ", inet_ntoa(*addr_list[i]));
    }
    printf(" (selected the first one)\n");
    params.dns_server = inet_ntoa(*(struct in_addr *)host->h_addr_list[0]);



  } else {
    // Google DNS is the default
    // Must be an IP address
    params.dns_server = "8.8.8.8";
  }

  params.serverPort = 53;

  return params;
  }
