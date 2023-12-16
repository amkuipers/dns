
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "connect.h"
#include "query.h"
#include "print.h"

// assume max 10 types
#define MAX_DNS_TYPES 10
// Define the maximum response size as 64k
#define MAX_RESPONSE_SIZE 65536 

// structure to store parameters
struct dns_params {
  char *hostname;
  char *dns_type;
  char *dns_server;
  char *tcp_udp;

  int dns_types[MAX_DNS_TYPES]; 
  int dns_types_len;
  int useTCP;
  int serverPort;
};

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
  printf("[+] DNS types:\n");
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


// ==================== MAIN ====================

int main(int argc, char *argv[]) {
  // Parse command line arguments
  struct dns_params params = parse_args(argc, argv);

  int dnsSocket;
  if (params.useTCP) {
    dnsSocket = connectTCP(params.dns_server, params.serverPort);
  } else {
    dnsSocket = connectUDP(params.dns_server, params.serverPort);
  }
  if (dnsSocket < 0) {
    printf("[-] Failed to connect to DNS server %s\n", params.dns_server);
    return -1;
  }

  printf("[+] Connected socket %d to DNS server %s:%d\n", dnsSocket, params.dns_server, params.serverPort);

  // iterate the dns_types
  for (int i = 0; i < params.dns_types_len; i++) {

    int query_type = params.dns_types[i];
    printf("[+] Querying DNS type %d = %s\n", query_type, get_type(query_type));
    // Construct the DNS query
    unsigned char query[512]; // UDP max 512 bytes
    memset(query, 0, sizeof(query));
    int queryLen = 0;
    if (params.useTCP) {
      // TCP: 2 bytes length in front of the query
      constructDNSQuery(query+2, &queryLen, params.hostname, query_type);
      query[0] = (queryLen >> 8) & 0xff;
      query[1] = queryLen & 0xff;
      queryLen += 2;

    } else {
      constructDNSQuery(query, &queryLen, params.hostname, query_type);
    }

    // Print the DNS query
    printf("[+] DNS query:\n");
    hexdump(query, queryLen);

    if (params.useTCP) {
      printf("[+] TCP DNS query:\n");
      print_packet(query+2, queryLen-2);
    } else {
      printf("[+] UDP DNS query:\n");
      print_packet(query, queryLen);
    }

    int responseLen = 0;
    unsigned char response[MAX_RESPONSE_SIZE]; 
    memset(response, 0, sizeof(response));

    // Send the DNS query
    if (send(dnsSocket, query, queryLen, 0) < 0) {
      perror("[-] Failed to send DNS query");
      close(dnsSocket);
      return -1;
    }

    // Receive the DNS response
    responseLen = recv(dnsSocket, response, sizeof(response), 0);


    if (responseLen < 0) {
      perror("[-] Failed to receive DNS response");
      close(dnsSocket);
      return -1;
    } else if (responseLen == 0) {
      printf("[-] Failed to receive DNS response: no data\n");
      close(dnsSocket);
      return -1;
    }

    // Print the DNS response
    printf("[+] DNS response:\n");
    hexdump(response, responseLen);

    if (params.useTCP) {
      printf("[+] TCP DNS response:\n");
      print_packet(response+2, responseLen-2);
    } else {
      printf("[+] UDP DNS response:\n");
      print_packet(response, responseLen);
    }

  }

  // Close the socket
  close(dnsSocket);

  return 0;
}
