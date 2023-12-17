
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
#include "connect.h"
#include "query.h"
#include "print.h"
#include "params.h"


/**
 * This application is a DNS client that can send DNS queries over TCP or UDP.
 * It can query for multiple DNS record types at once.
 * 
 * Usage: ./dns_client hostname [dnstype] [ut] [dnsserverIP]
 * dnstype    : record type, default is txt. Comma separated example: txt,ns,a,soa,cname
 * ut         : tcp, default is udp
 * dnsserverIP: IP address, default is 8.8.8.8
 * 
 */

int main(int argc, char *argv[]) {

  // Parse command line arguments
  struct dns_params params = parse_args(argc, argv);

  // Connect to the DNS server using TCP or UDP
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

  // Iterate the dns_types
  for (int i = 0; i < params.dns_types_len; i++) {

    int query_type = params.dns_types[i];
    printf("[+] Querying DNS type %d = %s\n", query_type, get_type(query_type));

    // Construct the DNS query
    unsigned char query[512]; // UDP max 512 bytes
    memset(query, 0, sizeof(query));
    int queryLen = 0;
    unsigned char *name = params.hostname;
    if (query_type == 12) {
      // PTR record type
      name = params.arpa_name;
    }
    if (params.useTCP) {

      // TCP: 2 bytes length in front of the query
      constructDNSQuery(query+2, &queryLen, name, query_type);
      query[0] = (queryLen >> 8) & 0xff;
      query[1] = queryLen & 0xff;
      queryLen += 2;

    } else {
      // UDP: no length in front of the query
      constructDNSQuery(query, &queryLen, name, query_type);
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

    // Send the DNS query
    if (send(dnsSocket, query, queryLen, 0) < 0) {
      perror("[-] Failed to send DNS query");
      close(dnsSocket);
      return -1;
    }

    // Receive the DNS response
    int responseLen = 0;
    unsigned char response[MAX_RESPONSE_SIZE]; 
    memset(response, 0, sizeof(response));
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

    // Repeat for the next query type
  }

  // Close the socket
  close(dnsSocket);

  return 0;
}
