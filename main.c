
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "connect.h"
#include "query.h"
#include "print.h"

// ==================== MAIN ====================

int main(int argc, char *argv[]) {
  char *hostname;
  char *dns_type;
  char *dns_server;
  char *tcp_udp;

  if (argc < 2) {
    printf("Usage: %s hostname [dnstype] [ut] [dnsserverIP]\n", argv[0]);
    printf("  dnstype    : record type, default is txt\n");
    printf("  ut         : tcp, default is udp\n");
    printf("  dnsserverIP: IP address, default is 8.8.8.8\n");
    return 1;
  }

  hostname = argv[1];
  if (strlen(hostname) > 255) {
    fprintf(stderr, "[-] Hostname too long.");
    exit(1);
  }

  if (argc >= 3) {
    dns_type = argv[2];
    // uppercase  
    for (int i = 0; dns_type[i]; i++) {
      dns_type[i] = toupper(dns_type[i]);
    }
  } else {
    dns_type = "TXT";
  }
  int query_type = get_type_int(dns_type);
  if (query_type < 0) {
    fprintf(stderr, "[-] Invalid DNS record type %s\n", dns_type);
    exit(1);
  }

  int useTCP = 0;
  if (argc >= 4) {
    tcp_udp = argv[3];
    // case insensitive compare (might not be portable)
    if (strcasecmp(tcp_udp, "tcp") == 0) {
      useTCP = 1;
    } else if (strcasecmp(tcp_udp, "udp") == 0) {
      useTCP = 0;
    } else {
      fprintf(stderr, "[-] Invalid socket type %s\n", tcp_udp);
      exit(1);
    }
  } else {
    // default is UDP
    useTCP = 0;
  }

  if (argc == 5) {
    dns_server = argv[4];
  } else {
    // Google DNS is the default
    // Must be an IP address
    dns_server = "8.8.8.8";
  }

  int serverPort = 53;

  int dnsSocket;
  if (useTCP) {
    dnsSocket = connectTCP(dns_server, serverPort);
  } else {
    dnsSocket = connectUDP(dns_server, serverPort);
  }
  if (dnsSocket < 0) {
    printf("[-] Failed to connect to DNS server %s\n", dns_server);
    return -1;
  }

  printf("[+] Connected socket %d to DNS server %s:%d query %s\n", dnsSocket, dns_server, serverPort, dns_type);

  // Construct the DNS query
  unsigned char query[512]; // UDP max 512 bytes
  memset(query, 0, sizeof(query));
  int queryLen = 0;
  if (useTCP) {
    // TCP: 2 bytes length in front of the query
    constructDNSQuery(query+2, &queryLen, hostname, query_type);
    query[0] = (queryLen >> 8) & 0xff;
    query[1] = queryLen & 0xff;
    queryLen += 2;

  } else {
    constructDNSQuery(query, &queryLen, hostname, query_type);
  }

  // Print the DNS query
  printf("[+] DNS query:\n");
  hexdump(query, queryLen);

  if (useTCP) {
    printf("[+] TCP DNS query:\n");
    print_packet(query+2, queryLen-2);
  } else {
    printf("[+] UDP DNS query:\n");
    print_packet(query, queryLen);
  }


  // retry
  int retries = 0;
  int responseLen = 0;

  unsigned char response[64*1024]; // tcp max 64k
  memset(response, 0, sizeof(response));
  do {

    // Send the DNS query
    if (send(dnsSocket, query, queryLen, 0) < 0) {
      perror("[-] Failed to send DNS query");
      close(dnsSocket);
      return -1;
    }
  
    // Receive the DNS response

    responseLen = recv(dnsSocket, response, sizeof(response), 0);
    //printf("DNS Response:\n%s\n", response);
    retries++;
  } while (retries < 1 && responseLen <= 0);
  printf("Retries: %d\n", retries-1);


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

  if (useTCP) {
    printf("[+] TCP DNS response:\n");
    print_packet(response+2, responseLen-2);
  } else {
    printf("[+] UDP DNS response:\n");
    print_packet(response, responseLen);
  }

  // Close the socket
  close(dnsSocket);

  return 0;
}
