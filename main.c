
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "connect.h"
#include "hexdump.h"
#include "dnstypes.h"
#include "query.h"


unsigned char *print_name(
		const unsigned char *msg,
        const unsigned char *p, 
        const unsigned char *end
        ) {
    // recursive

    if (p + 2 > end) {
        fprintf(stderr, "[-] A: End of message.\n"); 
        exit(1);
    }

    if ((*p & 0xC0) == 0xC0) {
    	// Name Pointer = offset to name (has high 2 bits set)
        const int k = ((*p & 0x3F) << 8) + p[1];
        p += 2;
        //printf(" (pointer %d) ", k);
        print_name(msg, msg+k, end);
        return (unsigned char *)p;

    } else {
    	// Not a name pointer
        const int len = *p++;
        if (p + len + 1 > end) {
            fprintf(stderr, "[-] B: End of message.\n"); 
            exit(1);
        }

		// domain name parts

        printf("%.*s", len, p);
        p += len;
        if (*p) {
        	// next part
            printf(".");
            return print_name(msg, p, end);
        } else {
            return (unsigned char *)p+1;
        }
    }
}

unsigned char *print_names(
		const unsigned char *msg,
        const unsigned char *p, 
        const unsigned char *end
		){
		
		unsigned char *q = (unsigned char*)p;
		while (q < end) {
			q = (unsigned char*)print_name(msg, q, end);
			printf("\n");
			hexdump(q, end-q);
		}
		return q;
		
}

// this uses a length byte in front of the domain name, without pointers
// returns the length of the domain name
int print_domain(unsigned char *p) {
  unsigned char *start = p;
  int len;
  do { 
    len = *p++;
    printf("%.*s", len, p);
    p += len;
    if (*p ) printf(".");
  } while (*p > 0);
  return p - start + 1; // include the 0 at the end
}


#define CONSUME_8BIT(x) (x = packet[offset++]);
#define CONSUME_16BIT(x) (x = (packet[offset] << 8) | packet[offset + 1]); offset += 2;
#define CONSUME_32BIT(x) (x = (packet[offset] << 24) | (packet[offset + 1] << 16) | (packet[offset + 2] << 8) | packet[offset + 3]); offset += 4;

// Print the DNS request or response
void print_packet(unsigned char *response, int length) {

  // Parse the DNS packet
  unsigned char *packet = response;

  // Header section
  // ID  to uniquely define the message relationship between query and response
  printf("[+] ID: 0x%02x%02x; 16bit client id\n", packet[0], packet[1]);

  // QR, Opcode, AA, TC, RD
  printf("[+] QR, Opcode, AA, TC, RD: 0x%02x; 8bit\n", packet[2]);
  const int qr = (packet[2] >> 7) & 0x01;
  printf("    [+] QR    : %d=%s; 1bit (0=query, 1=response)\n", qr, qr ? "response" : "query");
  const int opcode = (packet[2] >> 3) & 0x0f;
  printf("    [+] Opcode: %d; 4bit =", opcode);
  switch(opcode) {
      case 0: printf("standard\n"); break;
      case 1: printf("reverse\n"); break;
      case 2: printf("status\n"); break;
      default: printf("?\n"); break;
  }  
  const int aa = (packet[2] >> 2) & 0x01;
  printf("    [+] AA    : %d; 1bit =%s\n", aa, aa ? "authoritative answer" : "");
  const int tc = (packet[2] >> 1) & 0x01;
  printf("    [+] TC    : %d; 1bit =%s\n", tc, tc ? "message truncated (should be resend via TCP)" : "not truncated");
  const int rd = packet[2] & 0x01;
  printf("    [+] RD    : %d; 1bit =%s\n", rd, rd ? "recursion desired" : "");


  if (qr) {
      const int rcode = packet[3] & 0x0F;
      printf("Header RCODE = %d; 4bit ", rcode);
      switch(rcode) {
          case 0: printf("success\n"); break;
          case 1: printf("format error\n"); break;
          case 2: printf("server failure\n"); break;
          case 3: printf("name error\n"); break;
          case 4: printf("not implemented\n"); break;
          case 5: printf("refused\n"); break;
          default: printf("?\n"); break;
      }
      if (rcode != 0) return;
  }

  // RA, Z, RCODE
  printf("[+] RA, Z, RCODE: 0x%02x; 8bit\n", packet[3]);
  const int ra = (packet[3] >> 7) & 0x01;
  printf("    [+] RA   : %d (1=server supports recursion)\n", ra);
  const int z = (packet[3] >> 4) & 0x07;
  printf("    [+] Z    : %d (future use)\n", z);
  const int rcode = packet[3] & 0x0f;
  printf("    [+] RCODE: %d\n", rcode);

  // RA is set in the response if the server supports recursion
  // Z is reserved for future use
  // RCODE is the response code (0=success, 1=format error, 2=server failure, 3=name error, 4=not implemented, 5=refused)

  int offset = 4;
  
  // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
  int qdcount;
  int ancount;
  int nscount;
  int arcount;
  CONSUME_16BIT(qdcount);
  CONSUME_16BIT(ancount);
  CONSUME_16BIT(nscount);
  CONSUME_16BIT(arcount);

  printf("[+] QDCOUNT: %2d; 16bit number of entries in the query section (fixed 1 when query)\n", qdcount);
  printf("[+] ANCOUNT: %2d; 16bit number of answers\n", ancount);
  printf("[+] NSCOUNT: %2d; 16bit number of name server resource records\n", nscount);
  printf("[+] ARCOUNT: %2d; 16bit number of resource records in the additional records\n", arcount);

  // QDCOUNT is the number of entries in the question section of a query.
  // ANCOUNT is the number of resource records in the answer section of a response.
  // NSCOUNT is the number of name server resource records in the authority records section of a response.
  // ARCOUNT is the number of resource records in the additional records section of a response.


  // Question section
  // QNAME is the domain name being queried
  printf("[+] QNAME: ");
  offset += print_domain(response + offset);

  printf("\n");

  // QTYPE, QCLASS
  // QTYPE is the type of the query (1=A, 2=NS, 5=CNAME, 6=SOA, 12=PTR, 15=MX, 16=TXT, 28=AAAA, 33=SRV, 46=RRSIG, 47=NSEC, 48=DNSKEY, 255=ANY)
  int qtype;
  // QCLASS is the class of the query (1=Internet, 2=CSNET, 3=CHAOS, 4=Hesiod, 255=ANY)
  int qclass;
  CONSUME_16BIT(qtype);
  CONSUME_16BIT(qclass);

  printf("[+] QTYPE : %d=%s; 16bit record type\n", qtype, get_type(qtype));
  printf("[+] QCLASS: %d; 16bit (should be 1=Internet)\n", qclass);


  if (qr==0 && (offset < length)) {
    printf("MORE DATA IN QUERY!!! %d < %d\n", offset, length);
  }

  // Answer section
  if (ancount || nscount || arcount) {

    printf("[+] Answer section:\n");
    for (int i = 0; i < ancount + nscount + arcount; i++) {
      printf("[+] Answer %2d\n", i + 1); // answer 1, 2, ..

      printf("    [+] NAME     : ");
      unsigned char *p = response + offset;
      p = print_name(response, p, response + length);
      printf("\n");
      offset = p - response; 

      // TYPE is the type of the resource record (1=A, 2=NS, 5=CNAME, 6=SOA, 12=PTR, 15=MX, 16=TXT, 28=AAAA, 33=SRV, 46=RRSIG, 47=NSEC, 48=DNSKEY, 255=ANY)
      int type;
      // CLASS is the class of the resource record (1=Internet)
      int class;
      // TTL is the time in seconds that the answer is allowed to cache
      int ttl;
      // RDLENGTH is the length of the RDATA field
      int rdlength;

      CONSUME_16BIT(type);
      CONSUME_16BIT(class);
      CONSUME_32BIT(ttl);
      CONSUME_16BIT(rdlength); 

      printf("    [+] TYPE     : %d; 16bit record type: %s\n", type, get_type(type));
      printf("    [+] CLASS    : %d; 16bit (should be 1=Internet)\n", class);
      printf("    [+] TTL      : %u sec; 32bit; %u minutes the answer is allowed to cache\n", ttl, ttl/60);
      printf("    [+] RDLENGTH : %d; 16bit length of rdata\n", rdlength);

      // RDATA is the data for the resource record
      printf("    [+] RDATA ");

      if (rdlength == 4 && type == 1) {
        /* A Record */
        printf("Address = ");
        unsigned char *p = response + offset;
        printf("%d.%d.%d.%d\n", p[0], p[1], p[2], p[3]);
        offset += rdlength;

      } else if (type == 2) {
        /* NS */
        printf("NS : ");
        unsigned char *p = response + offset;
        p = print_name(response, p, response+length);
        offset = p - response; 

        printf("\n"); 
      } else if (type == 5) {
        // CNAME
        printf("CNAME : ");
        unsigned char *p = response + offset;
        p = print_name(response, p, response+length);
        offset = p - response;
        printf("\n");



      } else if (type == 6) {
        /* SOA 
        https://en.wikipedia.org/wiki/SOA_record
        https://datatracker.ietf.org/doc/html/rfc1912
        */
        printf("SOA: type %d rdlen %d \n", type, rdlength);
        // MNAME Primary master name
        // RNAME email aa\.bb.domain.com ==> aa.bb@domain.com
        // SERIAL for this zone (date + 05 = 2017031405 )
        // REFRESH 86400 seconds
        // RETRY seconds (7200 = 2hours recommended)
        // EXPIRE seconds secondary dns 3600000 seconds (1000 hours).
        // MINIMUM seconds TTL 172800 seconds (2 days)
        printf("        SOA: MNAME Primary master name = ");
        unsigned char *p = response + offset;
        p = print_name(response, p, response+length); 
        offset = p - response; 
        printf("\n");

        printf("        SOA: RNAME email = ");
        p = print_name(response, p, response+length); 
        offset = p - response; 
        printf("\n");

        // SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
        int serial;
        int refresh;
        int retry;
        int expire;
        int minimum;

        CONSUME_32BIT(serial);
        CONSUME_32BIT(refresh);
        CONSUME_32BIT(retry);
        CONSUME_32BIT(expire);
        CONSUME_32BIT(minimum);

        printf("        SOA: SERIAL  = %d\n", serial);
        printf("        SOA: REFRESH = %d sec\n", refresh);
        printf("        SOA: RETRY   = %d sec (7200 recommended)\n", retry);
        printf("        SOA: EXPIRE  = %d sec\n", expire);
        printf("        SOA: MINIMUM = %d sec\n", minimum);

        offset = p - response;

        if (offset < rdlength) {
          printf("MORE DATA!!!");
        }


      } else if (type == 15 && rdlength > 3) {
        /* MX Record */
        unsigned char *p = response + offset;
        const int preference = (p[0] << 8) + p[1];
        printf("MX: pref: %d ", preference);
        printf("= ");
        p=print_name(response, p+2, response+length); printf("\n");
        offset = p - response; 

      } else if (type == 13) {
        /* HINFO Record */
        printf("HINFO: ");
        //hexdump(response+offset, rdlength);

        unsigned char *p = response + offset;
        int len = p[0];
        printf("CPU: ");
        for (int j = 0; j < len; j++) {
          printf("%c", p[j+1]);
        }
        printf(" OS: ");
        len = p[len+1];
        for (int j = 0; j < len; j++) {
          printf("%c", p[j+1+len]);
        }
        printf("\n");
        offset += rdlength;

      } else if (type == 16) {
        /* TXT Record */
        //printf("TXT: ");
        //hexdump(response+offset, rdlength);
        // TCP has 8bit length in front of the TXT data
        int len = 0;
        do {
          CONSUME_8BIT(len);
          printf("\n        [+] TXT: len %d\n", len);
          printf("        [+] TXT: \"");

          for (int j = 0; j < len; j++) {
            printf("%c", response[offset++]);
          }
          printf("\"");
        } while (len == 0xFF);
        printf("\n");


      } else if (rdlength == 16 && type == 28) {
        /* AAAA Record */
        printf("AAAA: Address ");
        unsigned char *p = response + offset;

        int j;
        for (j = 0; j < rdlength; j+=2) {
            printf("%02x%02x", p[j], p[j+1]);
            if (j + 2 < rdlength) printf(":");
        }
        offset += rdlength;

        printf("\n");
      } else if (type == 46) {
        // RRSIG
        printf("RRSIG: type %d rdlen %d \n", type, rdlength);
        hexdump(response+offset, rdlength);
        // TYPE Covered
        // ALGORITHM
        // LABELS
        // ORIGINAL TTL
        // SIGNATURE EXPIRATION
        // SIGNATURE INCEPTION
        // KEY TAG
        // SIGNER'S NAME
        // SIGNATURE
        int type_covered;
        int algorithm;
        int labels;
        int original_ttl;
        int signature_expiration;
        int signature_inception;
        int key_tag;
        int signer_name_length;

        CONSUME_16BIT(type_covered);
        CONSUME_8BIT(algorithm);
        CONSUME_8BIT(labels);
        CONSUME_32BIT(original_ttl);
        CONSUME_32BIT(signature_expiration);
        CONSUME_32BIT(signature_inception);
        CONSUME_16BIT(key_tag);
        //CONSUME_8BIT(signer_name_length);

        printf("        RRSIG: TYPE Covered = %d\n", type_covered);
        printf("        RRSIG: ALGORITHM = %d (13=ECDSA Curve P-256 with SHA-256)\n", algorithm);
        printf("        RRSIG: LABELS = %d\n", labels);
        printf("        RRSIG: ORIGINAL TTL = %d\n", original_ttl);
        printf("        RRSIG: SIGNATURE EXPIRATION = %d (timestamp)\n", signature_expiration);
        printf("        RRSIG: SIGNATURE INCEPTION = %d (timestamp)\n", signature_inception);
        printf("        RRSIG: KEY TAG = %d\n", key_tag);
        printf("        RRSIG: SIGNER'S NAME = ");

        offset += print_domain(response + offset);

        printf("\n");
        printf("        RRSIG: SIGNATURE = ");
        for (int j = 0; j < rdlength - 18; j++) {
          printf("%02x", response[offset++]);
        }
        printf("\n");


      } else {
        printf("    [+] RDATA (raw): ");

        for (int j = 0; j < rdlength/*((response[offset - 2] << 8) | response[offset - 1])*/; j++) {
          printf("%02x", response[offset++]);
        }
        printf("\n");
      }


    }
  }

  
}


// ==================== MAIN ====================

int main(int argc, char *argv[]) {
  char *hostname;
  char *dns_type;
  char *serverIP;

  if (argc < 2) {
    printf("Usage: %s hostname [dnstype] [dnsserverIP]\n", argv[0]);
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

  if (argc == 4) {
    serverIP = argv[3];
  } else {
    serverIP = "8.8.8.8";
  }

  int serverPort = 53;

  int useTCP = 1;
  int dnsSocket;
  if (useTCP) {
    dnsSocket = connectTCP(serverIP, serverPort);
  } else {
    dnsSocket = connectUDP(serverIP, serverPort);
  }
  if (dnsSocket < 0) {
    printf("[-] Failed to connect to DNS server %s\n", serverIP);
    return -1;
  }

  printf("[+] Connected socket %d to DNS server %s:%d query %s\n", dnsSocket, serverIP, serverPort, dns_type);

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

  unsigned char response[2048];
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
