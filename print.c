#include "print.h"


// Print from the response the domain name starting at p, using domain name pointers
// msg is the start of the DNS message
// p is the start of the domain name
// end is the end of the DNS message
// returns the end of the domain name
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

      // Domain name parts
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

// Print from the response the domain name(s) starting at p, using domain name pointers, inc hexdump
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

// Print chain of Pascal strings from the response starting at p
// p points to the length byte of the string that follows
// returns the length processed
int print_domain(unsigned char *p) {
  unsigned char *start = p;
  int len;
  do { 
    len = *p++;
    printf("%.*s", len, p);
    p += len;
    if (*p ) printf("."); // another pascal string follows
  } while (*p > 0);
  return p - start + 1; // include the last pascal string with length 0 at the end
}




// Print the DNS request or response
// length is the length of the response
void print_packet(unsigned char *response, int length) {

  // Parse the DNS packet
  unsigned char *packet = response;


  // Header section
  // ID  to uniquely define the message relationship between query and response
  printf("[+] ID     : 0x%02x%02x; 16bit client id\n", packet[0], packet[1]);

  // QR, Opcode, AA, TC, RD
  printf("[+] QR, Opcode, AA, TC, RD: 0x%02x; 8bit\n", packet[2]);
  const int qr = (packet[2] >> 7) & 0x01;
  printf("[+]     QR    : %d=%s; 1bit (0=query, 1=response)\n", qr, qr ? "response" : "query");
  const int opcode = (packet[2] >> 3) & 0x0f;
  printf("[+]     Opcode: %d; 4bit =", opcode);
  switch(opcode) {
      case 0: printf("standard\n"); break;
      case 1: printf("reverse\n"); break;
      case 2: printf("status\n"); break;
      default: printf("?\n"); break;
  }  
  const int aa = (packet[2] >> 2) & 0x01;
  printf("[+]     AA    : %d; 1bit =%s\n", aa, aa ? "authoritative answer" : "");
  const int tc = (packet[2] >> 1) & 0x01;
  printf("[+]     TC    : %d; 1bit =%s\n", tc, tc ? "message truncated (should be resend via TCP)" : "not truncated");
  const int rd = packet[2] & 0x01;
  printf("[+]     RD    : %d; 1bit =%s\n", rd, rd ? "recursion desired" : "");


  // RA, Z, RCODE
  printf("[+] RA, Z, RCODE: 0x%02x; 8bit\n", packet[3]);
  const int ra = (packet[3] >> 7) & 0x01;
  printf("[+]     RA    : %d; 1bit (1=server supports recursion)\n", ra);
  const int z = (packet[3] >> 4) & 0x07;
  printf("[+]     Z     : %d; 3bit (future use)\n", z);
  const int rcode = packet[3] & 0x0f;
  printf("[+]     RCODE : %d; 4bit (response code) ", rcode);
  if (qr==0) {
    // Query
    printf("\n");
  } else {
    // Response
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
  printf("[+] QNAME  : ");
  offset += print_domain(packet + offset);

  printf("\n");

  // QTYPE, QCLASS
  // QTYPE is the type of the query (1=A, 2=NS, 5=CNAME, 6=SOA, 12=PTR, 15=MX, 16=TXT, 28=AAAA, 33=SRV, 46=RRSIG, 47=NSEC, 48=DNSKEY, 255=ANY)
  int qtype;
  // QCLASS is the class of the query (1=Internet, 2=CSNET, 3=CHAOS, 4=Hesiod, 255=ANY)
  int qclass;
  CONSUME_16BIT(qtype);
  CONSUME_16BIT(qclass);

  printf("[+] QTYPE  : %d; 16bit record type= %s\n", qtype, get_type(qtype));
  printf("[+] QCLASS : %d; 16bit (should be 1=Internet)\n", qclass);


  if (qr==0 && (offset < length)) {
    printf("[-] MORE DATA IN QUERY!!! %d < %d\n", offset, length);
  }

  // Answer section
  int answers = ancount + nscount + arcount;
  if (ancount || nscount || arcount) {

    printf("[+] Answer section:\n");
    for (int i = 0; i < answers; i++) {

      printf("[+] Answer %d of %d\n", i + 1, answers); // answer 1, 2, ..


      printf("[+]     NAME     : ");
      unsigned char *p = packet + offset;
      p = print_name(packet, p, packet + length);
      printf("\n");
      offset = p - packet; 

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

      printf("[+]     TYPE     : %d; 16bit record type: %s\n", type, get_type(type));
      printf("[+]     CLASS    : %d; 16bit (should be 1=Internet)\n", class);
      printf("[+]     TTL      : %u sec; 32bit; %u minutes the answer is allowed to cache\n", ttl, ttl/60);
      printf("[+]     RDLENGTH : %d; 16bit length of rdata\n", rdlength);

      // RDATA is the data for the resource record
      printf("[+]     RDATA    : ");

      //hexdump(packet + offset, rdlength);


      if (rdlength == 4 && type == 1) {
        /* A Record */
        unsigned char *p = packet + offset;
        printf("%d.%d.%d.%d (A record, IPv4 address)\n", p[0], p[1], p[2], p[3]);
        offset += rdlength;

      } else if (type == 2) {
        /* NS */
        unsigned char *p = packet + offset;
        p = print_name(packet, p, packet+length);
        offset = p - packet; 
        printf(" (NS record)\n"); 

      } else if (type == 5) {
        // CNAME
        unsigned char *p = packet + offset;
        p = print_name(packet, p, packet+length);
        offset = p - packet;
        printf(" (CNAME record)\n");

      } else if (type == 6) {
        /* SOA 
        https://en.wikipedia.org/wiki/SOA_record
        https://datatracker.ietf.org/doc/html/rfc1912
        */
        printf("(SOA Start of Authority)\n");
        //hexdump(packet+offset, rdlength);

        // MNAME Primary master name
        // RNAME email aa\.bb.domain.com ==> aa.bb@domain.com
        // SERIAL for this zone (date + 05 = 2017031405 )
        // REFRESH 86400 seconds
        // RETRY seconds (7200 = 2hours recommended)
        // EXPIRE seconds secondary dns 3600000 seconds (1000 hours).
        // MINIMUM seconds TTL 172800 seconds (2 days)
        printf("[+]          MNAME  : ");
        unsigned char *p = packet + offset;
        p = print_name(packet, p, packet+length); 
        offset = p - packet; 
        printf(" (Primary master name; the DNS server to use)\n");

        printf("[+]          RNAME  : ");
        p = print_name(packet, p, packet+length); 
        offset = p - packet; 
        printf(" (email)\n");

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

        printf("[+]          SERIAL : %d\n", serial);
        printf("[+]          REFRESH: %d sec = %d min\n", refresh, refresh/60);
        printf("[+]          RETRY  : %d sec = %d min (7200 sec recommended)\n", retry, retry/60);
        printf("[+]          EXPIRE : %d sec = %d min\n", expire, expire/60);
        printf("[+]          MINIMUM: %d sec = %d min\n", minimum, minimum/60);


      } else if (type == 15 && rdlength > 3) {
        /* MX Record */
        printf("(MX record)\n");

        unsigned char *p = packet + offset;
        const int preference = (p[0] << 8) + p[1];
        printf("[+]          PREF   : %d\n", preference);
        printf("[+]          NAME   : ");
        p=print_name(packet, p+2, packet+length); 
        printf("\n");
        offset = p - packet; 

      } else if (type == 13) {
        /* HINFO Record */
        printf("(HINFO record)\n");
        //hexdump(packet+offset, rdlength);

        unsigned char *p = packet + offset;
        int len = p[0];
        printf("[+]          CPU   : ");
        for (int j = 0; j < len; j++) {
          printf("%c", p[j+1]);
        }
        printf("\n[+]          OS    : ");
        len = p[len+1];
        for (int j = 0; j < len; j++) {
          printf("%c", p[j+1+len]);
        }
        printf("\n");
        offset += rdlength;

      } else if (type == 16) {
        /* TXT Record */
        printf("(TXT record)\n");
        //hexdump(response+offset, rdlength);
        // TCP has 8bit length in front of the TXT data
        int len = 0;
        int consumed = 0;

        do {
          CONSUME_8BIT(len);
          //printf("[+]          TXT: len %d\n", len);
          printf("[+]          TXT: \"");
          for (int j = 0; j < len; j++) {
            printf("%c", packet[offset++]);
          }
          printf("\"\n");
          consumed += len + 1;
        } while (len > 0 && consumed < rdlength);
        //printf("\n");


      } else if (rdlength == 16 && type == 28) {
        /* AAAA Record */
        //printf("AAAA: Address ");
        unsigned char *p = packet + offset;

        int j;
        for (j = 0; j < rdlength; j+=2) {
            printf("%02x%02x", p[j], p[j+1]);
            if (j + 2 < rdlength) printf(":");
        }
        offset += rdlength;
        printf(" (AAAA record, IPv6 address)\n");

      } else if (type == 46) {
        // RRSIG
        printf("(RRSIG Resource Record Signature)\n");

        //hexdump(packet+offset, rdlength);
        // s is start of answer
        int s = offset;
        //printf("DEBUG: offset %d rdlength %d\n", offset, rdlength);

        // TYPE Covered is the type of the RRset that is covered by this RRSIG record
        int type_covered;
        // ALGORITHM is the cryptographic algorithm used to create the signature
        int algorithm;
        // LABELS is the number of labels in the original RRSIG RR owner name
        int labels;
        // ORIGINAL TTL is the TTL of the covered RRset as it appears in the authoritative zone
        int original_ttl;
        // SIGNATURE EXPIRATION is the time at which the signature expires
        int signature_expiration;
        // SIGNATURE INCEPTION is the time at which the signature was created
        int signature_inception;
        // KEY TAG is the key tag value of the DNSKEY RR that validates this signature
        int key_tag;
        // SIGNER'S NAME is the owner name of the DNSKEY RR that a validator is supposed to use to validate this signature
        //int signer_name_length;

        CONSUME_16BIT(type_covered);
        CONSUME_8BIT(algorithm);
        CONSUME_8BIT(labels);
        CONSUME_32BIT(original_ttl);
        CONSUME_32BIT(signature_expiration);
        CONSUME_32BIT(signature_inception);
        CONSUME_16BIT(key_tag);

        printf("[+]          TYPE Covered        : %d=%s\n", type_covered, get_type(type_covered));
        printf("[+]          ALGORITHM           : %d (13=ECDSA Curve P-256 with SHA-256)\n", algorithm);
        printf("[+]          LABELS              : %d (number of labels in the original RRSIG RR owner name)\n", labels);
        printf("[+]          ORIGINAL TTL        : %d\n", original_ttl);
        printf("[+]          SIGNATURE EXPIRATION: %d (timestamp)= ", signature_expiration);
        print_timestamp(signature_expiration);
        //printf("\n");
        printf("[+]          SIGNATURE INCEPTION : %d (timestamp)= ", signature_inception);
        print_timestamp(signature_inception);
        //printf("\n");
        printf("[+]          KEY TAG             : %d\n", key_tag);
        //printf("DEBUG: offset %d rdlength %d\n", offset, rdlength);

        printf("[+]          SIGNER'S NAME       : ");
        offset += print_domain(packet + offset);
        printf("\n");
        printf("[+]          SIGNATURE           : ");
        // SIGNATURE is the cryptographic signature that covers the RRSIG RDATA (excluding the Signature field) and the RRset specified by the RRSIG owner name, RRSIG class, and RRSIG Type Covered field

        int len = rdlength - (offset-s);
        unsigned char *p = packet + offset;
        char base64Text[4 * ((len + 2) / 3) + 1];  // Enough space for encoding
        base64_encode(p, len, base64Text);

        printf("%s\n", base64Text);
        offset += len;

      } else if (type == 48) {
        // DNSKEY
        printf("(DNSKEY record)\n");
        int s = offset;

        int flags;
        int protocol;
        int algorithm;
        CONSUME_16BIT(flags);
        CONSUME_8BIT(protocol);
        CONSUME_8BIT(algorithm);
        printf("[+]          FLAGS               : %d\n", flags);
        printf("[+]          PROTOCOL            : %d\n", protocol);
        printf("[+]          ALGORITHM           : %d\n", algorithm);
        printf("[+]          PUBLIC KEY          : ");

        // public key as base64
        int len = rdlength - (offset-s);
        unsigned char *p = packet + offset;
        char base64Text[4 * ((len + 2) / 3) + 1];  // Enough space for encoding
        base64_encode(p, len, base64Text);

        printf("%s\n", base64Text);
        offset += len;

      } else if (type == 257) {
        // CAA Certificate Authority Authorization
        printf("(CAA Certificate Authority Authorization)\n");
        //hexdump(packet+offset, rdlength);

        int flags;
        int tag_length;
        CONSUME_8BIT(flags);
        CONSUME_8BIT(tag_length);
        printf("[+]          FLAGS               : %d\n", flags);
        printf("[+]          TAG LENGTH          : %d\n", tag_length);
        printf("[+]          TAG                 : ");
        for (int j = 0; j < tag_length; j++) {
          printf("%c", packet[offset++]);
        }
        printf("\n");
        printf("[+]          VALUE               : ");
        for (int j = 0; j < rdlength - 2 - tag_length; j++) {
          printf("%c", packet[offset++]);
        }
        printf("\n");




      } else {
        printf("(raw)\n");
        printf("[+]          RDATA    : ");

        for (int j = 0; j < rdlength; j++) {
          printf("%02x", packet[offset++]);
        }
        printf("\n");
      }


    }
  }

  
}
