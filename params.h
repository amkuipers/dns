#ifndef PARAMS_H
#define PARAMS_H

#define MAX_DNS_TYPES 10
#define MAX_RESPONSE_SIZE 65536 

struct dns_params {
  char *hostname;
  char *dns_type;
  char *dns_server;
  char *tcp_udp;

  int dns_types[MAX_DNS_TYPES]; 
  int dns_types_len;
  int useTCP;
  int serverPort;
  char *arpa_name;
};

struct dns_params parse_args(int argc, char *argv[]);

#endif // PARAMS_H