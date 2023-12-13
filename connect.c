#include "connect.h"

// internal function
int dns_connect(const char* serverIP, int serverPort, int socktype) {
    // Create a socket
    int sockfd = socket(AF_INET, socktype, 0);
    if (sockfd < 0) {
        perror("[-] Failed to create socket");
        exit(EXIT_FAILURE);
    //} else {
    //    printf("[+] Created socket %d\n", sockfd);
    }

    // Set up the server address
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    if (inet_pton(AF_INET, serverIP, &(serverAddr.sin_addr)) <= 0) {
        perror("[-] Invalid DNS server IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Connect to the DNS server
    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("[-] Failed to connect to DNS server");
        close(sockfd);
        exit(EXIT_FAILURE);
    //} else {
    //    printf("[+] Connected\n");
    }

    return sockfd;
}

int connectUDP(const char* serverIP, int serverPort) {
    printf("[+] Creating IPv4 socket to udp %d on %s\n", serverPort, serverIP);
    return dns_connect(serverIP, serverPort, SOCK_DGRAM);
}

int connectTCP(const char* serverIP, int serverPort) {
    printf("[+] Creating IPv4 socket to tcp %d on %s\n", serverPort, serverIP);
    return dns_connect(serverIP, serverPort, SOCK_STREAM);
}
