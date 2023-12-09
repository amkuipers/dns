#include "connect.h"

int connectUDP(const char* serverIP, int serverPort) {
    // Create a UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("[-] Failed to create socket");
        return -1;
    }

    // Set up the server address
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    if (inet_pton(AF_INET, serverIP, &(serverAddr.sin_addr)) <= 0) {
        perror("[-] Invalid DNS server IP address");
        close(sockfd);
        return -1;
    }

    // Connect to the DNS server
    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("[-] Failed to connect to DNS server");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int connectTCP(const char* serverIP, int serverPort) {
    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[-] Failed to create socket");
        exit(EXIT_FAILURE);
        //return -1;
    } else {
        printf("[+] Created socket %d\n", sockfd);
    }

    // Set up the server address
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    //serverAddr.sin_addr.s_addr = inet_addr(serverIP); // ?
    if (inet_pton(AF_INET, serverIP, &(serverAddr.sin_addr)) <= 0) {
        perror("[-] Invalid DNS server IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
        //return -1;
    }

    // Connect to the DNS server
    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("[-] Failed to connect to DNS server");
        close(sockfd);
        exit(EXIT_FAILURE);
        //return -1;
    } else {
        printf("[+] Connected to DNS TCP server\n");
    }

    return sockfd;
}


/*
int main(int argc, char *argv[]) {
    const char* serverIP = "192.168.0.1";
    int serverPort = 53;

    int dnsSocket = connectToDNS(serverIP, serverPort);
    if (dnsSocket < 0) {
        printf("Failed to connect to DNS server\n");
        return -1;
    }

    printf("Connected to DNS server\n");

    // Perform DNS operations...

    // Close the socket
    close(dnsSocket);

    return 0;
}
*/
