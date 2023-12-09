#ifndef CONNECT_H
#define CONNECT_H

// Include necessary libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Function declaration
int connectUDP(const char* serverIP, int serverPort);
int connectTCP(const char* serverIP, int serverPort);

#endif // CONNECT_H