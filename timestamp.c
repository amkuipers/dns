#include "timestamp.h"

void print_timestamp(int timestamp) {
    time_t rawtime = timestamp;
    struct tm * timeinfo;

    timeinfo = localtime(&rawtime);

    char buffer[80];
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
    puts(buffer);
}

