#include <unistd.h>            // For read(), write(), close()
#include <arpa/inet.h>         // For inet_pton(), htons(), sockaddr_in
#include <errno.h>             // For errno and perror()
#include <sys/types.h>         // For socket-related types
#include <sys/socket.h>        // For socket(), connect()
#include <stdio.h>             // For printf(), perror()
#include <string.h>            // For strlen(), memset()

int tmp; // Variable to temporarily store errno

int main()
{
    struct sockaddr_in addr; // Structure to hold server address
    int i, s, t;             // i: unused, s: socket descriptor, t: bytes read
    char request[5000], response[1000000]; // Buffers for HTTP request and response

    // IP address of the target server: 142.250.178.4 (Google)
    unsigned char targetip[4] = { 142, 250, 178, 4 };

    // Create a TCP socket
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) {
        tmp = errno;                        // Save errno in tmp
        perror("Socket failed");           // Print socket error
        printf("i=%d errno=%d\n", i, tmp); // Debug info
        return 1;
    }

    // Fill in address structure
    addr.sin_family = AF_INET;             // IPv4
    addr.sin_port = htons(80);             // Port 80 (HTTP), converted to network byte order
    addr.sin_addr.s_addr = *(unsigned int*)targetip; // Copy IP address as raw bytes

    // Connect to the remote server
    if (-1 == connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
        perror("Connect failed"); // Print connection error
    }

    printf("%d\n", s); // Print socket descriptor

    // Create a minimal HTTP GET request
    sprintf(request, "GET / \r\n");

    // Send the request to the server
    if (-1 == write(s, request, strlen(request))) {
        perror("write failed");
        return 1;
    }

    // Read the response in chunks and print the size
    while ((t = read(s, response, 999999)) > 0) {
        response[t] = 0;         // Null-terminate the buffer
        printf("\nt = %d\n", t); // Print number of bytes read
        // Uncomment the next line to print the actual response:
        // for(i=0; i<t; i++) printf("%c", response[i]);
    }

    // Check for read error
    if (t == -1) {
        perror("Read failed");
        return 1;
    }
}
