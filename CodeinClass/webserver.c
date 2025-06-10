#include <stdlib.h>             // For general utilities
#include <unistd.h>             // For read(), write(), close()
#include <arpa/inet.h>          // For htons(), sockaddr_in, inet functions
#include <errno.h>              // For errno and perror()
#include <sys/types.h>          // For socket types
#include <sys/socket.h>         // For socket functions
#include <stdio.h>              // For standard I/O functions
#include <string.h>             // For string operations

int tmp;

int main()
{
    struct sockaddr_in addr, remote_addr; // Server and client address structures
    int i, j, k, s, t, s2, len;           // s: listening socket, s2: accepted socket, t: temp
    int c;                                // For character reading
    FILE *fin;                            // File pointer for requested file
    int yes = 1;                          // For setsockopt
    char *method, *path, *ver;            // Parsed HTTP method, path, version
    char request[5000], response[10000];  // Buffers for request and response

    // Create TCP socket
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) {
        perror("Socket Failed");
        return 1;
    }

    // Set up the address struct
    addr.sin_family = AF_INET;       // IPv4
    addr.sin_port = htons(8033);     // Port 8033
    addr.sin_addr.s_addr = 0;        // Bind to all interfaces (0.0.0.0)

    // Allow address reuse to avoid "Address already in use" errors
    t = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    if (t == -1) {
        perror("setsockopt Failed");
        return 1;
    }

    // Bind the socket to the specified address and port
    if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
        perror("bind Failed");
        return 1;
    }

    // Listen for incoming connections, up to 5 pending
    if (listen(s, 5) == -1) {
        perror("Listen Fallita");
        return 1;
    }

    len = sizeof(struct sockaddr_in);

    // Infinite server loop
    while (1) {
        // Accept an incoming connection
        s2 = accept(s, (struct sockaddr *)&remote_addr, &len);
        if (s2 == -1) {
            perror("Accept Failed");
            return 1;
        }

        // Read HTTP request from the client
        t = read(s2, request, 4999);
        if (t == -1) {
            perror("Read Failed");
            return 1;
        }

        request[t] = 0; // Null-terminate the request string
        printf("%s", request); // Print raw request

        // Simple HTTP request parsing
        method = request;
        for (i = 0; request[i] != ' '; i++) {} // Find end of method
        request[i] = 0;
        path = request + i + 1;

        for (i++; request[i] != ' '; i++); // Find end of path
        request[i] = 0;
        ver = request + i + 1;

        for (i++; request[i] != '\r'; i++); // End of HTTP version
        request[i] = 0;

        printf("method=%s path=%s ver=%s\n", method, path, ver); // Log parsed request

        // Open the requested file (remove leading slash from path)
        if ((fin = fopen(path + 1, "rt")) == NULL) {
            // File not found — send 404 response
            sprintf(response, "HTTP/1.1 404 Not Found\r\n\r\n");
            write(s2, response, strlen(response));
        } else {
            // File found — send 200 OK header
            sprintf(response, "HTTP/1.1 200 OK\r\n\r\n");
            write(s2, response, strlen(response));

            // Send file contents character by character
            while ((c = fgetc(fin)) != EOF)
                write(s2, &c, 1);

            fclose(fin); // Close file after reading
        }

        close(s2); // Close connection with client
    }
}

/*Summary of What This Code Does:

    It sets up a very simple HTTP server on port 8033.

    It accepts connections and reads incoming HTTP GET requests.

    It extracts the method, path, and version from the request line.

    If the file corresponding to the path exists (in the same directory), it returns the content with a 200 OK.

    Otherwise, it returns a 404 Not Found.

    It handles one client at a time, sequentially.*/