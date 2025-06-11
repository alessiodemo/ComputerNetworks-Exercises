/*
OBIETTIVO DEL PROGRAMMA

    Leggere input da stdin (standard input, cioè tastiera) in modo asincrono tramite SIGIO, senza bloccare il programma in attesa.

    Attivare un timer che ogni secondo emette SIGALRM, per dimostrare la gestione simultanea di più segnali.

    Usare poll() per verificare se c'è input pronto da leggere, evitando letture bloccanti.
*/

#include <poll.h>        // For poll(), used to check input readiness
#include<stdio.h>        // Standard I/O functions
#include<signal.h>       // For signal handling (SIGIO, SIGALRM)
#include <fcntl.h>       // File control (e.g., O_ASYNC, F_SETOWN)
#include <sys/time.h>    // For setting timers
#include <unistd.h>      // For read(), pause(), etc.
#include <errno.h>       // For error codes like EAGAIN

// Buffer to store incoming data from stdin
unsigned char databuf[100];
int bufstart = 0;        // Tracks current index in databuf

// Signal handler for asynchronous I/O (SIGIO)
void myio(int signal) {
    struct pollfd p[1];      // Polling structure
    int t = 1;               // Variable to store read size
    
    printf("I/O handler called\n");

    p[0].fd = 0;             // File descriptor 0 = stdin
    p[0].events = POLLIN;   // We're interested in input events
    p[0].revents = 0;       // Will be set by poll() if an event occurs

    // Check if stdin has data available without blocking
    if (-1 == poll(p, 1, 0)) {
        perror("Poll failed\n");
        return;
    }

    // If input is available
    if (p[0].revents == POLLIN)
        // Keep reading until no more data or error
        for (bufstart; t; bufstart += t) {
            t = read(p[0].fd, databuf + bufstart, 99 - bufstart);
            if (t == -1) {
                if (errno != EAGAIN) perror("Read failed");  // Report errors other than EAGAIN
                t = 0;  // Exit loop
            }
        }
}

// Signal handler for the timer (SIGALRM)
void mytimer(int signal) {
    printf("Timer handler called\n");
}

// Signal action structures
struct sigaction sa_timer, sa_io;

int main() {
    sigset_t mask;          // Signal mask
    int s = 0;              // File descriptor for stdin
    int flags = 0;          // To store file status flags
    int t;
    struct itimerval itime; // Timer configuration structure

    // Set signal handlers
    sa_timer.sa_handler = mytimer;
    sa_io.sa_handler = myio;

    // Register SIGIO and SIGALRM handlers
    if (-1 == sigaction(SIGIO, &sa_io, NULL)) {
        perror("SIGIO sigaction failed");
        return 1;
    }
    if (-1 == sigaction(SIGALRM, &sa_timer, NULL)) {
        perror("SIGARM sigaction failed");
        return 1;
    }

    // Set current process as owner of stdin for async I/O
    if (-1 == fcntl(s, F_SETOWN, getpid())) {
        perror("fcntl F_SETOWN failed");
        return 1;
    }

    // Get current file status flags for stdin
    flags = fcntl(s, F_GETFL);
    if (flags == -1) {
        perror("fcntl F_GETFL failed");
        return -1;
    }

    // Set stdin to asynchronous and non-blocking mode
    if (-1 == fcntl(s, F_SETFL, flags | O_ASYNC | O_NONBLOCK)) {
        perror("fcntl F_SETFL failed");
        return -1;
    }

    // Configure timer: first signal and interval = 1 second
    itime.it_interval.tv_sec = 1;
    itime.it_interval.tv_usec = 0;
    itime.it_value.tv_sec = 1;
    itime.it_value.tv_usec = 0;
    if (-1 == setitimer(ITIMER_REAL, &itime, NULL)) {
        perror("setitimer failed");
        return -1;
    }

    // Unblock SIGIO and SIGALRM
    if (-1 == sigemptyset(&mask)) {
        perror("sigemptyset failed");
        return 1;
    }
    if (-1 == sigaddset(&mask, SIGIO)) {
        perror("sigaddset SIGIO failed");
        return 1;
    }
    if (-1 == sigaddset(&mask, SIGALRM)) {
        perror("sigaddset SIGALRM failed");
        return 1;
    }
    if (-1 == sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
        perror("setprocmask failed");
        return 1;
    }

    // Infinite loop: wait for signals
    while (1) {
        pause();  // Wait until a signal is delivered

        // If input has been received and stored in databuf
        if (bufstart) {
            databuf[bufstart] = 0;  // Null-terminate the buffer
            printf("Received data: %s\n", databuf);
            bufstart = 0;           // Reset for next input
        }
    }
}
