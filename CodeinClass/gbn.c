#include <poll.h>        // For polling file descriptors (e.g., stdin)
#include<stdio.h>        // Standard I/O functions
#include<signal.h>       // Signal handling
#include <fcntl.h>       // File control options
#include <sys/time.h>    // For setting timers
#include <unistd.h>      // POSIX API (e.g., pause, read)
#include <errno.h>       // Error codes

#define TIMEOUT 3        // Timeout duration in seconds
#define N 4              // Size of the sliding window buffer

// Structure to represent a packet
struct bufelem {
    int id;   // Packet ID
    int seq;  // Sequence number
} pktbuf[N];  // Circular buffer of packets

int mytime;          // Counter for the timer
int winstart;        // Index of the start of the sliding window
int winsize;         // Current window size (number of unacknowledged packets)
int seq=0;           // Current sequence number

// Function to send a packet
int pktsend(int id){
    // Wait if the window is full
    while(winsize == N) pause();

    struct bufelem * pkt;
    // Get pointer to next available slot in circular buffer
    pkt = pktbuf + ((winstart + winsize) % N);
    
    pkt->id = id;         // Set packet ID
    pkt->seq = seq;       // Set sequence number

    printf(" Sending pkt id = %d seq=%d\n", pkt->id, pkt->seq);

    seq = (seq + 1) % (N + 1);  // Increment sequence number modulo (N+1)
    winsize++;                 // Increase window size
    return 1;
}

unsigned char databuf[100];  // Unused buffer (possibly for future use)
int bufstart=0;              // Start index for databuf (unused)

// Handler for I/O signals (SIGIO)
void myio(int signal) {
    struct pollfd p[1];     // Poll structure for monitoring stdin
    int t=1;
    int i;
    int recv_ack;           // Variable to store received ACK

    printf("I/O handler called\n");

    p[0].fd = 0;            // Monitor standard input (fd 0)
    p[0].events = POLLIN;  // Interested in read events
    p[0].revents = 0;

    if (-1 == poll(p, 1, 0)) { perror("Poll failed\n"); return; }

    // Check if there's input to read
    if (p[0].revents == POLLIN)
        if (scanf("%d", &recv_ack))  // Read the ACK sequence number
            for (i = 0; i < winsize; i++) {
                // Search for the ACK in the window
                if (pktbuf[(winstart + i) % N].seq == recv_ack) {
                    printf("Dequeueing %d packets\n", i + 1);
                    // Slide the window forward past the acknowledged packets
                    winstart = (winstart + i + 1) % N;
                    winsize -= (i + 1);
                    mytime = 0;  // Reset the timer
                    break;
                }
            }
}

int mytime = 0;  // Timer counter

// Handler for timer signals (SIGALRM)
void mytimer(int signal){
    int i;
    printf("Timer handler called\n");

    // If timeout not reached, increment time and return
    if(mytime++ < TIMEOUT) return;

    mytime = 0;  // Reset timer

    // Resend all unacknowledged packets in the window
    for (i = 0; i < winsize; i++) {
        printf(" Resending pkt id = %d seq = %d\n",
            pktbuf[(winstart + i) % N].id,
            pktbuf[(winstart + i) % N].seq);
    }
}

// Signal action structures
struct sigaction sa_timer, sa_io;

int main() {
    sigset_t mask;
    int s = 0;       // File descriptor for stdin
    int flags = 0;
    int t;
    struct itimerval itime;

    sa_timer.sa_handler = mytimer;  // Set timer handler
    sa_io.sa_handler = myio;        // Set I/O handler

    // Set signal actions
    if (-1 == sigaction(SIGIO, &sa_io, NULL)) { perror("SIGIO sigaction failed"); return 1; }
    if (-1 == sigaction(SIGALRM, &sa_timer, NULL)) { perror("SIGARM sigaction failed"); return 1; }

    // Set the current process as the owner of stdin (for async I/O)
    if (-1 == fcntl(s, F_SETOWN, getpid())) { perror("fcntl F_SETOWN failed"); return 1; }

    // Get current file status flags for stdin
    flags = fcntl(s, F_GETFL);
    if (flags == -1) { perror("fcntl F_GETFL failed"); return -1; }

    // Set stdin to asynchronous and non-blocking mode
    if (-1 == fcntl(s, F_SETFL, flags | O_ASYNC | O_NONBLOCK)) { perror("fcntl F_SETFL failed"); return -1; }

    // Set timer to trigger every 1 second
    itime.it_interval.tv_sec = 1;
    itime.it_interval.tv_usec = 0;
    itime.it_value.tv_sec = 1;
    itime.it_value.tv_usec = 0;
    if (-1 == setitimer(ITIMER_REAL, &itime, NULL)) { perror("setitimer failed"); return -1; }

    // Initialize and unblock signals
    if (-1 == sigemptyset(&mask)) { perror("sigemptyset failed"); return 1; }
    if (-1 == sigaddset(&mask, SIGIO)) { perror("sigaddset SIGIO failed"); return 1; }
    if (-1 == sigaddset(&mask, SIGALRM)) { perror("sigaddset SIGALRM failed"); return 1; }
    if (-1 == sigprocmask(SIG_UNBLOCK, &mask, NULL)) { perror("setprocmask failed"); return 1; }

    int id = 0;

    // Main loop: continuously send packets
    while (1) {
        while (pktsend(id)) id++;  // Send packets with increasing ID
    }
}
