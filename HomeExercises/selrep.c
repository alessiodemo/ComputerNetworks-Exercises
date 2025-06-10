#include <signal.h>    // For signal handling
#include <sys/time.h>  // For setting timers
#include <unistd.h>    // For read, sleep, etc.
#include <fcntl.h>     // For file control options (fcntl)
#include <stdio.h>     // For printf, perror, etc.
#include <poll.h>      // For poll() function (non-blocking I/O)
#include <errno.h>     // For error number macros

#define N 5  // Window size for packets

// Structure to represent each packet in the sliding window
struct packet {
    int is_acked;   // Flag to indicate if the packet has been acknowledged
    int timeout;    // Timeout value for retransmission
} win[2*N];         // Window buffer size is twice N to handle wrap-around

int winstart;       // Index of the start of the current window (lowest unacked packet)

// Signal set used for blocking/unblocking signals
sigset_t mask;
int seconds;  // Global counter to keep track of seconds elapsed (timer ticks)

/*
 * Timer handler function called on SIGALRM.
 * It increments the timer and checks packets in the current window.
 * If any packet is unacknowledged and its timeout expired, it "resends" it by resetting the timeout.
 */
void mytimer(int num)
{
    int i;
    seconds++;  // Increase global timer tick count
    printf("Timer Call: %d\n", seconds);

    // Iterate through packets in the current window
    for (i = winstart; i < winstart + N; i++) {
        // Check if packet is not acknowledged and its timeout expired
        if ((!win[i % (2 * N)].is_acked) && (win[i % (2 * N)].timeout <= seconds)) {
            printf("Timer Handler: Send Packet %d\n", i);
            // Reset timeout for retransmission (current time + 4 seconds)
            win[i % (2 * N)].timeout = seconds + 4;
        }
    }
}

/*
 * I/O handler function called on SIGIO.
 * It polls stdin for incoming acknowledgments asynchronously.
 * Reads the acknowledgment number and updates the window accordingly.
 */
void myio(int num) {
    int t, i;
    int ack_no;
    char buffer[101];
    struct pollfd fd[1];

    fd[0].fd = 0;            // stdin file descriptor
    fd[0].events = POLLIN;   // Interested in input events
    fd[0].revents = 0;

    printf("I/O called\n");

    // Poll stdin with zero timeout to check if input is ready
    if (-1 == poll(fd, 1, 0)) {
        perror("poll error");
        return;
    }

    // If stdin is ready to read
    if (fd[0].revents & POLLIN) {
        // Read as much data as available, up to 100 bytes
        for (i = 0; (t = read(fd[0].fd, buffer + i, 100 - i)) > 0; i += t) {}

        // If read failed with an error other than EAGAIN (would block)
        if (t == -1 && (errno != EAGAIN))
            perror("read");

        buffer[i] = 0;  // Null-terminate the string

        // Parse the acknowledgment number from the input buffer
        sscanf(buffer, "%d", &ack_no);
        printf("Acked: %d\n", ack_no);

        // Check if ack_no is within the current window range
        if (ack_no >= winstart && ack_no < winstart + N) {
            // Mark the acknowledged packet as received
            win[ack_no % (2 * N)].is_acked = 1;

            // Slide the window forward as far as possible
            for (i = winstart; i < winstart + N && win[i % (2 * N)].is_acked; i++) {
                // Reset state for the new packet entering the window
                win[(i + N) % (2 * N)].is_acked = 0;
                win[(i + N) % (2 * N)].timeout = seconds + 4;
                printf("I/O Handler: sending packet %d\n", i + N);
            }
            // Update the start of the window
            winstart = i;
        }
    }
}

struct sigaction sa_io, sa_timer;  // Structures to specify signal handling behavior

int main() {
    struct itimerval ti;  // Timer structure for setting periodic timer
    int s = 0;            // File descriptor (stdin)
    int flags;

    // Set current process as the owner of the file descriptor for SIGIO signals
    flags = fcntl(s, F_SETOWN, getpid());
    
    // Get current file status flags
    flags = fcntl(s, F_GETFL);
    if (flags == -1) {
        perror("fcntl-F_GETFL");
        return 1;
    }

    // Set file descriptor flags to asynchronous and non-blocking I/O
    flags = fcntl(s, F_SETFL, flags | O_ASYNC | O_NONBLOCK);
    if (flags == -1) {
        perror("fcntl-F_SETFL");
        return 1;
    }

    // Set signal handler for SIGIO to myio (I/O event handler)
    sa_io.sa_handler = myio;

    // Set signal handler for SIGALRM to mytimer (timer handler)
    sa_timer.sa_handler = mytimer;

    // Configure the timer to expire every 1 second (interval and initial)
    ti.it_interval.tv_sec = 1;
    ti.it_interval.tv_usec = 0;
    ti.it_value.tv_sec = 1;
    ti.it_value.tv_usec = 0;
    
    // Start the real-time interval timer (raises SIGALRM periodically)
    setitimer(ITIMER_REAL, &ti, NULL);

    // Register signal handlers
    if (-1 == sigaction(SIGIO, &sa_io, NULL)) {
        perror("Sigaction SIGIO error");
        return 1;
    }
    if (-1 == sigaction(SIGALRM, &sa_timer, NULL)) {
        perror("Sigaction SIGALRM error");
        return 1;
    }

    // Initialize empty signal set
    if (-1 == sigemptyset(&mask)) {
        perror("Sigemptyset error");
        return 1;
    }

    // Add SIGIO to the signal set
    if (-1 == sigaddset(&mask, SIGIO)) {
        perror("Sigaddset SIGIO error");
        return 1;
    }

    // Add SIGALRM to the signal set
    if (-1 == sigaddset(&mask, SIGALRM)) {
        perror("Sigaddset SIGALRM error");
        return 1;
    }

    // Unblock SIGIO and SIGALRM signals to allow delivery
    if (-1 == sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
        perror("Sigprocmask err");
        return 1;
    }

    // Main loop: program waits indefinitely, signals will interrupt sleep to handle events
    while (1) {
        sleep(1000);  // Sleep long time; signals will interrupt sleep to run handlers
    }
}