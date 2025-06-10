#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <time.h>

#define CACHE_SZ 100            // Size of ARP cache
#define MAXFRAME 10000         // Max Ethernet frame buffer size
#define TIMER_USECS 100000     // Timer interval in microseconds

// Broadcast MAC address (all ones)
unsigned char broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
// My MAC address (hardcoded for this example)
unsigned char mymac[6] = {0xf2, 0x3c, 0x94, 0x90, 0x4f, 0x4b};
// My IP address (hardcoded)
unsigned char myip[4] = {212, 71, 252, 26};
// Network mask
unsigned char netmask[4] = {255, 255, 255, 0};
// Gateway IP
unsigned char gateway[4] = {212, 71, 252, 1};

// Ethernet frame header structure
struct ethernet_frame {
    unsigned char dst[6];       // Destination MAC address
    unsigned char src[6];       // Source MAC address
    unsigned short type;        // Ethernet type (e.g., 0x0806 for ARP)
    unsigned char payload[1];  // Start of payload data
};

// ARP packet structure (fields aligned as per ARP protocol)
struct arp_packet {
    unsigned short haddr;       // Hardware type (e.g., Ethernet = 1)
    unsigned short paddr;       // Protocol type (e.g., IPv4 = 0x0800)
    unsigned char hlen;         // Hardware address length (6 for MAC)
    unsigned char plen;         // Protocol address length (4 for IPv4)
    unsigned short op;          // Operation code (1=request, 2=reply)
    unsigned char srcmac[6];    // Sender MAC address
    unsigned char srcip[4];     // Sender IP address
    unsigned char dstmac[6];    // Target MAC address (zeros for request)
    unsigned int dstip;         // Target IP address (network order)
};

// Function to build Ethernet header given destination MAC and type
void forge_eth(struct ethernet_frame *eth, unsigned char *dst, unsigned short type);

// Globals
int pkts = 0;                   // Packet counter
struct sigaction action_io, action_timer;  // Signal handlers
sigset_t mymask;                // Signal mask for blocking/unblocking signals
unsigned char l2buffer[MAXFRAME]; // Buffer for Ethernet frames
struct pollfd fds[1];           // Poll structure for async IO
int fdfl;                      // File descriptor flags
long long int tick = 0;         // Global tick counter for timer
int unique_s;                   // Raw socket file descriptor
int fl;                        // Flag to detect overlapping signals
struct sockaddr_ll sll;         // Link-layer socket address structure

// ARP cache entry structure
struct arp_cache {
    unsigned int ip;            // IP address (host order or network order? careful!)
    unsigned char mac[6];       // Corresponding MAC address
    unsigned int t_created;     // Tick when cache entry was created
    unsigned char occupied;     // Flag to mark if this entry is valid
} cache[CACHE_SZ];

// Utility function to print a buffer as hex + decimal for debugging
int printbuf(void *b, int size) {
    int i;
    unsigned char *c = (unsigned char *)b;
    for (i = 0; i < size; i++)
        printf("%.2x(%.3d) ", c[i], c[i]);
    printf("\n");
}

// Function to resolve IP address to MAC using ARP
int arp_resolve(unsigned int ipaddr, unsigned char *mac) {
    int len, t;
    unsigned char buffer[1000];
    struct ethernet_frame *eth;
    struct arp_packet *arp;

    // First check if IP is in ARP cache
    for (int i = 0; i < CACHE_SZ; i++) {
        if (cache[i].occupied)
            if (cache[i].ip == ipaddr) {  // Cache hit
                for (int k = 0; k < 6; k++)
                    mac[k] = cache[i].mac[k];  // Copy cached MAC
                return 0; // Success
            }
    }

    // Prepare ARP request packet
    eth = (struct ethernet_frame *)buffer;
    arp = (struct arp_packet *)eth->payload;

    // Fill Ethernet header: destination broadcast, protocol type ARP
    forge_eth(eth, broadcast, 0x0806);

    // Fill ARP header fields (Ethernet + IPv4)
    arp->haddr = htons(1);           // Ethernet hardware type
    arp->paddr = htons(0x0800);      // IPv4 protocol type
    arp->hlen = 6;                   // MAC address length
    arp->plen = 4;                   // IPv4 address length
    arp->op = htons(1);              // ARP request

    // Fill source MAC and IP (our address)
    for (int i = 0; i < 6; i++)
        arp->srcmac[i] = mymac[i];
    for (int i = 0; i < 4; i++)
        arp->srcip[i] = myip[i];

    // Clear target MAC (unknown)
    for (int i = 0; i < 6; i++)
        arp->dstmac[i] = 0;

    // Target IP to resolve
    arp->dstip = ipaddr;

    printf("ARP Request");

    // Initialize sockaddr_ll for sendto call
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");  // Interface index, change if needed

    len = sizeof(struct sockaddr_ll);

    // Send ARP request packet on raw socket
    t = sendto(unique_s, buffer, 64, 0, (struct sockaddr *)&sll, len);
    if (t == -1) {
        perror("sendto Failed");
        return 1;
    }
    //printf("ARP Request %d bytes sent\n",t);

    // Save current tick to measure timeout
    unsigned int time = tick;

    // Wait for ARP reply or timeout (3 ticks)
    while (pause()) { // pause() waits for signal (like SIGIO on recv)

        // Check cache again for ARP reply
        for (int i = 0; i < CACHE_SZ; i++) {
            if (cache[i].occupied)
                if (cache[i].ip == ipaddr) {
                    for (int k = 0; k < 6; k++)
                        mac[k] = cache[i].mac[k];
                    return 0;
                }
        }

        // Timeout after 3 timer ticks (~3 seconds)
        if (tick - time >= 3)
            return -1;
    }
}

// Function to fill Ethernet header fields
void forge_eth(struct ethernet_frame *eth, unsigned char *dst, unsigned short type) {
    for (int i = 0; i < 6; i++)
        eth->dst[i] = dst[i];
    for (int i = 0; i < 6; i++)
        eth->src[i] = mymac[i];
    eth->type = htons(type);
}

// Timer signal handler increments tick counter and cleans cache entries
void mytimer(int number) {
    int i;
    // Block signals to avoid race conditions
    if (-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return;
    }
    fl++;   // Increase flag counter to detect overlap
    tick++; // Increase global tick counter

    // Print packet count every second
    if (tick % (1000000 / TIMER_USECS) == 0) {
        printf("Mytimer Called: pkts =%d\n", pkts);
        pkts = 0;
    }
    if (fl > 1)
        printf("Overlap Timer\n");
    fl--;

    // Clean ARP cache entries older than 300 ticks (~300 seconds)
    for (i = 0; i < CACHE_SZ; i++) {
        if (cache[i].occupied) {
            if (tick - cache[i].t_created >= 300)
                cache[i].occupied = 0; // Invalidate old entry
        }
    }

    // Unblock signals
    if (-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return;
    }
}

// I/O signal handler triggered on incoming packets (SIGIO)
void myio(int number) {
    int len, size;
    struct ethernet_frame *eth = (struct ethernet_frame *)l2buffer;
    struct arp_packet *arp = (struct arp_packet *)eth->payload;

    if (-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return;
    }
    fl++;
    if (fl > 1)
        printf("Overlap (%d) in myio\n", fl);

    // Poll to check if data is available to read
    if (poll(fds, 1, 0) == -1) {
        perror("Poll failed");
        return;
    }

    if (fds[0].revents & POLLIN) {
        len = sizeof(struct sockaddr_ll);

        // Read all available packets
        while (0 <= (size = recvfrom(unique_s, l2buffer, MAXFRAME, 0, (struct sockaddr *)&sll, &len))) {
            pkts++; // Increment packet count

            // Check if this is an ARP packet
            if (eth->type == htons(0x0806))
                // And if it is an ARP reply
                if (arp->op == htons(2)) {
                    // Add/update entry in ARP cache
                    for (int i = 0; i < CACHE_SZ; i++) {
                        if (!cache[i].occupied) {
                            cache[i].occupied = 1;
                            cache[i].t_created = tick; // Timestamp
                            // Copy IP address from ARP sender
                            for (int j = 0; j < 4; j++)
                                ((unsigned char *)(&cache[i].ip))[j] = arp->srcip[j];
                            // Copy MAC address from ARP sender
                            for (int j = 0; j < 6; j++)
                                cache[i].mac[j] = arp->srcmac[j];
                            break;
                        }
                    }
                }
            //printf("No ARP response received\n");
        }
        if (errno != EAGAIN) {
            perror("Packet recvfrom Error\n");
        }
    }
    // Reset poll events for next call
    fds[0].events = POLLIN | POLLOUT;
    fds[0].revents = 0;

    if (fl > 1)
        printf("Overlap (%d) in myio\n", fl);

    fl--;
    if (-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return;
    }
}

int main(int argc, char **argv) {
    unsigned char target_ip[4] = {212, 71, 252, 1}; // Target IP to resolve
    unsigned char target_mac[6];                     // Buffer for resolved MAC

    fl = 0; // Initialize flag

    struct itimerval myt;  // Timer struct

    if (argc != 3) {
        printf("usage: %s <first byte> <last byte>\n", argv[0]);
        return 1;
    }

    // Setup signal handlers for IO and timer signals
    action_io.sa_handler = myio;
    action_timer.sa_handler = mytimer;
    sigaction(SIGIO, &action_io, NULL);
    sigaction(SIGALRM, &action_timer, NULL);

    // Create raw socket to listen/send Ethernet frames (all protocols)
    unique_s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (unique_s == -1) {
        perror("Socket Failed");
        return 1;
    }

    // Set ownership of socket signals to current process (for SIGIO)
    if (-1 == fcntl(unique_s, F_SETOWN, getpid())) {
        perror("fcntl setown");
        return 1;
    }

    // Get current flags of socket fd
    fdfl = fcntl(unique_s, F_GETFL, NULL);
    if (fdfl == -1) {
        perror("fcntl f_getfl");
        return 1;
    }

    // Enable asynchronous IO and nonblocking mode
    fdfl = fcntl(unique_s, F_SETFL, fdfl | O_ASYNC | O_NONBLOCK);
    if (fdfl == -1) {
        perror("fcntl f_setfl");
        return 1;
    }

    // Setup poll structure for raw socket
    fds[0].fd = unique_s;
    fds[0].events = POLLIN | POLLOUT;
    fds[0].revents = 0;

    // Setup sockaddr_ll for sendto usage
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0"); // Change interface name if needed

    // Setup timer interval and initial expiration (1 second)
    myt.it_interval.tv_sec = 1;
    myt.it_interval.tv_usec = 0;
    myt.it_value.tv_sec = 1;
    myt.it_value.tv_usec = 0;

    // Initialize empty signal mask and add signals to block/unblock
    if (-1 == sigemptyset(&mymask)) {
        perror("Sigemptyset");
        return 1;
    }
    if (-1 == sigaddset(&mymask, SIGALRM)) {
        perror("Sigaddset");
        return 1;
    }
    if (-1 == sigaddset(&mymask, SIGIO)) {
        perror("Sigaddset");
        return 1;
    }

    // Unblock signals for timer and IO
    if (-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return -1;
    }

    // Start the timer for repeated SIGALRM signals
    if (-1 == setitimer(ITIMER_REAL, &myt, NULL)) {
        perror("Setitimer");
        return 1;
    }

    // Loop over IP range from argv[1] to argv[2] in last byte of IP
    for (unsigned int i = 0; i < 2; i++)
        for (target_ip[3] = atoi(argv[1]); target_ip[3] < atoi(argv[2]); target_ip[3]++) {
            printf("resolving: 212.71.252.26.%d: ", target_ip[3]);
            if (!arp_resolve(*(unsigned int *)target_ip, target_mac))
                printbuf(target_mac, 6);
            else
                printf("unresolved ip\n");
        }
}
