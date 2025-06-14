#include <stdio.h>
#include <net/if.h>               // For interface name to index conversion
#include <arpa/inet.h>            // For htons, htonl, etc.
#include <sys/socket.h>           // For socket functions
#include <linux/if_packet.h>      // For low-level packet structures
#include <net/ethernet.h>         // For Ethernet protocol constants
#include <errno.h>                // For errno handling
#include <string.h>              
#include <stdlib.h>  // per rand() e srand()
#include <time.h>    // per time()

// Structure representing an ARP packet
struct arp_packet {
    unsigned short htype;         // Hardware type (Ethernet = 1)
    unsigned short ptype;         // Protocol type (IPv4 = 0x0800)
    unsigned char hlen;           // Hardware address length (MAC = 6)
    unsigned char plen;           // Protocol address length (IP = 4)
    unsigned short op;            // Operation (1=request, 2=reply)
    unsigned char srcmac[6];      // Sender MAC address
    unsigned char srcip[4];       // Sender IP address
    unsigned char dstmac[6];      // Target MAC address
    unsigned char dstip[4];       // Target IP address
};

// Ethernet frame structure
struct eth_frame {
    unsigned char dst[6];         // Destination MAC
    unsigned char src[6];         // Source MAC
    unsigned short type;          // EtherType (0x0800 = IP, 0x0806 = ARP)
    unsigned char payload[1];     // Payload (ARP, IP, etc.)
};

// IP packet structure
struct ip_datagram {
    unsigned char ver_ihl;        // Version (4 bits) + IHL (4 bits)
    unsigned char tos;            // Type of Service
    unsigned short totlen;        // Total length (IP header + payload)
    unsigned short id;            // Identification
    unsigned short flags_offs;    // Flags and fragment offset
    unsigned char ttl;            // Time to Live
    unsigned char proto;          // Protocol (ICMP = 1)
    unsigned short checksum;      // Header checksum
    unsigned int src;             // Source IP
    unsigned int dst;             // Destination IP
    unsigned char payload[1];     // Payload (ICMP, etc.)
};

//[MODIFIED] tcp segment instead of icmp packet
struct tcp_segment {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char data_offset_reserved_ns; // data offset (4 bits) + reserved (3 bits) + NS flag (1 bit)
    unsigned char flags;                   // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
    // No options, no payload and payload empty
};

// Node config (same)
unsigned char myip[4] = {212, 71, 252, 26};
unsigned char mymac[6] = {0xF2, 0x3C, 0x94, 0x90, 0x4F, 0x4b};
unsigned char gateway[4] = {212, 71, 252, 1};
unsigned char mask[4] = {255, 255, 255, 0};
unsigned char target_ip[4] = {147, 162, 2, 100};
int s;

// Compute checksum for IP and TCP checksum calculation
unsigned short int checksum(unsigned char *b, int len) {
    unsigned short *p = (unsigned short *)b;
    unsigned int tot = 0;
    int i;

    for (i = 0; i < len / 2; i++) {
        tot += ntohs(p[i]);
        if (tot & 0x10000) tot = (tot + 1) & 0xFFFF;
    }

    if (len & 0x1) {
        tot += ntohs(p[i]) & 0xFF00;
        if (tot & 0x10000) tot = (tot + 1) & 0xFFFF;
    }

    return (0xFFFF - ((unsigned short)tot));
}

// Print raw bytes in buffer for debugging
void print_buffer(unsigned char* buffer, int size) {
    for (int i = 0; i < size; i++) {
        printf("%.3d (%.2X) ", buffer[i], buffer[i]);
        if (i % 4 == 3) printf("\n");
    }
    printf("\n");
}

// Resolve target IP to MAC using ARP request
int resolve_ip(unsigned char *target, unsigned char *mac) {
    int len;
    unsigned char buffer[1500];
    struct sockaddr_ll sll;
    struct arp_packet *arp;
    struct eth_frame *eth;
    int i, j, n;

    eth = (struct eth_frame *) buffer;
    arp = (struct arp_packet *) eth->payload;

    // Fill Ethernet header
    for (i = 0; i < 6; i++) {
        eth->src[i] = mymac[i];
        eth->dst[i] = 0xFF; // Broadcast
    }
    eth->type = htons(0x0806); // ARP

    // Fill ARP packet
    arp->htype = htons(1); // Ethernet
    arp->ptype = htons(0x0800); // IP
    arp->hlen = 6;
    arp->plen = 4;
    arp->op = htons(1); // ARP request

    for (i = 0; i < 6; i++) {
        arp->srcmac[i] = mymac[i];
        arp->dstmac[i] = 0;
    }
    for (i = 0; i < 4; i++) {
        arp->srcip[i] = myip[i];
        arp->dstip[i] = target[i];
    }

    // Clear sockaddr_ll
    for (i = 0; i < sizeof(struct sockaddr_ll); i++) ((char *) &sll)[i] = 0;

    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    len = sizeof(struct sockaddr_ll);

    // Send ARP request
    if (-1 == sendto(s, buffer, 1500, 0, (struct sockaddr *) &sll, len)) {
        perror("Send Failed");
        return 1;
    }

    // Wait for ARP reply
    j = 100;
    while (j--) {
        n = recvfrom(s, buffer, 1500, 0, (struct sockaddr *) &sll, &len);
        if (n == -1) {
            printf("Errno = %d\n", errno);
            perror("Recvfrom Failed");
            return 1;
        }

        if (eth->type == htons(0x0806) && arp->op == htons(2)) {
            printf("ARP REPLY RECEIVED:\n");
            print_buffer(buffer, n);

            for (i = 0; i < 6; i++)
                mac[i] = arp->srcmac[i];
            return 0;
        }
    }

    return 1;
}

// Forge IP header for TCP
void forge_ip(struct ip_datagram *ip, unsigned short tcp_len, unsigned char *dst) {
    ip->ver_ihl = 0x45;                      // IPv4 and header length 20 bytes
    ip->tos = 0;
    ip->totlen = htons(tcp_len + 20);       // IP header + TCP length
    ip->id = htons(0x1234);
    ip->flags_offs = htons(0);
    ip->ttl = 128;
    ip->proto = 6;                          // TCP protocol
    ip->checksum = 0;
    ip->src = *((unsigned int *)myip);
    ip->dst = *((unsigned int *)dst);
    ip->checksum = htons(checksum((unsigned char *)ip, 20));
}

// Calculate TCP checksum with pseudo-header
unsigned short tcp_checksum(struct ip_datagram *ip, struct tcp_segment *tcp, int tcp_len) {
    unsigned char buf[4096];
    unsigned char *ptr = buf;

    // Pseudo header
    memcpy(ptr, &ip->src, 4); ptr += 4;
    memcpy(ptr, &ip->dst, 4); ptr += 4;
    *ptr++ = 0;
    *ptr++ = ip->proto;
    *((unsigned short *)ptr) = htons(tcp_len);
    ptr += 2;

    // TCP segment
    memcpy(ptr, tcp, tcp_len);
    ptr += tcp_len;

    // If tcp_len is odd, pad with zero
    int total_len = (ptr - buf);
    if (tcp_len % 2 != 0) {
        *ptr++ = 0;
        total_len++;
    }

    return htons(checksum(buf, total_len));
}

// Random source port [1024-65535]
unsigned short random_port() {
    return (unsigned short)(1024 + rand() % (65535 - 1024));
}

// Random 32-bit sequence number
unsigned int random_seq() {
    return (unsigned int)rand();
}


int main() {
    unsigned char buffer[1500];
    struct eth_frame *eth = (struct eth_frame *)buffer;
    struct ip_datagram *ip = (struct ip_datagram *)eth->payload;
    struct tcp_segment *tcp = (struct tcp_segment *)ip->payload;

    struct sockaddr_ll sll;
    int len, n, i, j;
    unsigned char target_mac[6];

    srand(time(NULL));

    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s == -1) {
        perror("Socket Failed");
        return 1;
    }

    // Resolve MAC address for target (direct or via gateway)
    if ((*(unsigned int *)myip & *(unsigned int *)mask) ==
        (*(unsigned int *)target_ip & *(unsigned int *)mask)) {
        if (resolve_ip(target_ip, target_mac)) {
            fprintf(stderr, "Failed to resolve target IP\n");
            return 1;
        }
    } else {
        if (resolve_ip(gateway, target_mac)) {
            fprintf(stderr, "Failed to resolve gateway IP\n");
            return 1;
        }
    }

    // Prepare Ethernet header
    for (i = 0; i < 6; i++) {
        eth->dst[i] = target_mac[i];
        eth->src[i] = mymac[i];
    }
    eth->type = htons(0x0800); // IP

    // Prepare TCP segment
    unsigned short src_port = random_port();
    unsigned int seq_num = random_seq();

    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(80);          // HTTP port
    tcp->seq_num = htonl(seq_num);
    tcp->ack_num = 0;                   // irrelevant
    tcp->data_offset_reserved_ns = (5 << 4); // data offset=5 (20 bytes), rest 0
    tcp->flags = 0x02;                  // SYN flag only
    tcp->window = htons(0xFFFF);
    tcp->checksum = 0;
    tcp->urgent_ptr = 0;

    int tcp_len = 20; // TCP header only

    // Forge IP header
    forge_ip(ip, tcp_len, target_ip);

    // Compute TCP checksum
    tcp->checksum = tcp_checksum(ip, tcp, tcp_len);

    // Prepare sockaddr_ll
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    sll.sll_halen = ETH_ALEN;
    for (i = 0; i < 6; i++) sll.sll_addr[i] = target_mac[i];

    // Send TCP SYN packet
    if (sendto(s, buffer, 14 + 20 + tcp_len, 0, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("Send Failed");
        return 1;
    }
    printf("Sent TCP SYN packet to %d.%d.%d.%d src_port=%d seq_num=%u\n",
           target_ip[0], target_ip[1], target_ip[2], target_ip[3], src_port, seq_num);

    // Receive and validate TCP SYN-ACK reply
    j = 1000; // retry count
    while (j--) {
        n = recvfrom(s, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n == -1) {
            perror("Recvfrom Failed");
            return 1;
        }

        if (eth->type == htons(0x0800) && ip->proto == 6) { // IP protocol TCP
            struct tcp_segment *resp_tcp = (struct tcp_segment *)ip->payload;

            unsigned short resp_src_port = ntohs(resp_tcp->src_port);
            unsigned short resp_dst_port = ntohs(resp_tcp->dst_port);
            unsigned int resp_ack_num = ntohl(resp_tcp->ack_num);
            unsigned char resp_flags = resp_tcp->flags;

            if (resp_src_port == 80 &&
                resp_dst_port == src_port &&
                resp_ack_num == (seq_num + 1) &&
                (resp_flags & 0x12) == 0x12) { // SYN & ACK flags set
                printf("Received valid TCP SYN-ACK reply from %d.%d.%d.%d\n",
                    (ip->src >> 24) & 0xFF,
                    (ip->src >> 16) & 0xFF,
                    (ip->src >> 8) & 0xFF,
                    ip->src & 0xFF);
                break;
            }
        }
    }

    if (j <= 0) {
        printf("No valid TCP SYN-ACK reply received\n");
        return 1;
    }

    return 0;
}