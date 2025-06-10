/*
Modify the ping.c program so that it builds the IP datagram with a "time to live" small enough to prevent the IP datagram from reaching its destination.
Intercept the ICMP "Time Exceeded" message (see documentation below from RFC 792) from the intermediate node that discarded the packet and print the IP address that originated this message on the screen. 
*/

#include<stdio.h>
#include <net/if.h>               // For interface name to index conversion
#include <arpa/inet.h>            // For htons, htonl, etc.
#include <sys/socket.h>           // For socket functions
#include <linux/if_packet.h>      // For low-level packet structures
#include <net/ethernet.h>         // For Ethernet protocol constants
#include <errno.h>                // For errno handling

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

// ICMP packet structure
struct icmp_packet {
    unsigned char type;           // Type (8=echo request, 0=echo reply)
    unsigned char code;           // Code (usually 0)
    unsigned short checksum;      // Checksum
    unsigned short id;            // Identifier
    unsigned short seq;           // Sequence number
    unsigned char payload[1];     // Data
};

// Node configuration
unsigned char myip[4] = {212, 71, 252, 26};         // Local IP address
unsigned char mymac[6] = {0xF2, 0x3C, 0x94, 0x90, 0x4F, 0x4b}; // Local MAC address
unsigned char gateway[4] = {212, 71, 252, 1};       // Default gateway IP
unsigned char mask[4] = {255, 255, 255, 0};         // Subnet mask

// Target IP to ping
unsigned char target_ip[4] = {147, 162, 2, 100};    // Target IP address
unsigned char broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast MAC
int s; // Raw socket descriptor

// Function prototypes
int resolve_ip(unsigned char *target, unsigned char *mac);
void print_buffer(unsigned char* buffer, int size);

// Calculates the Internet checksum
unsigned short int checksum(unsigned char *b, int len) {
    unsigned short *p = (unsigned short *)b;
    unsigned int tot = 0;
    int i;

    for (i = 0; i < len / 2; i++) {
        tot += ntohs(p[i]);
        if (tot & 0x10000) tot = (tot + 1) & 0xFFFF;
    }

    // Handle odd byte
    if (len & 0x1) {
        tot += ntohs(p[i]) & 0xFF00;
        if (tot & 0x10000) tot = (tot + 1) & 0xFFFF;
    }

    return (0xFFFF - ((unsigned short)tot));
}

// Create an ICMP Echo Request
void forge_icmp(struct icmp_packet *icmp, unsigned char type, unsigned char code, int payloadsize) {
    icmp->type = type;               // ICMP type
    icmp->code = code;               // ICMP code
    icmp->checksum = 0;              // Initially 0 for checksum calculation
    icmp->id = htons(0xABCD);        // Identifier
    icmp->seq = htons(1);            // Sequence number

    for (int i = 0; i < payloadsize; i++)
        icmp->payload[i] = i;        // Fill payload with incremental bytes

    // Calculate checksum
    icmp->checksum = htons(checksum((unsigned char*)icmp, payloadsize + 8));
}

// Construct an IP header
void forge_ip(struct ip_datagram *ip, unsigned short payloadlen, unsigned char *dst) {
    ip->ver_ihl = 0x45;                      // IPv4 and header length = 20 bytes
    ip->tos = 0;                             // No special TOS
    ip->totlen = htons(payloadlen + 20);     // Total length
    ip->id = htons(0x1234);                  // Arbitrary ID
    ip->flags_offs = htons(0);               // No fragmentation
    ip->ttl = 1;  // <<<< CHANGED FROM 128 TO 1
    ip->proto = 1;                           // ICMP protocol
    ip->checksum = 0;
    ip->src = *((unsigned int *)myip);       // Source IP
    ip->dst = *((unsigned int *)dst);        // Destination IP
    ip->checksum = htons(checksum((unsigned char *)ip, 20)); // Calculate checksum
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

// Main function: forge and send ICMP Echo Request
int main() {
    unsigned char buffer[1500];
    struct icmp_packet *icmp;
    struct ip_datagram *ip;
    struct eth_frame *eth;
    struct sockaddr_ll sll;
    int len, n, i, j;
    unsigned char target_mac[6];

    // Create raw socket
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s == -1) {
        printf("Errno = %d\n", errno);
        perror("Socket Failed");
        return 1;
    }

    eth = (struct eth_frame *) buffer;
    ip = (struct ip_datagram *) eth->payload;
    icmp = (struct icmp_packet *) ip->payload;

    // Create ICMP and IP packets
    forge_icmp(icmp, 8, 0, 40); // Echo request with 40-byte payload
    forge_ip(ip, 48, target_ip);

    // Check if target is on same subnet
    if ((*(unsigned int *)myip & *(unsigned int *)mask) ==
        (*(unsigned int *)target_ip & *(unsigned int *)mask)) {
        if (resolve_ip(target_ip, target_mac)) printf("Resolution Failed\n");
    } else {
        if (resolve_ip(gateway, target_mac)) printf("Resolution Failed\n");
    }

    // Fill Ethernet frame with resolved MACs
    for (i = 0; i < 6; i++) {
        eth->dst[i] = target_mac[i];
        eth->src[i] = mymac[i];
    }
    eth->type = htons(0x0800); // IP

    // Debug print
    printf("Ethernet header\n");
    print_buffer((unsigned char *)eth, 14);
    printf("Ethernet payload\n");
    print_buffer((unsigned char *)ip, 68);

    // Prepare sockaddr_ll
    for (i = 0; i < sizeof(struct sockaddr_ll); i++) ((char *)&sll)[i] = 0;
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    len = sizeof(struct sockaddr_ll);

    // Send ICMP request
    if (-1 == sendto(s, buffer, 1500, 0, (struct sockaddr *)&sll, len)) {
        perror("Send Failed");
        return 1;
    }

    // Wait for ICMP reply
    j = 100;
    while (j--) {
        n = recvfrom(s, buffer, 1500, 0, (struct sockaddr *)&sll, &len);
        if (n == -1) {
            printf("Errno = %d\n", errno);
            perror("Recvfrom Failed");
            return 1;
        }

        if (eth->type == htons(0x0800)) {
            struct ip_datagram *recv_ip = (struct ip_datagram *)eth->payload;
            if (recv_ip->proto == 1) { // ICMP
                struct icmp_packet *recv_icmp = (struct icmp_packet *)recv_ip->payload;
        
                if (recv_icmp->type == 11 && recv_icmp->code == 0) {
                    printf("ICMP TIME EXCEEDED RECEIVED\n");
        
                    // <<< Extract and print source IP of the ICMP Time Exceeded
                    unsigned char *ip_bytes = (unsigned char *)&recv_ip->src;
                    printf("Router IP: %d.%d.%d.%d\n",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
        
                    print_buffer((unsigned char *)recv_ip, n - 14);
                    break;
                }
        
                // (Optional) Retain old Echo Reply check if desired
                if (recv_icmp->type == 0 && recv_icmp->id == htons(0xABCD)) {
                    printf("ICMP REPLY DETECTED\n");
                    print_buffer((unsigned char *)recv_ip, 20 + 48);
                    break;
                }
            }
        }
        
    }
    return 0;
}


/*

Why These Changes Are Required
- ip->ttl = 1	To ensure packet is dropped by the first hop, which triggers ICMP Time Exceeded.
- recv_icmp->type == 11 && code == 0	According to RFC 792, this identifies an ICMP Time Exceeded message.
- recv_ip->src	Source IP in outer IP header of ICMP error = router that dropped the packet.

Sample Output You Might See

ICMP TIME EXCEEDED RECEIVED  
Router IP: 212.71.252.1  

*/