/*
Modify the ping.c program to implement a "traceroute" program. The program sends many ip packets destined to 147.162.2.100 having an increasing 
TTL value from 1 to 30 and reports the list of the IP addresses of the gateways encountered in the network path. 
*/

#include <stdio.h>
#include <net/if.h>               // For interface name to index conversion
#include <arpa/inet.h>            // For htons, htonl, etc.
#include <sys/socket.h>           // For socket functions
#include <linux/if_packet.h>      // For low-level packet structures
#include <net/ethernet.h>         // For Ethernet protocol constants
#include <errno.h>                // For errno handling
#include <string.h>     
#include <unistd.h>


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
    ip->ttl = 128;                           // TTL
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
    
    //structures & variables
    struct icmp_packet *icmp;
    struct ip_datagram *ip;
    struct eth_frame *eth;
    struct sockaddr_ll sll;
    int len, n, i, j;
    unsigned char target_mac[6];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    //socket creation
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(s==-1) {
        perror("Socket failed");
        return 1;
    }

    //MAC address resolving for next hop (gateway or target)
    unsigned char *ip_next_hop;
    if(*(unsigned int *)myip & *(unsigned int *)mask == *(unsigned int *)target_ip & *(unsigned int *)mask) {
        ip_next_hop = target_ip;

    }  
    else {
        ip_next_hop = gateway;
    }

    if(resolve_ip(ip_next_hop, target_mac)) {
        printf("MAC resolution failed\n");
        return 1;
    }

    printf("traceroute tp %d.%d.%d.%d:\n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);


    // sendind packets with ttl from 1 to 30
    for(int ttl_val = 1; ttl_val<=30; ttl_val++) {

        memset(buffer, 0, sizeof(buffer));
        eth=(struct eth_frame *) buffer;
        ip=(struct ip_datagram *) eth->payload;
        icmp=(struct icmp_packet *) ip->payload;

        forge_icmp(icmp, 8, 0, 40);
        forge_ip(ip, 48, target_ip);
        ip->ttl=ttl_val;
        ip->checksum=0;
        ip->checksum=htons(checksum((unsigned char *)ip, 20));

        //ethernet header
        for(i=0;i<6;i++) {
            eth->dst[i]=target_mac[i];
            eth->src[i]=mymac[i];
        }

        //sockaddr_ll
        memset(&sll, 0, sizeof(sll));
        sll.sll_family=AF_PACKET;
        sll.sll_ifindex=if_nametoindex("eth0");
        len = sizeof(struct sockaddr_ll);

        //send packet
        if(-1 == sendto(s, buffer, 14+20+8+40, 0, (struct sockaddr *)&sll, len)) {
            perror("Send failed");
            continue;
        }

        //receive answer
        int received =0;
        for(j=0;j<10;j++) {
            n = recvfrom(s, buffer, sizeof(buffer), 0, &saddr, &saddr_len);
            if(n==1) {
                perror("Recvfrom Failed");
                continue;
            }


            eth = (struct eth_frame *) buffer;
            ip = (struct ip_datagram *) eth->payload;
            icmp = (struct icmp_packet *) ip->payload;

            if(eth->type != htons(0x0800) || ip->proto != 1)
                continue;

            unsigned char *sender_ip = (unsigned char *)&ip->src;

            if (icmp->type == 11) { // Time Exceeded
                printf("%2d: %d.%d.%d.%d (Time Exceeded)\n", ttl_val,
                       sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
                received = 1;
                break;
            } else if (icmp->type == 0 && icmp->id == htons(0xABCD)) { // Echo Reply
                printf("%2d: %d.%d.%d.%d (Destination Reached)\n", ttl_val,
                       sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
                received = 1;
                break;
            }
        }

        if(!received) {
            printf("%2d: *\n", ttl_val);
        }

        // Ferma se è raggiunta la destinazione
        if (icmp->type == 0 && icmp->id == htons(0xABCD))
            break;

        sleep(1); // Attendi 1 secondo tra gli hop

    }
return 0;
    
}
