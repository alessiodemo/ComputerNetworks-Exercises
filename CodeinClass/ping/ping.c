#include<stdio.h>                     // Standard I/O functions (e.g., printf)
#include <net/if.h>                   // Interface-related functions (e.g., if_nametoindex)
#include <arpa/inet.h>                // Functions for IP address manipulation
#include <sys/socket.h>               // Core socket definitions
#include <linux/if_packet.h>          // Low-level packet interface for raw socket
#include <net/ethernet.h>             // Ethernet protocol definitions
#include <errno.h>                    // To access error numbers (errno)


struct arp_packet {
    unsigned short htype;            // Hardware type (e.g., Ethernet)
    unsigned short ptype;            // Protocol type (e.g., IP)
    unsigned char hlen;              // Hardware address length (e.g., 6 for MAC)
    unsigned char plen;              // Protocol address length (e.g., 4 for IPv4)
    unsigned short op;               // ARP operation (1=request, 2=reply)
    unsigned char srcmac[6];         // Sender MAC address
    unsigned char srcip[4];          // Sender IP address
    unsigned char dstmac[6];         // Target MAC address (to be filled in by response)
    unsigned char dstip[4];          // Target IP address
};

struct eth_frame {
    unsigned char dst[6];            // Destination MAC address
    unsigned char src[6];            // Source MAC address
    unsigned short type;             // EtherType (e.g., 0x0806 for ARP)
    unsigned char payload[1];        // Payload (e.g., ARP packet)
};

struct ip_datagram {
    unsigned char ver_ihl;           // Version and header length
    unsigned char tos;               // Type of Service
    unsigned short totlen;           // Total length of IP datagram
    unsigned short id;               // Identification
    unsigned short flags_offs;       // Flags and fragment offset
    unsigned char ttl;               // Time To Live
    unsigned char proto;             // Protocol (e.g., 1 for ICMP)
    unsigned short checksum;         // Header checksum
    unsigned int src;                // Source IP address
    unsigned int dst;                // Destination IP address
};

struct icmp_packet {
    unsigned char type;              // ICMP type (e.g., 8 for echo request)
    unsigned char code;              // ICMP code
    unsigned short checksum;         // Checksum for ICMP header and data
    unsigned short id;               // Identifier (used to match request/response)
    unsigned short seq;              // Sequence number
    unsigned char payload[1];        // ICMP payload
};


// Node configuration
// Our node's IP and MAC address
unsigned char myip[4]={212,71,252,26};
unsigned char mymac[6] = { 0xF2,0x3C,0x94, 0x90, 0x4F, 0x4b};

// Broadcast MAC address (for ARP requests)
unsigned char broadcast[6] = { 0xFF, 0xFF, 0xFF,0xFF,0xFF,0xFF};

//This function constructs an IP packet, sets the header fields, and calculates the checksum
void forge_ip(struct ip_datagram * ip, unsigned short totlen, unsigned char * dst)
{
ip-> ver_ihl = 0x45;
ip-> tos = 0;
ip-> totlen = htons(totlen);
ip-> id = htons(0x1234);
ip-> flags_offs=htons(0);
ip-> ttl=128;
ip-> proto=1;
ip-> checksum = htons(0);
ip-> src = *((unsigned int *)myip);
ip-> dst=  *((unsigned int *)dst);
ip-> checksum = checksum((unsigned char *)ip,20);
}
// Target address
// Target IP to resolve
unsigned char target_ip[4] = { 212,71,252,150};

//other useful parameters
int s;

 // Print the contents of a buffer as decimal and hex
void print_buffer( unsigned char* buffer, int size)
{
int i;
for(i=0; i<size; i++) 
	printf("%.3d (%.2X) ",buffer[i],buffer[i]);
printf("\n");
}

//Function — sends ARP request and waits for a reply
int resolve_ip(unsigned char * target, unsigned char * mac) {
    int len;
    unsigned char buffer[1500];               // Ethernet frame buffer
    struct sockaddr_ll sll;                   // Low-level socket address
    struct arp_packet * arp;
    struct eth_frame * eth;
    int i, j, n;

    // Cast buffer to Ethernet and ARP structures
    eth = (struct eth_frame *) buffer;
    arp = (struct arp_packet *) eth->payload;

    // Fill Ethernet header: source MAC = our MAC, destination = broadcast
    for(i = 0; i < 6; i++) {
        eth->src[i] = mymac[i];
        eth->dst[i] = 0xFF;
    }
    eth->type = htons(0x0806); // ARP EtherType

    // Fill ARP header
    arp->htype = htons(1);     // Ethernet
    arp->ptype = htons(0x0800); // IPv4
    arp->hlen = 6;              // MAC length
    arp->plen = 4;              // IP length
    arp->op = htons(1);         // ARP request
    for(i = 0; i < 6; i++) {
        arp->srcmac[i] = mymac[i];   // Sender MAC
        arp->dstmac[i] = 0;          // Target MAC (unknown)
    }
    for(i = 0; i < 4; i++) {
        arp->srcip[i] = myip[i];     // Sender IP
        arp->dstip[i] = target[i];   // Target IP
    }

    // Clear the socket address struct
    for(i = 0; i < sizeof(struct sockaddr_ll); i++)
        ((char *) &sll)[i] = 0;

    // Set up socket address
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");  // Get interface index for "eth0"
    len = sizeof(struct sockaddr_ll);

    // Send the ARP request
    if(-1 == sendto(s, buffer, 1500, 0, (struct sockaddr *)&sll, len)) {
        perror("Send Failed");
        return 1;
    }

    // Wait for ARP reply
    j = 100;
    while(j--) {
        n = recvfrom(s, buffer, 1500, 0, (struct sockaddr *)&sll, &len);
        if (n == -1) {
            printf("Errno = %d\n", errno);
            perror("Recvfrom Failed");
            return 1;
        }

        // Check if it's an ARP reply
        if (eth->type == htons(0x0806)) {
            if (arp->op == htons(2)) {
                printf("ARP REPLY RECEIVED:\n");
                for(i = 0; i < n; i++)
                    printf("%.3d (%.2X) ", buffer[i], buffer[i]);
                printf("\n");

                // Copy the sender MAC (resolved address)
                for(i = 0; i < 6; i++)
                    mac[i] = arp->srcmac[i];

                return 0; // Success
            }
        }
    }
    return 1; // Timeout / failed to resolve
}

int main () {
    unsigned char target_mac[6];        // To store resolved MAC address
    int n, i;

    // Create a raw socket to capture all Ethernet packets
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s == -1) {
        printf("Errno = %d\n", errno);
        perror("Socket Failed");
        return 1;
    }

    // Try to resolve the IP to a MAC address via ARP
    if (resolve_ip(target_ip, target_mac))
        printf("Resolution Failed\n");
    else {
        printf("MAC: ");
        print_buffer(target_mac, 6);    // Print the resolved MAC
    }
}

