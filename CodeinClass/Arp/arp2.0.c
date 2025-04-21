#include <stdio.h>              // For input/output: printf, perror, etc.
#include <net/if.h>             // For if_nametoindex: gets the index of an interface like "eth0"
#include <arpa/inet.h>          // For IP address conversion functions
#include <sys/socket.h>         // For socket functions
#include <linux/if_packet.h>    // For working at the Ethernet layer (AF_PACKET)
#include <net/ethernet.h>       // Defines Ethernet protocol constants (e.g., ETH_P_ALL)
#include <errno.h>              // For printing system error codes

//struct definition
struct arp_packet {
    unsigned short htype;      // Hardware type (1 = Ethernet)
    unsigned short ptype;      // Protocol type (0x0800 = IPv4)
    unsigned char hlen;        // Hardware address length (6 = MAC)
    unsigned char plen;        // Protocol address length (4 = IPv4)
    unsigned short op;         // Operation (1 = request, 2 = reply)
    unsigned char srcmac[6];   // Source MAC address
    unsigned char srcip[4];    // Source IP address
    unsigned char dstmac[6];   // Target MAC address
    unsigned char dstip[4];    // Target IP address
};

struct eth_frame {
    unsigned char dst[6];      // Destination MAC
    unsigned char src[6];      // Source MAC
    unsigned short type;       // Protocol type (0x0806 = ARP)
    unsigned char payload[1];  // Payload (ARP in this case)
};

// Node configuration
unsigned char myip[4] = { 212, 71, 252, 26 };
unsigned char mymac[6] = { 0xF2, 0x3C, 0x9A, 0x90, 0x4F, 0x4B };
unsigned char broadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// Target address
unsigned char target_ip[4] = { 212, 71, 252, 150 };

int main() {
    // Declare packet structures, a socket address, a buffer, and control variables.
    struct arp_packet *arp;
    struct eth_frame *eth;

    struct sockaddr_ll sll;
    unsigned char buffer[1500];
    int n, i, s;
    int len;

    // Creation a raw socket at the data link layer to capture all Ethernet packets.
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    //if it fails
    if (s == -1) {
        printf("Errno = %d\n", errno);
        perror("Socket Failed");
        return 1;
    }

   //Set up structures to receive packets
   eth = (struct eth_frame *)  buffer; //points to the beginning of the buffer, representing an Ethernet frame
   arp = (struct arp_packet *) eth->payload; //points to the payload of the Ethernet frame

for(i = 0; i < 6; i++) {
    eth->src[i] = mymac[i]; // // Source MAC
    eth->dst[i] = 0xFF; // // Broadcast destination
}

eth->type = htons(0x0806); // Set Ethernet type to ARP

arp->htype = htons(1);         // Hardware type = Ethernet
arp->ptype = htons(0x0800);    // Protocol type = IPv4
arp->hlen = 6;                 // Hardware address length
arp->plen = 4;                 // Protocol address length
arp->op = htons(1);            // Operation = ARP request

for(i = 0; i < 6; i++) {
    arp->srcmac[i] = mymac[i];   // Our MAC address
    arp->dstmac[i] = 0;          // Unknown target MAC
}
for(i = 0; i < 4; i++) {
    arp->srcip[i] = myip[i];        // Our IP address
    arp->dstip[i] = target_ip[i];   // Target IP address
}

//Printing the full ARP request (14 bytes Ethernet header + 28 bytes ARP payload).
for(i = 0; i < 14 + 28; i++)
    printf("%.3d (%.2X) ", buffer[i], buffer[i]);

printf("\n");

// configure the interface
for(i = 0; i < sizeof(struct sockaddr_ll); i++) ((char *) &sll)[i] = 0;

sll.sll_family = AF_PACKET;
sll.sll_ifindex = if_nametoindex("eth0"); // // Get interface index
len = sizeof(struct sockaddr_ll);

// Send the ARP request through the socket
if (-1 == sendto(s, buffer, 42, 0, (struct sockaddr *) &sll, len)) {
    perror("Send Failed");
    return 1;
}

//Receiving the loop -> Waits for incoming packets (blocking).
while(1) {
    /*
        s: the raw socket previously created

    buffer: the memory where the incoming packet is stored

    1500: maximum size of the buffer (standard MTU size)

    sll: structure to store the source address info

    len: size of the sll structure

    This function blocks the program until a packet is received.
    */
    n = recvfrom(s, buffer, 1500, 0, (struct sockaddr *) &sll, &len);
    if (n == -1) {
        printf("Errno = %d\n", errno);
        perror("Recvfrom Failed");
        return 1;
    }

    //check for arp reply, If an ARP reply is received, print its content and extract the MAC address of the target IP
    if (eth->type == htons(0x0806)) {  // if ARP packet -> This checks the Ethernet frame's type field to see if it's an ARP packet (type 0x0806).
        if (arp->op == htons(2)) { // if ARP reply -> Inside the ARP packet, the op field (operation) is checked: 1 = ARP Request, 2 = ARP Reply
            printf("ARP REPLY RECEIVED:\n");
            for(i = 0; i < n; i++)
                printf("%.3d (%.2X) ", buffer[i], buffer[i]);
            printf("\n");
            printf("Target MAC: %x:%x:%x:%x:%x:%x:%x", arp->srcmac[0], arp->srcmac[1], arp->srcmac[2], arp->srcmac[3], arp->srcmac[4], arp->srcmac[5], arp->srcmac[6]);
            return 0;
        }
    }
}
}

/*
This code:

    Builds and sends an ARP request for a given IP address.

    Waits for an ARP reply.

    Prints the MAC address associated with the target IP.
*/

