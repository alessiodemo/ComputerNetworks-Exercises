#include<stdio.h>                      // Standard I/O functions (e.g., printf)
#include <net/if.h>                   // Network interface structures
#include <arpa/inet.h>                // Functions for byte order conversion (e.g., htons)
#include <sys/socket.h>               // Socket definitions
#include <linux/if_packet.h>          // Packet socket definitions for link layer access
#include <net/ethernet.h>             // Ethernet protocol definitions
#include <errno.h> 
                   // For error reporting (e.g., perror, errno)
struct arp_packet {
        unsigned short htype;            // Hardware type (e.g., Ethernet = 1)
        unsigned short ptype;            // Protocol type (e.g., IPv4 = 0x0800)
        unsigned char hlen;              // Hardware address length (6 for MAC)
        unsigned char plen;              // Protocol address length (4 for IPv4)
        unsigned short op;               // Operation (1 = request, 2 = reply)
        unsigned char srcmac[6];         // Sender MAC address
        unsigned char srcip[4];          // Sender IP address
        unsigned char dstmac[6];         // Target MAC address
        unsigned char dstip[4];          // Target IP address
};

struct eth_frame {
        unsigned char dst[6];            // Destination MAC address
        unsigned char src[6];            // Source MAC address
        unsigned short type;             // EtherType (e.g., ARP = 0x0806, IP = 0x0800)
        unsigned char payload[1];        // Start of payload (ARP, IP, etc.)
};

struct ip_datagram {
        unsigned char ver_ihl;           // Version + IHL (e.g., 0x45 = IPv4 + 20B header)
        unsigned char tos;               // Type of service (usually 0)
        unsigned short totlen;           // Total length (header + payload)
        unsigned short id;               // Identification field
        unsigned short flags_offs;       // Flags + Fragment offset
        unsigned char ttl;               // Time to live
        unsigned char proto;             // Protocol (ICMP = 1)
        unsigned short checksum;         // Header checksum
        unsigned int src;                // Source IP address
        unsigned int dst;                // Destination IP address
        unsigned char payload[1];        // Payload (ICMP data)
};
    

    struct icmp_packet {
        unsigned char type;              // ICMP type (8 = Echo request)
        unsigned char code;              // Code (0 for echo request)
        unsigned short checksum;         // Checksum over ICMP header + data
        unsigned short id;               // Identifier
        unsigned short seq;              // Sequence number
        unsigned char payload[1];        // Payload data
};
    

unsigned char myip[4] = {212, 71, 252, 26};         // Local IP address
unsigned char mymac[6] = {0xF2,0x3C,0x94,0x90,0x4F,0x4B}; // Local MAC address
unsigned char gateway[4] = {212, 71, 252, 1};        // Gateway IP
unsigned char mask[4] = {255, 255, 255, 0};          // Subnet mask

// Target address
unsigned char target_ip[4] = {212, 71, 252, 150};    // Destination IP
unsigned char broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; // Broadcast MAC

int s; // Socket descriptor
int resolve_ip(unsigned char * target, unsigned char * mac); // ARP resolution
void print_buffer(unsigned char* buffer, int size);          // Debug buffer

//Checksum calculation
unsigned short int checksum (unsigned char * b, int len){
unsigned short * p;
int i;
unsigned int tot = 0;
p = (unsigned short * ) b;
for(i=0;i<len/2;i++){
 tot = tot + ntohs(p[i]);
 if ( tot & 0x10000)
                        tot = (tot + 1) & 0xFFFF;
        }
if ( len&0x1 ){
        tot = tot + ntohs(p[i])&0xFF00;
  if ( tot & 0x10000)
                        tot = (tot + 1) & 0xFFFF;
}

return ( 0xFFFF - ((unsigned short) tot));
}

//forge ICMP packet
void forge_icmp(struct icmp_packet * icmp, unsigned char type, unsigned char code,  int payloadsize )
{
int i;
icmp-> type = type;
icmp-> code = code;
icmp-> checksum = 0;
icmp-> id = htons(0xABCD);
icmp-> seq = htons(1);
for(i=0;i<payloadsize;i++)
        icmp-> payload[i]=i;
icmp-> checksum = htons(checksum((unsigned char*)icmp, payloadsize + 8));
}

//forge IP header
void forge_ip(struct ip_datagram * ip, unsigned short payloadlen, unsigned char * dst)
{
ip-> ver_ihl = 0x45;
ip-> tos = 0;
ip-> totlen = htons(payloadlen+20);
ip-> id = htons(0x1234);
ip-> flags_offs=htons(0);
ip-> ttl=128;
ip-> proto=1;
ip-> checksum = htons(0);
ip-> src = *((unsigned int *)myip);
ip-> dst=  *((unsigned int *)dst);
ip-> checksum = htons(checksum((unsigned char *)ip,20));
}

//print buffer
void print_buffer( unsigned char* buffer, int size)
{
int i;
for(i=0; i<size; i++){
        printf("%.3d (%.2X) ",buffer[i],buffer[i]);
        if(i%4 == 3) printf("\n");
        }
printf("\n");
}

//resolve IP via ARP
int resolve_ip(unsigned char * target, unsigned char * mac)
{
int len;
unsigned char buffer[1500];
struct sockaddr_ll sll;
struct arp_packet * arp;
struct eth_frame * eth;
int i, j,n;
eth = (struct eth_frame *) buffer;
arp = (struct arp_packet * ) eth->payload;

for(i=0;i<6;i++){
        eth->src[i]=mymac[i];
        eth->dst[i]=0xFF;
}
eth->type=htons(0x0806);


arp->htype=htons(1);
arp->ptype=htons(0x0800);
arp->hlen=6;
arp->plen=4;
arp->op=htons(1);
for(i=0;i<6;i++) {
        arp->srcmac[i]=mymac[i];
        arp->dstmac[i]=0;
}
for(i=0;i<4;i++){
        arp->srcip[i]=myip[i];
        arp->dstip[i]=target[i];
}

for(i=0; i<sizeof(struct sockaddr_ll); i++)  ((char *) &sll)[i] = 0;

sll.sll_family = AF_PACKET;
sll.sll_ifindex = if_nametoindex("eth0");
len = sizeof(struct sockaddr_ll);
if( -1 == sendto(s, buffer, 1500, 0, (struct sockaddr * ) &sll, len)){
                perror("Send Failed");
                return 1;
}
j=100;
while(j--){
        n = recvfrom(s,buffer,1500, 0,(struct sockaddr *)  &sll, &len);
        if ( n == -1 ) {
          printf("Errno = %d\n",errno);
          perror("Recvfrom Failed");
                return 1;
                 }
        if (eth->type==htons(0x0806)){
                if(arp->op == htons(2)){
                        printf("ARP REPLY RECEIVED:\n");
                        for(i=0; i<n; i++)
                                printf("%.3d (%.2X) ",buffer[i],buffer[i]);
                        printf("\n");
                        for(i=0;i<6;i++)
                                mac[i] = arp->srcmac[i];
                        return 0;
                }
        }
}
return 1;
}

int main () {

//Buffer and Pointer Setup
unsigned char buffer[1500];
struct icmp_packet * icmp;
struct ip_datagram * ip;
struct eth_frame * eth;


unsigned char target_mac[6];
int n,i;

//create raw socket
s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

//check for errors
if ( s == -1 ) {
         printf("Errno = %d\n",errno);
         perror("Socket Failed");
         return 1;
}

//Assign Struct Pointers
eth = (struct eth_frame *) buffer;
ip = (struct ip_datagram *) eth->payload;
icmp = ( struct icmp_packet *) ip->payload;

//Craft ICMP and IP Packets
forge_icmp(icmp,8,0,40);
forge_ip(ip,40+8,target_ip);

//Check if Target is in Same Subnet
if ( (*(unsigned int *) myip) & (*(unsigned int*) mask)
   == *(unsigned int * )target_ip & (*(unsigned int* ) mask) ) {
        if (resolve_ip(target_ip,target_mac)) printf("Resolution Failed\n");
        }
else
        if (resolve_ip(gateway,target_mac)) printf("Resolution Failed\n");

//Set Ethernet Header
for(i=0;i<6; i++){ eth->dst[i]=target_mac[i]; eth->src[i]=mymac[i];}
eth->type = htons( 0x0800);

//Print Ethernet Header and Payload
printf("Ethernet header\n");
print_buffer ( (unsigned char *) eth, 14);
printf("Ethernet payload\n");
print_buffer((unsigned char *) ip, 68);
return 0;
}