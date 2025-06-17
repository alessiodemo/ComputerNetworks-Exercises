#include<stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <errno.h>
#include <string.h>

struct arp_packet {
unsigned short htype;
unsigned short ptype;
unsigned char hlen;
unsigned char plen;
unsigned short op;
unsigned char srcmac[6];
unsigned char srcip[4];
unsigned char dstmac[6];
unsigned char dstip[4];
};

struct eth_frame{
unsigned char dst[6];
unsigned char src[6];
unsigned short type;
unsigned char payload[1];
};

struct ip_datagram{
unsigned char ver_ihl;
unsigned char tos;
unsigned short totlen;
unsigned short id;
unsigned short flags_offs;
unsigned char ttl;
unsigned char proto;
unsigned short checksum;
unsigned int src;
unsigned int dst;
unsigned char option_type;
unsigned char length;
unsigned char pointer;
unsigned char route_data[36];
unsigned char payload[1];
};

struct icmp_packet{
unsigned char type;
unsigned char code;
unsigned short checksum;
unsigned short id;
unsigned short seq;
unsigned char payload[1];
};

// Node configuration
unsigned char myip[4]={212,71,252,26};
unsigned char mymac[6] = { 0xF2,0x3C,0x94, 0x90, 0x4F, 0x4b};
unsigned char gateway[4] = { 212,71,252,1 };
unsigned char mask[4] = { 255,255,255,0};

// Target address
//unsigned char target_ip[4] = { 212,71,252,150};
unsigned char target_ip[4] = { 147,162,2,100};
unsigned char broadcast[6] = { 0xFF, 0xFF, 0xFF,0xFF,0xFF,0xFF};
int s;
int resolve_ip(unsigned char * target, unsigned char * mac);
void print_buffer( unsigned char* buffer, int size);


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

void forge_ip(struct ip_datagram * ip, unsigned short payloadlen, unsigned char * dst)
{
ip-> ver_ihl = 0x4F;
ip-> tos = 0;
ip-> totlen = htons(payloadlen+60);
ip-> id = htons(0x1234);
ip-> flags_offs=htons(0);
ip-> ttl=128;
ip-> proto=1;
ip-> checksum = htons(0);
ip-> src = *((unsigned int *)myip);
ip-> dst=  *((unsigned int *)dst);
ip-> option_type = 0x7;
ip-> length = 39;
ip-> pointer = 4;
memset(ip->route_data, 0, 36);
ip-> checksum = htons(checksum((unsigned char *)ip,60));
}

void print_buffer( unsigned char* buffer, int size)
{
int i;
for(i=0; i<size; i++){
        printf("%.3d (%.2X) ",buffer[i],buffer[i]);
        if(i%4 == 3) printf("\n");
        }
printf("\n");
}


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
unsigned char buffer[1500];
struct icmp_packet * icmp;
struct ip_datagram * ip;
struct eth_frame * eth;
struct sockaddr_ll sll;
int len;

unsigned char target_mac[6];
int n,i,j;
s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if ( s == -1 ) {
         printf("Errno = %d\n",errno);
         perror("Socket Failed");
         return 1;
}
eth = (struct eth_frame *) buffer;
ip = (struct ip_datagram *) eth->payload;
icmp = ( struct icmp_packet *) ip->payload;
forge_icmp(icmp,8,0,40);
forge_ip(ip,40+8,target_ip);


if ( (*(unsigned int *) myip) & (*(unsigned int*) mask)
   == *(unsigned int * )target_ip & (*(unsigned int* ) mask) ) {
        if (resolve_ip(target_ip,target_mac)) printf("Resolution Failed\n");
        }
else
        if (resolve_ip(gateway,target_mac)) printf("Resolution Failed\n");

for(i=0;i<6; i++){ eth->dst[i]=target_mac[i]; eth->src[i]=mymac[i];}
eth->type = htons(0x0800);
printf("Ethernet header\n");
print_buffer ( (unsigned char *) eth, 14);
printf("Ethernet payload\n");
print_buffer((unsigned char *) ip, 60);
printf("Internet payload\n");
print_buffer((unsigned char *) icmp, 48);

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
        if (eth->type==htons(0x0800)){
//              printf("IP PKT RECEIVED: protocol: %d icmp type: %d\n", ip->proto, icmp->type);
                if(ip->proto == 1 ){
                        printf("ICMP PKT RECEIVED type:%d id:%.4X:\n", icmp->type, icmp->id);
                        if ( (icmp->type == 0) ){
                                printf("ICMP REPLY DETECTED\n");
                                // IP Datagram + ICMP Packet
                                print_buffer((unsigned char * ) ip, 60 + 48 );
                                if(ip->option_type==7) {
                                    int recrod_size=((ip->pointer)-4)/4;
                                    printf("Found record route , size: %d\n", recrod_size);
                                    for(int j=0;j<recrod_size;j++)
                                    {
                                        printf("Record: %d: %u.%u.%u.%u\n", j, ip->route_data[4*j], ip->route_data[4*j+1], ip->route_data[4*j+2], ip->route_data[4*j+3]);
                                    }
                                }
                                break;
                        }else if (icmp->type == 12 && icmp->code == 0){
                                printf("IP Header:\n");
                                print_buffer((unsigned char*) ip, 60 + 48);
                                printf("Parameter problem on octet: %d\n", icmp->id);
                        }
                }
        }
}
return 0;
}