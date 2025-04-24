#include<stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <errno.h>

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
unsigned char broadcast[6] = { 0xFF, 0xFF, 0xFF,0xFF,0xFF,0xFF};

void forge_ip(struct ip_packet * ip, unsigned short totlen, unsigned char * dst)
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
unsigned char target_ip[4] = { 212,71,252,150};
int s;
int resolve_ip(unsigned char * target, unsigned char * mac);
void print_buffer( unsigned char* buffer, int size);

int main () {
unsigned char target_mac[6];
int n,i;
s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if ( s == -1 ) {
	 printf("Errno = %d\n",errno);
	 perror("Socket Failed"); 	
	 return 1;
}
if (resolve_ip(target_ip,target_mac))
	printf("Resolution Failed\n");
else{
	printf("MAC: ");
	print_buffer(target_mac, 6);
	}
}

 
void print_buffer( unsigned char* buffer, int size)
{
int i;
for(i=0; i<size; i++) 
	printf("%.3d (%.2X) ",buffer[i],buffer[i]);
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
