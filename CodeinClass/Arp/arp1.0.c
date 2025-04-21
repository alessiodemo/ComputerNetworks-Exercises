#include<stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <errno.h>

struct arp_packet { //arp packet 
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
    
    struct eth_frame{ //frame ethernet with payload that contains an ARP
    unsigned char dst[6];
    unsigned char src[6];
    unsigned short type;
    unsigned char payload[1];
};

//Node configuration
//local IP and MAC address
unsigned char myip[4] = {212,71,252,26};
unsigned char mymac[6] = { 0xF2,0x3C,0x94,0x90,0x4F,0x44};
unsigned char broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};//broadcast MAC address


//Target address
unsigned char target_ip { 212,71,252,150}; //IP of the target machine

int main(){
     struct arp_packet * arp;
     struct eth_frame * eth;

     struct sockaddr_ll sll;
     unsigned char buffer[1500];
     int n,i,s;
     int len;
     s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); //new socket created, This receives all Ethernet packets (not just IP or ARP).
     if  ( s==-1){ //if it fails
            printf("Errno = %d\n",errno);
            perror("Socket Failed");
            return 1;
     }
     //Set up structures to receive packets
     eth = (struct eth_frame *)  buffer; //points to the beginning of the buffer, representing an Ethernet frame
     arp = (struct arp_packet *) eth->payload; //points to the payload of the Ethernet frame

     for(i=0;i<6;i++) {
            eth->dst[i]=0xFF;
            eth->src[i]=mymac[i];
     }
     eth->type=htons(0x0806);

     for(i=0; i<sizeof(struct sockaddr_ll); i++) ((char *) &sll)[i]=0;

     sll.sll_family = AF_PACKET;
     sll.sll_ifindex = if_nametoindex("eth0"); //Prepares the sockaddr_ll structure to receive from the eth0 interface

     len = sizeof(struct sockaddr_ll);

     n = recvfrom(s,buffer,1500, 0,(struct sockaddr *) &sll, &len); //Receives a packet using recvfrom, it blocks execution until a packet is received on the eth0 interface
     if(n==-1) { //if it fails
            printf("Errno = %d\n",errno);
            perror("Recvfrom Failed");
            return 1;
     }

     //Print the received bytes in both decimal and hexadecimal format 
     for(i=0;i<n;i++)
        printf("%.3d (%.2X) ", buffer[i],buffer[i]);
    printf("\n");

}
    

/*
Questo codice:

    Apre un socket raw.

    Si prepara a ricevere pacchetti Ethernet.

    Blocca fino a che un pacchetto non arriva sull’interfaccia eth0.

    Lo stampa byte per byte.
*/