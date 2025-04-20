#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <errno.h>

//structure definition
struct arp_packet {
    unsigned short htype; //hardware type 
    unsigned short ptype; //protocol type
    unsigned char hlen; //lenght of hardware address
    unsigned char plen; //lenght of the protocol address
    unsigned short op; //operation
    unsigned char srcmac[6]; //MAC source
    unsigned char srcip[4]; //IP source
    unsigned char dstmac[6]; //MAC destination
    unsigned char dstip[4]; //IP destination
};
    
    struct eth_frame{
    unsigned char dst[6]; //MAC destination
    unsigned char src[6]; //MAC source
    unsigned short type; //protocol type
    unsigned char payload[1]; //packet data
};

//Node configuration
unsigned char myip[4] = {212,71,252,26}; //IP of the node
unsigned char mymac[6] = { 0xF2,0x3C,0x94,0x90,0x4F,0x44}; //MAC of the node
unsigned char broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; //broadcast MAC


//Target address
unsigned char target_ip = { 212,71,252,150};

int main(){
    //data structure creation
     struct arp_packet * arp;
     struct eth_frame * eth;

     struct sockaddr_ll sll;
     unsigned char buffer[1500];
     int n,i,s;
     int len;
     s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); //socket creation -> socket raw at link level that catch all the packets
     if  ( s==-1){ // if socket fails
            printf("Errno = %d\n",errno);
            perror("Socket Failed");
            return 1;
     }
     eth = (struct eth_frame *)  buffer; //buffer for send and receive the packets
     arp = (struct arp_packet *) eth->payload; //eth references to te inital part, arp ath the payload

     //build the ethernet header
     for(i=0;i<6;i++) {
            eth->dst[i]=0xFF; //destination MAC = broadcast
            eth->src[i]=mymac[i]; //source MAC = our MAC address
     }
     eth->type=htons(0x0806); //set type = ARP

     //structure sockaddr_ll for identify the interface
     for(i=0; i<sizeof(struct sockaddr_ll); i++) ((char *) &sll)[i]=0;

     sll.sll_family = AF_PACKET;
     sll.sll_ifindex = if_nametoindex("eth0"); //obtain interface index named "eth0"

     len = sizeof(struct sockaddr_ll);

     n = recvfrom(s,buffer,1500, 0,(struct sockaddr *) &sll, &len); // blocks the program until the packet is received -> writes the data in the buffer
     if(n==-1) { //if it fails
            printf("Errno = %d\n",errno);
            perror("Recvfrom Failed");
            return 1;
     }
     //prints the received packet
     for(i=0;i<n;i++)
        printf("%.3d (%.2X) ", buffer[i],buffer[i]); //prints every byte in decimal and exadecimal
    printf("\n");

}


/*
In summary:

The program receives an Ethernet packet (any type), interprets it as an ARP packet and prints it to the screen.

It is ready for building a tool that analyzes ARP sniffing or is used to develop an ARP spoofing tool.

It does not send anything, it just sniffs (with an Ethernet header that could be used to send packets in broadcast).
*/