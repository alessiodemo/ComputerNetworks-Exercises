#include <stdio.h>
#include <net/if.h> // Needed for if_nametoindex() — gets the network interface index
#include <arpa/inet.h> //Functions for IP address conversions
#include <sys/socket.h> //socket functions
#include <linux/if_packet.h> //for working with low-level packet sockets
#include <net/ethernet.h> //defines the L2 protocols like ETH_P_ALL
#include <errno.h> //for printing errors with errno

int main(){
    //data structure creation
    
     struct sockaddr_ll sll; // Structure for Layer 2 (Ethernet) socket addressing
     unsigned char buffer[1500]; // Buffer to store the received packet
     int n,i,s;
     int len;

     /*
     socket creation -> socket raw at link level that catch all the packets.
     AF_PACKET: for raw link-layer access.
     SOCK_RAW: raw socket to capture full packets.
     htons(ETH_P_ALL): captures all Ethernet protocols .
     */
     s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 

     //if it fails
     if  ( s==-1){
            printf("Errno = %d\n",errno);
            perror("Socket Failed");
            return 1;
     }


     //structure sockaddr_ll for identify the interface, clears the sockaddr_ll structure by setting all its bytes to 0
     for(i=0; i<sizeof(struct sockaddr_ll); i++) ((char *) &sll)[i]=0;

     sll.sll_family = AF_PACKET; // specifies the address family as Ethernet.
     sll.sll_ifindex = if_nametoindex("eth0"); // gets the index of the "eth0" network interface

     len = sizeof(struct sockaddr_ll); // sets the length for the recvfrom call

    /*
    Receives a packet from the eth0 interface.
    Blocking call: the program waits until a packet is received.
    The received data is stored in buffer.
    */
     n = recvfrom(s,buffer,1500, 0,(struct sockaddr *) &sll, &len); 

    //if it fails
     if(n==-1) { 
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
In summary this program:

    Creates a raw socket at the Ethernet level.

    Listens for incoming packets on the eth0 interface.

    Waits until a packet is received.

    Prints the content of the packet byte-by-byte in both decimal and hexadecimal formats.

It's a simple packet sniffer written in C using raw sockets on Linux.
*/