s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
/*
    serve per creare un socket raw a basso livello, che permette di leggere e scrivere pacchetti Ethernet direttamente (compresi gli header), bypassando lo stack TCP/IP.
    È usato spesso per sniffing di pacchetti, programmi ARP/ICMP personalizzati, e tool tipo ping, tcpdump, ecc.
    - AF_PACKET	Specifica che vuoi lavorare a livello Ethernet (livello 2 ISO/OSI)
    - SOCK_RAW	Tipo di socket: permette di inviare/leggere pacchetti grezzi, inclusi header
    - htons(ETH_P_ALL)	Filtro sul protocollo: ETH_P_ALL = tutti i protocolli Ethernet. htons converte in big endian (network byte order)

    */

-----------------------------------------------------------------------------
/*
    La struttura struct sockaddr_in è definita nel file header <netinet/in.h> ed è usata per rappresentare indirizzi IPv4 in programmazione di rete con i socket.
    È una struttura specifica per IPv4, usata spesso con socket TCP o UDP.
*/
    struct sockaddr_in {
    sa_family_t    sin_family;  // Famiglia dell'indirizzo (AF_INET per IPv4)
    in_port_t      sin_port;    // Numero di porta (formato network byte order)
    struct in_addr sin_addr;    // Indirizzo IP (struttura con campo s_addr)
    char           sin_zero[8]; // Padding per uguagliare la dimensione di sockaddr
    };
-----------------------------------------------------------------------------
/*
    A cosa serve sockaddr_ll?
    È usata per inviare o ricevere pacchetti direttamente sul livello datalink, bypassando gli strati IP/TCP/UDP. In particolare:
    Viene usata con socket di tipo PF_PACKET.
    Permette di specificare l’interfaccia di rete (eth0, wlan0, ecc.) su cui operare.
    Può indicare direttamente l’indirizzo MAC di destinazione.
    È usata in sendto() o recvfrom() per lavorare a livello Ethernet.
*/
#include <linux/if_packet.h>
#include <net/ethernet.h> // ETH_P_ALL

struct sockaddr_ll {
    unsigned short sll_family;      // Sempre AF_PACKET
    unsigned short sll_protocol;    // Protocollo livello superiore (es. htons(ETH_P_IP))
    int            sll_ifindex;     // Indice dell'interfaccia (ottenuto con ioctl)
    unsigned short sll_hatype;      // Tipo hardware (ARPHRD_ETHER per Ethernet)
    unsigned char  sll_pkttype;     // Tipo di pacchetto (es. PACKET_OUTGOING)
    unsigned char  sll_halen;       // Lunghezza indirizzo hardware
    unsigned char  sll_addr[8];     // Indirizzo hardware (es. MAC address)
};
--------------------------------------------------------------------------------------
/*
    È una struttura generica, usata come interfaccia comune per diverse famiglie di indirizzi (IPv4, IPv6, UNIX domain socket, ecc.).

    Usata come tipo di parametro per funzioni di sistema come bind(), connect(), accept(), che vogliono accettare qualsiasi tipo di indirizzo.
*/
    struct sockaddr {
    sa_family_t sa_family;   // Tipo di indirizzo (es. AF_INET, AF_INET6)
    char        sa_data[14]; // Dati dell'indirizzo (formato generico)
};
--------------------------------------------------------------------------------------
/*
     Opzioni utili:
    Comando / Opzione	Descrizione
    man <nome>	Mostra la prima man page trovata per <nome>
    man <sezione> <nome>	Mostra la man page nella sezione specificata
    man -k <parola>	Cerca la parola tra tutte le man page (come apropos)
    man -f <comando>	Mostra le sezioni disponibili per quel comando (come whatis)
    man -a <nome>	Mostra tutte le man page con quel nome, una alla volta
    man -w <nome>	Mostra il percorso del file della man page
    man -P "comando"	Specifica un pager (es. man -P cat ls)
    man --help	Mostra le opzioni disponibili per man

*/
--------------------------------------------------------------------------------------
/*ARP packet
Un ARP packet (pacchetto ARP) è un pacchetto di rete utilizzato dal protocollo ARP (Address Resolution Protocol), che serve a risolvere un indirizzo IP in un indirizzo MAC all'interno di una rete locale (LAN).
In parole semplici:

Quando un computer vuole comunicare con un altro nella stessa rete, conosce l’indirizzo IP di destinazione, ma per inviare effettivamente i dati sul livello di collegamento (livello 2 del modello OSI), ha bisogno dell’indirizzo MAC. Il protocollo ARP fa questa associazione.
Struttura di un pacchetto ARP

Un pacchetto ARP ha una struttura standard. Ecco i campi principali:
Campo	Descrizione
Hardware Type	Di solito 1 per Ethernet
Protocol Type	Di solito 0x0800 per IPv4
Hardware Size	Lunghezza dell’indirizzo MAC (di solito 6 byte)
Protocol Size	Lunghezza dell’indirizzo IP (di solito 4 byte)
Opcode	1 = richiesta (request), 2 = risposta (reply)
Sender MAC Address	MAC dell’host che invia il pacchetto
Sender IP Address	IP dell’host che invia il pacchetto
Target MAC Address	MAC del destinatario (0 in una richiesta)
Target IP Address	IP del destinatario (quello da risolvere)*/
--------------------------------------------------------------------------------------------
/*Ethernet frame
È un “contenitore” che incapsula i dati da inviare tra dispositivi all’interno di una rete locale (LAN), includendo informazioni fondamentali come gli indirizzi MAC del mittente e del destinatario.
Struttura di un Ethernet Frame (standard Ethernet II)

Ecco i principali campi di un frame Ethernet:
Campo	Dimensione	Descrizione
Preamble	7 byte	Sequenza di sincronizzazione (non sempre visibile nel software)
Start Frame Delimiter (SFD)	1 byte	Indica l'inizio del frame (valore: 0xAB)
Destination MAC	6 byte	Indirizzo MAC del destinatario
Source MAC	6 byte	Indirizzo MAC del mittente
EtherType	2 byte	Specifica il protocollo del payload (es: 0x0800 per IPv4, 0x0806 per ARP)
Payload (Data)	46–1500 byte	I dati veri e propri (es. un pacchetto IP, ARP, ecc.)
Frame Check Sequence (FCS)	4 byte	CRC per controllo errori

⚠️ Nota: Il payload minimo è di 46 byte, per cui se i dati sono meno, si aggiunge padding.*/
--------------------------------------------------------------------------------------------
/*IP packet
Un pacchetto IP trasporta i dati da un dispositivo a un altro usando gli indirizzi IP, e può attraversare più reti (router) lungo il percorso.
Struttura di un pacchetto IP (IPv4)
Campo	Dimensione	Descrizione
Version	4 bit	Versione IP (4 per IPv4)
IHL (Header Length)	4 bit	Lunghezza dell’header
Type of Service (ToS)	1 byte	Priorità del pacchetto
Total Length	2 byte	Lunghezza totale (header + dati)
Identification	2 byte	ID per frammentazione
Flags + Fragment Offset	3 bit + 13 bit	Per gestire frammentazione
TTL (Time To Live)	1 byte	Numero max di hop (router)
Protocol	1 byte	Protocollo del payload (es. TCP = 6, UDP = 17, ICMP = 1)
Header Checksum	2 byte	Controllo errori sull’header
Source IP Address	4 byte	IP del mittente
Destination IP Address	4 byte	IP del destinatario
Options (opzionale)	variabile	Opzioni extra
Payload	variabile	Dati da trasportare (es. TCP/UDP/ICMP)*/
-----------------------------------------------------------------------------------------
/*ICMP packet
A cosa serve un pacchetto ICMP?

    Comunicare errori di rete (host irraggiungibile, TTL scaduto, ecc.)

    Usato per strumenti come ping e traceroute

    Segnalare problemi come:

        Host o porta non raggiungibile

        Router congestionato

        Problemi di instradamento

Struttura di un pacchetto ICMP
Campo	Dimensione	Descrizione
Type	1 byte	Tipo del messaggio (es. 8 = Echo Request, 0 = Echo Reply)
Code	1 byte	Codice specifico per quel tipo (es. 0 = standard)
Checksum	2 byte	Controllo errori sull’intero pacchetto ICMP
Rest of Header	4 byte	Dipende dal tipo: identificatore, sequenza, MTU, ecc.
Payload	variabile	Dati (es. timestamp o parte del pacchetto IP originale)*/
-----------------------------------------------------------------------------------------
[ Ethernet Frame ]
  └── [ IP Packet ]
        └── Protocol: ICMP (1)
              └── [ ICMP Header ]
                    ├── Type = 8 (Request)
                    ├── Code = 0
                    ├── Checksum
                    └── Payload (es. timestamp)
-----------------------------------------------------------------------------------------
//SOCKET creation
int socket(int domain, int type, int protocol);
/* Parametri

    domain (o address family): specifica la famiglia di protocolli da usare.
        AF_INET → IPv4
        AF_INET6 → IPv6
        AF_PACKET → livello link layer (Ethernet) — usato per raw socket
    type: specifica il tipo di socket.
        SOCK_STREAM → per connessioni orientate (es. TCP)
        SOCK_DGRAM → per datagrammi (es. UDP)
        SOCK_RAW → per pacchetti raw (basso livello, come nel tuo programma)
    protocol: indica il protocollo specifico da usare (di solito può essere 0 per lasciare scegliere al sistema operativo quello predefinito per quel domain e type).
        IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, ...
        ETH_P_ALL (in htons) → per ricevere tutti i protocolli Ethernet (solo per AF_PACKET)*/
