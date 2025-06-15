#include <arpa/inet.h> // Per htons, htonl, ntohs, ntohl, inet_addr
#include<errno.h>      // Per errno e strerror
#include<stdio.h>      // Per printf, perror, fopen, fread, fclose
#include<signal.h>     // Per sigaction, sigemptyset, sigaddset, sigprocmask, pause
#include <sys/types.h>  // Per vari tipi di sistema (es. pid_t)
#include <sys/time.h>   // Per gettimeofday, setitimer, struct timeval, struct itimerval
#include <unistd.h>     // Per getpid, sleep, fcntl
#include <fcntl.h>      // Per fcntl, O_ASYNC, O_NONBLOCK, F_SETOWN, F_GETFL, F_SETFL
#include <sys/socket.h> // Per socket, sendto, recvfrom, sockaddr, AF_PACKET, SOCK_RAW
#include <linux/if_packet.h> // Per sockaddr_ll, ETH_P_ALL
#include <net/ethernet.h> /* the L2 protocols */ // Per ETH_P_ALL (potrebbe essere un errore di commento, dovrebbe essere in <linux/if_packet.h> o <net/ethernet.h>)
#include <net/if.h>     // Per if_nametoindex
#include <strings.h>    // Per bzero (deprecato, preferire string.h e memset)
#include <string.h>     // Per memcpy, memset, strcmp, strlen
#include <stdlib.h>     // Per malloc, free, atoi, rand, abs
#include <poll.h>       // Per poll, pollfd, POLLIN, POLLOUT
#include <time.h>       // Per clock, CLOCKS_PER_SEC

// Definizioni di costanti
#define MAXFRAME 30000        // Dimensione massima del frame Ethernet
#define TIMER_USECS 500       // Intervallo del timer in microsecondi (0.5 ms)
#define RXBUFSIZE 64000       // Dimensione del buffer di ricezione TCP
#define MAXTIMEOUT 2000       // Timeout massimo in unità di TIMER_USECS (2000 * 0.5ms = 1 secondo)
#define MAXRTO MAXTIMEOUT     // Retransmission Timeout massimo

#define MIN_PORT 19000        // Porta minima per l'assegnazione automatica
#define MAX_PORT 19999        // Porta massima per l'assegnazione automatica

// Macro per il calcolo del minimo e massimo
#define MIN(x,y) (((x) > (y) ) ? (y) : (x) )
#define MAX(x,y) (((x) < (y) ) ? (y) : (x) )

// Variabili globali per gli argomenti della linea di comando
char * * g_argv; // Puntatore agli argomenti della linea di comando
int g_argc;      // Numero di argomenti della linea di comando

// Macro per configurare parametri in base agli argomenti della linea di comando
// TXBUFSIZE: Dimensione del buffer di trasmissione TCP (default 100KB, o dal 3° argomento)
#define TXBUFSIZE    ((g_argc<3) ?100000:(atoi(g_argv[2])))
// INIT_TIMEOUT: Timeout iniziale in unità di TIMER_USECS (default 300ms, o dal 4° argomento)
#define INIT_TIMEOUT (((g_argc<4) ?(300*1000):(atoi(g_argv[3])*1000))/TIMER_USECS)
// INV_LOSS_RATE: Inverso del tasso di perdita pacchetti (es. 10000 significa 1/10000)
#define INV_LOSS_RATE    ((g_argc<6) ?10000:(atoi(g_argv[5])))

// Stringa di utilizzo per la riga di comando
char * usage_string = "%s <port> [<TXBUFSIZE (default 100K)>] [<TIMEOUT msec (default 300)>] [MODE: <SRV|CLN> (default SRV)] [1/LOSSRATE <1/N> (default 10000)\n";
// Opzione MSS (Maximum Segment Size) per il TCP, 0x0590 = 1424 (dimensione del payload massimo)
unsigned char  mssopt[4] = { 0x02, 0x04, 0x05, 0x90};

// Strutture per la gestione dei segnali
struct sigaction action_io, action_timer; // Azioni per i segnali I/O e timer
sigset_t mymask; // Maschera di segnali da bloccare/sbloccare

// Buffer per i frame Ethernet ricevuti
unsigned char l2buffer[MAXFRAME];

struct sockaddr_ll; // Dichiarazione incompleta (definita più avanti)

// Struttura per il polling dei file descriptor
struct pollfd fds[1];

int fdfl; // Flag del file descriptor del socket raw

long long int tick=0; // Contatore dei "tick" del timer (ogni tick = TIMER_USECS)
int unique_s; // File descriptor del socket raw
int fl; // Flag per il controllo di sovrapposizione delle chiamate ai gestori di segnale (flog)

struct sockaddr_ll sll; // Struttura per l'indirizzo del socket di livello link (usato per sendto/recvfrom sul socket raw)

// Funzione per stampare un buffer in formato esadecimale e decimale
int printbuf(void * b, int size){
    int i;
    unsigned char * c = (unsigned char *) b;
    for(i=0;i<size;i++)
        printf("%.2x(%.3d) ", c[i],c[i]); // Stampa byte in esadecimale e decimale
    printf("\n");
}

// Indirizzi di rete configurati
unsigned char myip[4] = { 212,71,252,26};         // Indirizzo IP locale
unsigned char mymac[6] ={0xf2,0x3c,0x94,0x90,0x4f,0x4b}; // Indirizzo MAC locale
unsigned char mask[4] = { 255,255,255,0 };        // Subnet mask
unsigned char gateway[4] = {212,71,252,1};      // Indirizzo IP del gateway

// Funzione per ottenere il tempo di clock in microsecondi
// cmd=1: resetta il contatore a zero
// cmd=0: restituisce il tempo trascorso dall'ultimo reset
unsigned long int rtclock(int cmd){
    static struct timeval tv,zero;
    gettimeofday(&tv,NULL); // Ottiene l'ora corrente
    if(cmd==1) zero = tv; // Resetta il punto di riferimento
    // Calcola il tempo trascorso in microsecondi
    return (tv.tv_sec - zero.tv_sec)*1000000 + (tv.tv_usec - zero.tv_usec);
}

// Struttura di un pacchetto ICMP (Internet Control Message Protocol)
struct icmp_packet{
    unsigned char type;         // Tipo di messaggio ICMP
    unsigned char code;         // Codice del messaggio ICMP
    unsigned short checksum;    // Checksum del pacchetto ICMP
    unsigned short id;          // Identificatore
    unsigned short seq;         // Numero di sequenza
    unsigned char data[20];     // Dati del payload (es. per Echo Request/Reply)
};

// Struttura di un datagramma IP (Internet Protocol)
struct ip_datagram {
    unsigned char ver_ihl;      // Versione IP (4 bit) e Internet Header Length (IHL, 4 bit)
    unsigned char tos;          // Type of Service (ora Differentiated Services Code Point, DSCP)
    unsigned short totlen;      // Lunghezza totale del datagramma
    unsigned short id;          // Identificatore del datagramma
    unsigned short fl_offs;     // Flag e offset di frammentazione
    unsigned char ttl;          // Time To Live
    unsigned char proto;        // Protocollo del payload (es. TCP, UDP, ICMP)
    unsigned short checksum;    // Checksum dell'header IP
    unsigned int srcaddr;       // Indirizzo IP sorgente
    unsigned int dstaddr;       // Indirizzo IP destinazione
    unsigned char payload[20];  // Inizio del payload (dimensione variabile, qui per ICMP/TCP header min.)
};

// Dichiarazione della funzione per risolvere un indirizzo MAC tramite ARP
int resolve_mac(unsigned int destip, unsigned char * destmac);

// Struttura di un pacchetto ARP (Address Resolution Protocol)
struct arp_packet {
    unsigned short int htype;   // Tipo di hardware (es. Ethernet)
    unsigned short int ptype;   // Tipo di protocollo (es. IPv4)
    unsigned char hlen;         // Lunghezza dell'indirizzo hardware
    unsigned char plen;         // Lunghezza dell'indirizzo di protocollo
    unsigned short op;          // Operazione (Request o Reply)
    unsigned char srcmac[6];    // Indirizzo MAC sorgente
    unsigned char srcip[4];     // Indirizzo IP sorgente
    unsigned char dstmac[6];    // Indirizzo MAC destinazione
    unsigned char dstip[4];     // Indirizzo IP destinazione
};

// Struttura di un frame Ethernet (livello 2)
struct ethernet_frame {
    unsigned char dstmac[6];    // Indirizzo MAC destinazione
    unsigned char srcmac[6];    // Indirizzo MAC sorgente
    unsigned short int type;    // EtherType (es. IP, ARP)
    unsigned char payload[10];  // Inizio del payload (dimensione variabile)
};

int s; // Variabile globale non utilizzata in modo significativo, forse un residuo.

// Funzione per confrontare due blocchi di memoria
// Restituisce 1 se sono uguali, 0 altrimenti
int are_equal(void *a1, void *a2, int l)
{
    char *b1 = (char *)a1;
    char *b2 = (char *)a2;
    for(int i=0; i<l; i++)
        if(b1[i]!=b2[i]) return 0; // Se un byte è diverso, restituisce 0
    return 1; // Tutti i byte sono uguali
}

// Funzione helper per il calcolo del checksum (complemento a uno, parte 1)
// Usata per il checksum IP e TCP
unsigned short int compl1( char * b, int len)
{
    unsigned short total = 0;
    unsigned short prev = 0;
    unsigned short *p = (unsigned short * ) b;
    int i;
    for(i=0; i < len/2 ; i++){ // Somma word a 16 bit
        total += ntohs(p[i]);
        if (total < prev ) total++; // Gestione del carry (se la somma è minore della precedente, c'è stato un overflow)
        prev = total;
    }
    if ( i*2 != len){ // Se la lunghezza è dispari, elabora l'ultimo byte
        total += (ntohs(p[len/2]) & 0xFF00); // Somma l'ultimo byte come word
        if (total < prev ) total++; // Gestione del carry
        prev = total;
    }
    return (total);
}

// Funzione per calcolare il checksum (complemento a uno) su due buffer
// Usato per il checksum TCP che include la pseudo-header IP
unsigned short int checksum2 ( char * b1, int len1, char* b2, int len2)
{
    unsigned short prev, total;
    prev = compl1(b1,len1); // Checksum del primo buffer (pseudo-header)
    total = (prev + compl1(b2,len2)); // Somma con il checksum del secondo buffer (TCP header + data)
    if (total < prev ) total++; // Gestione del carry
    return (0xFFFF - total); // Restituisce il complemento a uno della somma
}

// Funzione per calcolare il checksum (complemento a uno) su un singolo buffer
// Usato per il checksum IP e ICMP
unsigned short int checksum ( char * b, int len)
{
    unsigned short total = 0;
    unsigned short prev = 0;
    unsigned short *p = (unsigned short * ) b;
    int i;
    for(i=0; i < len/2 ; i++){ // Somma word a 16 bit
        total += ntohs(p[i]);
        if (total < prev ) total++; // Gestione del carry
        prev = total;
    }
    if ( i*2 != len){ // Se la lunghezza è dispari, elabora l'ultimo byte
        total += (ntohs(p[len/2]) & 0xFF00); // Somma l'ultimo byte come word
        if (total < prev ) total++; // Gestione del carry
        prev = total;
    }
    return (0xFFFF-total); // Restituisce il complemento a uno della somma
}

// Funzione per forgiare un pacchetto ICMP Echo Request
void forge_icmp_echo(struct icmp_packet * icmp, int payloadsize)
{
    int i;
    icmp->type=8;       // Tipo 8: Echo Request
    icmp->code=0;       // Codice 0
    icmp->checksum=htons(0); // Inizializza a 0 per il calcolo
    icmp->id=htons(0x1234);  // ID arbitrario
    icmp->seq=htons(1);    // Numero di sequenza arbitrario
    for(i=0;i<payloadsize;i++)
        icmp->data[i]=i&0xFF; // Riempi il payload con dati sequenziali
    // Calcola il checksum finale del pacchetto ICMP
    icmp->checksum=htons(checksum((unsigned char *)icmp , 8 + payloadsize));
}

// Funzione per forgiare un datagramma IP
void forge_ip(struct ip_datagram * ip, int payloadsize, char proto,unsigned int target )
{
    ip->ver_ihl=0x45;   // Versione 4, IHL 5 (5 * 4 = 20 byte di header)
    ip->tos=0;          // Type of Service a 0
    ip->totlen=htons(20+payloadsize); // Lunghezza totale = 20 (header IP) + payloadsize
    ip->id = rand()&0xFFFF; // ID del datagramma casuale
    ip->fl_offs=htons(0);   // Nessun flag di frammentazione, offset 0
    ip->ttl=128;        // Time To Live
    ip->proto = proto;  // Protocollo del payload (es. TCP=6, ICMP=1)
    ip->checksum=htons(0); // Inizializza a 0 per il calcolo
    ip->srcaddr= *(unsigned int*)myip; // Indirizzo IP sorgente
    ip->dstaddr= target; // Indirizzo IP destinazione
    // Calcola il checksum finale dell'header IP
    ip->checksum = htons(checksum((unsigned char *)ip,20));
}

// Funzione per forgiare un frame Ethernet
void forge_ethernet(struct ethernet_frame * eth, unsigned char * dest, unsigned short type)
{
    memcpy(eth->dstmac,dest,6); // Copia l'indirizzo MAC destinazione
    memcpy(eth->srcmac,mymac,6); // Copia l'indirizzo MAC sorgente (locale)
    eth->type=htons(type); // Tipo EtherType (es. IP=0x0800, ARP=0x0806)
}

// Funzione per inviare un pacchetto IP
// Incapsula la logica di risoluzione MAC e invio a livello link
int send_ip(unsigned char * payload, unsigned char * targetip, int payloadlen, unsigned char proto)
{
    static int losscounter; // Contatore per la simulazione di perdita pacchetti
    int i,t,len ;
    unsigned char destmac[6]; // Indirizzo MAC destinazione
    unsigned char packet[2000]; // Buffer per il frame Ethernet completo
    struct ethernet_frame * eth = (struct ethernet_frame *) packet; // Puntatore al frame Ethernet
    struct ip_datagram * ip = (struct ip_datagram *) eth->payload; // Puntatore al datagramma IP (nel payload Ethernet)

    // Simulazione della perdita di pacchetti (solo se il programma è in modalità Server 'S')
    if(!(rand()%INV_LOSS_RATE) && g_argv[4][0]=='S') {printf("==========TX LOST ===============\n");return 1;}
    // Altra condizione per la perdita di pacchetti (ogni 25 pacchetti in modalità Server)
    if((losscounter++ == 25)  &&(g_argv[4][0]=='S')){printf("==========TX LOST ===============\n");return 1;}

    // Decisione di routing: se l'IP di destinazione è nella stessa sottorete, usa il suo MAC diretto,
    // altrimenti usa il MAC del gateway.
    if( (((*(unsigned int*)targetip) & (*(unsigned int*) mask)) == ((*(unsigned int*)myip) & (*(unsigned int*) mask))) )
        t = resolve_mac(*(unsigned int *)targetip, destmac); // Stessa sottorete
    else
        t = resolve_mac(*(unsigned int *)gateway, destmac); // Gateway
    if(t==-1) return -1; // Impossibile risolvere l'indirizzo MAC

    // Forgia l'header Ethernet (tipo 0x0800 per IP)
    forge_ethernet(eth,destmac,0x0800);
    // Forgia l'header IP
    forge_ip(ip,payloadlen,proto,*(unsigned int *)targetip);
    // Copia il payload IP (es. segmento TCP)
    memcpy(ip->payload,payload,payloadlen);

    len=sizeof(sll);
    bzero(&sll,len); // Inizializza la struttura sockaddr_ll
    sll.sll_family=AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0"); // Specifica l'interfaccia di rete
    // Invia il frame Ethernet completo (Ethernet header + IP header + IP payload)
    t=sendto(unique_s,packet,14+20+payloadlen, 0,(struct sockaddr *)&sll,len);
    if (t == -1) {perror("sendto failed"); return -1;}
    return 0;
}

// Cache ARP per memorizzare le associazioni IP-MAC
#define MAX_ARP 200
struct arpcacheline {
    unsigned int key; // Indirizzo IP
    unsigned char mac[6]; // Indirizzo MAC corrispondente
}arpcache[MAX_ARP];

// Costanti per i protocolli e le dimensioni
#define TCP_PROTO 6         // Numero di protocollo per TCP
#define MAX_FD 8            // Numero massimo di file descriptor (socket) gestiti
#define TCP_MSS 1400        // Maximum Segment Size per TCP (dimensione massima del payload TCP)

// Stati dei socket a livello di file descriptor (gestiti dal livello "mysocket")
#define FREE 0          // Socket libero
#define TCP_UNBOUND 1   // Socket creato ma non associato a porta/IP
#define TCP_BOUND 2     // Socket associato a porta/IP
#define TCB_CREATED 3   // Socket con TCB (Transmission Control Block) creato

// Input per la Finite State Machine (FSM) TCP
#define APP_ACTIVE_OPEN 1   // Richiesta di apertura attiva (client)
#define APP_PASSIVE_OPEN 2  // Richiesta di apertura passiva (server listen)
#define PKT_RCV 3           // Pacchetto ricevuto
#define APP_CLOSE 4         // Richiesta di chiusura dall'applicazione
#define TIMEOUT 5           // Timeout scaduto

// Stati della TCB (Transmission Control Block) - Stati della FSM TCP
#define TCP_CLOSED 10       // Stato iniziale
#define LISTEN 11           // In attesa di una richiesta di connessione
#define SYN_SENT 12         // SYN inviato, in attesa di SYN-ACK
#define SYN_RECEIVED 13     // SYN ricevuto e SYN-ACK inviato, in attesa di ACK
#define ESTABLISHED 14      // Connessione stabilita, fase di trasferimento dati
#define FIN_WAIT_1 15       // FIN inviato, in attesa di ACK
#define FIN_WAIT_2 16       // ACK del FIN ricevuto, in attesa di FIN dal remoto
#define CLOSE_WAIT 17       // FIN ricevuto dal remoto, in attesa di chiusura dall'app locale
#define CLOSING 18          // FIN inviato e FIN ricevuto, in attesa di ACK del FIN inviato
#define LAST_ACK 19         // FIN inviato dopo CLOSE_WAIT, in attesa dell'ACK finale
#define TIME_WAIT 20        // In attesa per assicurare ACK finale sia ricevuto dal remoto

// Flag TCP
#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20

int myerrno; // Variabile per gli errori personalizzati (simile a errno)

// Funzione per stampare messaggi di errore personalizzati
void myperror(char *message) {
    //printf("%s: %s\n",message,strerror(myerrno)); // Rimosso ;
}

// Struttura di un segmento TCP
struct tcp_segment {
    unsigned short s_port;      // Porta sorgente
    unsigned short d_port;      // Porta destinazione
    unsigned int seq;           // Numero di sequenza
    unsigned int ack;           // Numero di acknowledgement
    unsigned char d_offs_res;   // Data Offset (lunghezza header TCP, 4 bit) e Riservato (4 bit)
    unsigned char flags;        // Flag TCP (SYN, ACK, FIN, ecc.)
    unsigned short window;      // Dimensione della finestra di ricezione
    unsigned short checksum;    // Checksum del segmento TCP
    unsigned short urgp;        // Puntatore urgente (non usato in questa implementazione)
    unsigned char payload[TCP_MSS]; // Payload del segmento TCP (dati applicativi)
};

// Struttura per la pseudo-header TCP (usata per il calcolo del checksum TCP)
struct pseudoheader {
    unsigned int s_addr, d_addr; // Indirizzi IP sorgente e destinazione
    unsigned char zero;         // Byte a zero
    unsigned char prot;         // Protocollo (TCP = 6)
    unsigned short len;         // Lunghezza del segmento TCP (header + payload)
};

// Struttura per il controllo dei segmenti ricevuti fuori ordine
struct rxcontrol{
    unsigned int stream_offs;       // Offset del segmento nello stream di byte
    unsigned int streamsegmentsize; // Dimensione del segmento
    struct rxcontrol * next;       // Puntatore al prossimo segmento (lista concatenata)
};

// Struttura per il controllo dei buffer di trasmissione
struct txcontrolbuf{
    struct tcp_segment * segment;   // Puntatore al segmento TCP
    int totlen;                     // Lunghezza totale del segmento (header + payload)
    int payloadlen;                 // Lunghezza del payload del segmento
    long long int txtime;           // Tempo di ultima trasmissione del segmento (tick)
    struct txcontrolbuf * next;     // Puntatore al prossimo segmento in coda di trasmissione
    int retry;                      // Contatore dei tentativi di ritrasmissione
};

// Struttura Transmission Control Block (TCB) - Contiene tutto lo stato di una connessione TCP
struct tcpctrlblk{
    struct txcontrolbuf *txfirst, * txlast; // Coda di trasmissione (first e last)
    int st;                             // Stato della FSM TCP (es. ESTABLISHED)
    unsigned short r_port;              // Porta remota
    unsigned int r_addr;                // Indirizzo IP remoto
    unsigned short adwin;               // Finestra di ricezione pubblicizzata (adv_window)
    unsigned short radwin;              // Finestra di ricezione pubblicizzata dal remoto
    unsigned char * rxbuffer;           // Buffer di ricezione
    unsigned int rx_win_start;          // Inizio della finestra di ricezione (offset nello stream)
    struct rxcontrol * unack;           // Lista di segmenti ricevuti fuori ordine
    unsigned int cumulativeack;         // ACK cumulativo (prossimo byte atteso dal remoto)
    unsigned int ack_offs, seq_offs;    // Offset per la normalizzazione dei numeri di sequenza/ack
    long long timeout;                  // Retransmission Timeout (RTO) in tick
    unsigned int sequence;              // Numero di sequenza locale corrente (per il prossimo byte da inviare)
    unsigned int txfree;                // Spazio libero nel buffer di trasmissione
    unsigned int mss;                   // Maximum Segment Size negoziato
    unsigned int stream_end;            // Fine dello stream (segnale FIN ricevuto)
    unsigned int fsm_timer;             // Timer per gli stati della FSM (es. TIME_WAIT)
/* CONG CTRL*/
#ifdef CONGCTRL // Se la macro CONGCTRL è definita, includi i campi per il controllo della congestione
    unsigned int ssthreshold;           // Soglia di slow start
    unsigned int rtt_e;                 // Stima del RTT (Round Trip Time)
    unsigned int Drtt_e;                // Deviazione media del RTT
    unsigned int cong_st;               // Stato del controllo di congestione (SLOW_START, CONG_AVOID, FAST_RECOV)
    unsigned int last_ack;              // Ultimo ACK ricevuto (in network byte order)
    unsigned int repeated_acks;         // Contatore di ACK duplicati
    unsigned int flightsize;            // Dimensione dei dati in volo (non ancora ACKati)
    unsigned int cgwin;                 // Finestra di congestione (congestion window)
    unsigned int lta;                   // Limited Transmit Allowance (per trasmissione limitata)
#endif
};

// Struttura che mappa i file descriptor ai TCB e alle informazioni del socket
struct socket_info{
    struct tcpctrlblk * tcb;    // Puntatore al TCB associato (per socket connessi/listening)
    int st;                     // Stato del file descriptor (FREE, TCP_UNBOUND, TCP_BOUND, TCB_CREATED)
    unsigned short l_port;      // Porta locale del socket
    unsigned int l_addr;        // Indirizzo IP locale del socket
    struct tcpctrlblk * tcblist; // Coda di backlog per i socket in ascolto
    int bl;                     // Lunghezza del backlog
}fdinfo[MAX_FD]; // Array di informazioni sui file descriptor

/* Parametri di Controllo Congestione */
#define ALPHA 1         // Parametro per la stima RTT (per smoothed RTT)
#define BETA 4          // Parametro per la stima RTT (per RTT deviation)
#define KRTO 6          // Fattore per il calcolo del RTO (K * RTT_dev)
#define SLOW_START 0    // Stato di controllo congestione: Slow Start
#define CONG_AVOID 1    // Stato di controllo congestione: Congestion Avoidance
#define FAST_RECOV 2    // Stato di controllo congestione: Fast Recovery
#define INIT_CGWIN 1    // Dimensione iniziale della finestra di congestione (in MSS)
#define INIT_THRESH 8   // Soglia iniziale di slow start (in MSS)

#ifdef CONGCTRL
// Funzione FSM per il controllo della congestione
// Gestisce la finestra di congestione (cwnd) e la soglia di slow start (ssthresh)
void congctrl_fsm(struct tcpctrlblk * tcb, int event, struct tcp_segment * tcp,int streamsegmentsize){

    if(event == PKT_RCV){ // Se l'evento è un pacchetto ricevuto (ACK)
        //printf(" ACK: %d last ACK: %d\n",htonl(tcp->ack)-tcb->seq_offs, htonl(tcb->last_ack)-tcb->seq_offs); // Rimosso commento
        switch( tcb->cong_st ){ // In base allo stato corrente del controllo congestione

        case SLOW_START : // Stato di Slow Start
            // Quando GRO (Generic Receive Offload) è attivo, tcb->cgwin += (htonl(tcp->ack)-htonl(tcb->last_ack));
            tcb->cgwin += tcb->mss; // Aumenta la finestra di congestione di 1 MSS per ogni ACK ricevuto
            if(tcb->cgwin > tcb->ssthreshold) { // Se cwnd supera ssthresh
                tcb->cong_st = CONG_AVOID; // Passa a Congestion Avoidance
                printf(" SLOW START->CONG AVOID\n");
                tcb->repeated_acks = 0; // Azzera il contatore di ACK duplicati
            }
            break;

        case CONG_AVOID: // Stato di Congestion Avoidance
            // Logica per gestire ACK duplicati e Limited Transmit (RFC 3042)
            if((((tcp->flags)&(SYN|FIN))==0) &&  streamsegmentsize==0 && (htons(tcp->window) == tcb->radwin) && (tcp->ack == tcb->last_ack))
                if( tcp->ack == tcb->last_ack)
                    tcb->repeated_acks++; // Incrementa il contatore di ACK duplicati

            printf(" REPEATED ACKS = %d (flags=0x%.2x streamsgmsize=%d, tcp->win=%d radwin=%d tcp->ack=%d tcb->lastack=%d)\n",tcb->repeated_acks,tcp->flags,streamsegmentsize,htons(tcp->window), tcb->radwin,htonl(tcp->ack),htonl(tcb->last_ack));

            if((tcb->repeated_acks == 1 ) || ( tcb->repeated_acks == 2)){ // Primo o secondo ACK duplicato
                if (tcb->flightsize<=tcb->cgwin + 2* (tcb->mss))
                    tcb->lta = tcb->repeated_acks+2*tcb->mss; // Permette trasmissione limitata (extra-TX-win)
            }
            else if (tcb->repeated_acks == 3){ // Terzo ACK duplicato (Fast Retransmit/Recovery)
                printf(" THIRD ACK...\n");
                if(tcb->txfirst!= NULL){
                    // ssthresh = max (FlightSize / 2, 2*SMSS)
                    tcb->ssthreshold = MAX(tcb->flightsize/2,2*tcb->mss);
                    tcb->cgwin = tcb->ssthreshold + 3*tcb->mss; /* Il terzo incremento è nello stato FAST_RECOV */

                    // Ritrasmetti il segmento perso (SND.UNA) immediatamente
                    unsigned int shifter = MIN(htonl(tcb->txfirst->segment->seq),htonl(tcb->txfirst->segment->ack));
                    if(htonl(tcb->txfirst->segment->seq)-shifter <= (htonl(tcp->ack)-shifter))
                        tcb->txfirst->txtime = 0; // Ritrasmissione immediata
                    printf(" FAST RETRANSMIT....\n");
                    tcb->cong_st=FAST_RECOV; // Passa a Fast Recovery
                    printf(" CONG AVOID-> FAST_RECOVERY\n");
                }
            }
            else { // Congestion Avoidance "normale" (senza ACK duplicati significativi)
                // tcb->cgwin += (htonl(tcb->last_ack)-htonl(tcp->ack))*(htonl(tcb->last_ack)-htonl(tcp->ack))/tcb->cgwin (quando GRO è attivo)
                tcb->cgwin += (tcb->mss)*(tcb->mss)/tcb->cgwin; // Aumenta cwnd in modo additivo
                if (tcb->cgwin<tcb->mss) tcb->cgwin = tcb->mss; // cwnd non può essere meno di 1 MSS
            }
            break;

        case FAST_RECOV: // Stato di Fast Recovery
            if(tcb->last_ack==tcp->ack) { // Se è un altro ACK duplicato
                tcb->cgwin += tcb->mss; // Incrementa cwnd di 1 MSS per ogni ACK duplicato aggiuntivo
                printf(" Increasing congestion window to : %d\n", tcb->cgwin);
            }
            else { // Se è un ACK "nuovo" (che ACKa dati precedentemente non ACKati)
                tcb->cgwin = tcb->ssthreshold; // "Sgonfia" la finestra (setta cwnd a ssthresh)
                tcb->cong_st=CONG_AVOID; // Torna a Congestion Avoidance
                printf("FAST_RECOVERY ---> CONG_AVOID\n");
                tcb->repeated_acks=0; // Azzera i contatori
            }
            break;
        }
        tcb->last_ack = tcp->ack; // Aggiorna l'ultimo ACK ricevuto
    }
    else if (event == TIMEOUT) { // Se l'evento è un timeout
        if(tcb->cong_st == CONG_AVOID) tcb->ssthreshold= MAX(tcb->flightsize/2,2*tcb->mss); // Se Congestion Avoidance, ssthresh = FlightSize / 2
        if(tcb->cong_st == FAST_RECOV) tcb->ssthreshold=MAX(tcb->mss,tcb->ssthreshold/=2); // Se Fast Recovery, ssthresh = ssthresh / 2
        if(tcb->cong_st == SLOW_START) tcb->ssthreshold=MAX(tcb->mss,tcb->ssthreshold/=2); // Se Slow Start, ssthresh = ssthresh / 2
        tcb->cgwin = INIT_CGWIN* tcb->mss; // Resetta cwnd a 1 MSS
        tcb->timeout = MIN( MAXRTO, tcb->timeout*2); // Raddoppia il RTO (backoff esponenziale)
        tcb->rtt_e = 0; /* RFC 6298 Note 2 page 6 */ // Resetta la stima RTT
        printf(" TIMEOUT: --->SLOW_START\n");
        tcb->cong_st = SLOW_START; // Torna a Slow Start
    }
}

// Funzione per stimare il Round Trip Time (RTT) e aggiornare il Retransmission Timeout (RTO)
void rtt_estimate(struct tcpctrlblk * tcb, struct txcontrolbuf * node ){
    if(node->retry==1){ // Solo se il segmento non è stato ritrasmesso (Karn's Algorithm)
        int rtt = tick - node->txtime; // Calcola l'RTT per questo segmento
        printf("%.7ld: RTT:%d RTTE:%d DRTTE:%d TIMEOUT:%lld",rtclock(0),rtt*1000/TIMER_USECS,tcb->rtt_e*1000/TIMER_USECS, tcb->Drtt_e*1000/TIMER_USECS,tcb->timeout*1000/TIMER_USECS);
        if (tcb->rtt_e == 0) { // Prima stima
            tcb->rtt_e = rtt;
            tcb->Drtt_e = rtt/2;
        }
        else{ // Stima smoothed RTT e deviazione (Jacobson's algorithm)
            tcb->Drtt_e = ((8-BETA)*tcb->Drtt_e + BETA*abs(rtt-tcb->rtt_e))>>3; // Drtt_e = (1-beta)*Drtt_e + beta*|RTT_sample - RTT_e|
            tcb->rtt_e = ((8-ALPHA)*tcb->rtt_e + ALPHA*rtt)>>3; // RTT_e = (1-alpha)*RTT_e + alpha*RTT_sample
        }
        // Calcola il nuovo RTO
        tcb->timeout = MIN(MAX(tcb->rtt_e + KRTO*tcb->Drtt_e,300*1000/TIMER_USECS),MAXRTO);
        printf("---> RTT:%d RTTE:%d DRTTE:%d TIMEOUT:%lld\n",rtt*1000/TIMER_USECS,tcb->rtt_e*1000/TIMER_USECS, tcb->Drtt_e*1000/TIMER_USECS,tcb->timeout*1000/TIMER_USECS);
    }
}
#endif // CONGCTRL

// Funzione per preparare un segmento TCP per la trasmissione
// Alloca un txcontrolbuf e un tcp_segment, li popola e li aggiunge alla coda di trasmissione
int prepare_tcp(int s, unsigned char flags, unsigned char * payload, int payloadlen,unsigned char * options, int optlen){
    struct tcpctrlblk *t = fdinfo[s].tcb; // TCB associato al socket
    struct tcp_segment * tcp;
    // Alloca una nuova struttura di controllo per la trasmissione
    struct txcontrolbuf * txcb = (struct txcontrolbuf*) malloc(sizeof( struct txcontrolbuf));

    txcb->txtime = -MAXTIMEOUT ; // Inizializza il tempo di trasmissione per attivare la prima trasmissione
    txcb->payloadlen = payloadlen; // Lunghezza del payload dati
    txcb->totlen = payloadlen + 20+optlen; // Lunghezza totale del segmento (20 byte di header TCP + payload + opzioni)
    txcb->retry = 0; // Nessun tentativo di ritrasmissione ancora

    // Alloca il segmento TCP
    tcp = txcb->segment = (struct tcp_segment *) malloc(sizeof(struct tcp_segment));

    tcp->s_port = fdinfo[s].l_port ; // Porta sorgente (locale)
    tcp->d_port = t->r_port;       // Porta destinazione (remota)
    if( t->r_port == 0 ) // Controllo per porta remota invalida (debug)
        ;//printf("Illegal Packet...\n");
    tcp->seq = htonl(t->seq_offs+t->sequence); // Numero di sequenza (offset + sequenza corrente)
    tcp->d_offs_res=(5+optlen/4) << 4; // Data Offset (5 word per header base, + opzioni)
    tcp->flags=flags&0x3F; // Flag TCP (mascherati per sicurezza)
    tcp->urgp=0; // Puntatore urgente a 0

    if(options!=NULL)
        memcpy(tcp->payload,options,optlen); // Copia le opzioni TCP (es. MSS)
    if(payload != NULL)
        memcpy(tcp->payload+(optlen/4)*4,payload,payloadlen); // Copia il payload dati

    txcb->next=NULL; // Inizializza il puntatore al prossimo segmento
    // Aggiunge il segmento alla coda di trasmissione del TCB
    if(t->txfirst == NULL) { t->txlast = t->txfirst = txcb;}
    else {t->txlast->next = txcb; t->txlast = t->txlast->next; }

    printf("%.7ld: Packet seq inserted %d:%d\n",rtclock(0),t->sequence, t->sequence+payloadlen);
    t->sequence += payloadlen; // Aggiorna il numero di sequenza locale per il prossimo invio

    // I campi ack, window e checksum vengono aggiornati in update_tcp_header prima dell'invio
    //tcp->ack;
    //tcp->window;
    //tcp->checksum=0;
    return 0; // Successo
}

// Funzione per risolvere un indirizzo MAC tramite ARP
// Invia una richiesta ARP e attende la risposta, aggiornando la cache ARP
int resolve_mac(unsigned int destip, unsigned char * destmac)
{
    int len,n,i;
    clock_t start; // Per misurare il tempo di attesa della risposta ARP
    unsigned char pkt[1500]; // Buffer per il pacchetto ARP
    struct ethernet_frame *eth; // Puntatore al frame Ethernet
    struct arp_packet *arp;     // Puntatore al pacchetto ARP

    // Cerca nella cache ARP
    for(i=0;i<MAX_ARP && (arpcache[i].key!=0);i++)
        if(!memcmp(&arpcache[i].key,&destip,4)) break;
    if(arpcache[i].key){ // Se trovato nella cache, copia il MAC e ritorna
        memcpy(destmac,arpcache[i].mac,6);
        return 0;
    }

    // Se non trovato, forgia e invia una richiesta ARP
    eth = (struct ethernet_frame *) pkt;
    arp = (struct arp_packet *) eth->payload;
    // Indirizzo MAC di destinazione Broadcast (FF:FF:FF:FF:FF:FF)
    for(i=0;i<6;i++) eth->dstmac[i]=0xff;
    // Indirizzo MAC sorgente locale
    for(i=0;i<6;i++) eth->srcmac[i]=mymac[i];
    eth->type=htons(0x0806); // EtherType per ARP

    arp->htype=htons(1);       // Hardware type: Ethernet (1)
    arp->ptype=htons(0x0800);  // Protocol type: IPv4 (0x0800)
    arp->hlen=6;             // Hardware address length: 6 bytes (MAC)
    arp->plen=4;             // Protocol address length: 4 bytes (IP)
    arp->op=htons(1);        // Operation: ARP Request (1)
    for(i=0;i<6;i++) arp->srcmac[i]=mymac[i]; // MAC sorgente
    for(i=0;i<4;i++) arp->srcip[i]=myip[i]; // IP sorgente
    for(i=0;i<6;i++) arp->dstmac[i]=0; // MAC destinazione (sconosciuto)
    for(i=0;i<4;i++) arp->dstip[i]=((unsigned char*) &destip)[i]; // IP destinazione

    // Invia il pacchetto ARP raw sull'interfaccia
    bzero(&sll,sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    len = sizeof(sll);
    n=sendto(unique_s,pkt,14+sizeof(struct arp_packet), 0,(struct sockaddr *)&sll,len);
    fl--; // Decrementa il flag di sovrapposizione per la pausa (permettere ad altri segnali di essere gestiti)

    // Blocca i segnali SIGALRM per evitare interruzioni del timer durante l'attesa ARP
    sigset_t tmpmask=mymask;
    if( -1 == sigdelset(&tmpmask, SIGALRM)){perror("Sigaddset");return 1;} // Rimuovi SIGALRM dalla maschera
    sigprocmask(SIG_UNBLOCK,&tmpmask,NULL); // Sblocca tutti tranne SIGIO (per la risposta ARP)

    start=clock(); // Inizia il timer per l'attesa ARP
    while(pause()){ // Entra in pausa e attende un segnale
        // Controlla di nuovo la cache ARP dopo ogni segnale ricevuto (es. risposta ARP)
        for(i=0;(i<MAX_ARP) && (arpcache[i].key!=0);i++)
            if(!memcmp(&arpcache[i].key,&destip,4)) break;
        if(arpcache[i].key){ // Se trovato, copia il MAC e esce
            memcpy(destmac,arpcache[i].mac,6);
            sigprocmask(SIG_BLOCK,&tmpmask,NULL); // Ripristina la maschera di segnali
            fl++; // Incrementa il flag di sovrapposizione
            return 0; // Risolto
        }
        // Se il timeout per ARP è scaduto, esce
        if ((clock()-start) > CLOCKS_PER_SEC/100) break; // 10 ms di timeout
    }
    sigprocmask(SIG_BLOCK,&tmpmask,NULL); // Ripristina la maschera di segnali
    fl++;
    return -1 ; // Non risolto
}

// Funzione per aggiornare l'header TCP prima dell'invio
// Calcola ACK, Window e Checksum
void update_tcp_header(int s, struct txcontrolbuf *txctrl){
    struct tcpctrlblk * tcb  = fdinfo[s].tcb; // TCB associato al socket
    struct pseudoheader pseudo; // Pseudo-header per il checksum TCP

    // Popola la pseudo-header
    pseudo.s_addr = fdinfo[s].l_addr; // Indirizzo IP sorgente (locale)
    pseudo.d_addr = tcb->r_addr;     // Indirizzo IP destinazione (remota)
    pseudo.zero = 0;                 // Byte a zero
    pseudo.prot = 6;                 // Protocollo TCP (6)
    pseudo.len = htons(txctrl->totlen); // Lunghezza del segmento TCP (header + payload)

    txctrl->segment->checksum = htons(0); // Inizializza checksum a 0 per il calcolo
    txctrl->segment->ack = htonl(tcb->ack_offs + tcb->cumulativeack); // Numero di ACK (offset + ACK cumulativo)
    txctrl->segment->window = htons(tcb->adwin); // Finestra di ricezione pubblicizzata
    // Calcola il checksum finale del segmento TCP (usando pseudo-header e segmento TCP)
    txctrl->segment->checksum = htons(checksum2((unsigned char*)&pseudo, 12, (unsigned char*) txctrl->segment, txctrl->totlen));
}

// Implementazione semplificata della funzione `socket()`
int mysocket(int family, int type, int proto)
{
    int i;
    // Supporta solo AF_INET (IPv4) e SOCK_STREAM (TCP)
    if (( family == AF_INET ) && (type == SOCK_STREAM) && (proto ==0)){
        // Cerca un file descriptor libero (dal 3 in su, per lasciare 0, 1, 2 a stdin/stdout/stderr)
        for(i=3; i<MAX_FD && fdinfo[i].st!=FREE;i++);
        if(i==MAX_FD) {myerrno = ENFILE; return -1;} // Nessun file descriptor libero
        else {
            bzero(fdinfo+i, sizeof(struct socket_info)); // Inizializza la struttura
            fdinfo[i].st = TCP_UNBOUND; // Imposta lo stato a UNBOUND
            myerrno = 0; // Nessun errore
            return i; // Restituisce il file descriptor
        }
    }else {myerrno = EINVAL; return -1; } // Argomenti non validi
}

int last_port=MIN_PORT; // Ultima porta assegnata per la ricerca di porte libere

// Controlla se una porta è già in uso
int port_in_use( unsigned short port ){
    int s;
    for ( s=3; s<MAX_FD; s++)
        if (fdinfo[s].st != FREE && fdinfo[s].st!=TCP_UNBOUND)
            if(fdinfo[s].l_port == port)
                return 1; // Porta in uso
    return 0; // Porta libera
}

// Ottiene una porta locale libera automaticamente
unsigned short int get_free_port()
{
    unsigned short p;
    // Cerca dal last_port in su
    for ( p = last_port; p<MAX_PORT && port_in_use(p); p++);
    if (p<MAX_PORT) return last_port=p; // Trovata
    // Se non trovata in avanti, cerca dall'inizio (MIN_PORT) fino a last_port
    for ( p = MIN_PORT; p<last_port && port_in_use(p); p++);
    if (p<last_port) return last_port=p; // Trovata
    return 0; // Nessuna porta libera trovata
}

// Implementazione semplificata della funzione `bind()`
int mybind(int s, struct sockaddr * addr, int addrlen){
    if((addr->sa_family == AF_INET)){ // Solo AF_INET (IPv4)
        struct sockaddr_in * a = (struct sockaddr_in*) addr;
        if ( s >= 3 && s<MAX_FD){ // File descriptor valido
            if(fdinfo[s].st != TCP_UNBOUND){myerrno = EINVAL; return -1;} // Deve essere UNBOUND
            // Se una porta specifica è richiesta e in uso
            if(a->sin_port && port_in_use(a->sin_port)) {myerrno = EADDRINUSE; return -1;}
            // Assegna la porta (se 0, ottiene una porta libera)
            fdinfo[s].l_port = (a->sin_port)?a->sin_port:get_free_port();
            if(fdinfo[s].l_port == 0 ) {myerrno = ENOMEM; return -1;} // Nessuna porta libera
            // Assegna l'indirizzo IP locale (se 0, usa l'IP predefinito)
            fdinfo[s].l_addr = (a->sin_addr.s_addr)?a->sin_addr.s_addr:*(unsigned int*)myip;
            fdinfo[s].st = TCP_BOUND; // Imposta lo stato a BOUND
            myerrno = 0;
            return 0;
        }
        else { myerrno = EBADF ; return -1;} // File descriptor non valido
    }
    else { myerrno = EINVAL; return -1; } // Famiglia di indirizzi non valida
}

// Funzione FSM (Finite State Machine) per la gestione degli stati TCP
// `s`: socket file descriptor
// `event`: evento che triggera la transizione (APP_ACTIVE_OPEN, PKT_RCV, TIMEOUT, APP_CLOSE)
// `ip`: puntatore al datagramma IP ricevuto (se `event` è PKT_RCV)
int fsm(int s, int event, struct ip_datagram * ip)
{
    struct tcpctrlblk * tcb = fdinfo[s].tcb; // Ottiene il TCB associato
    printf("%.7ld: FSM: Socket: %d Curr-State =%d, Input=%d \n",rtclock(0),s,tcb->st,event);
    struct tcp_segment * tcp;
    int i;
    // Se è un pacchetto ricevuto, ottiene il puntatore al segmento TCP
    if(ip != NULL)
        tcp = (struct tcp_segment * )((char*)ip+((ip->ver_ihl&0xF)*4)); // Payload IP inizia dopo l'header IP

    switch(tcb->st){ // Switch sullo stato corrente del TCB

        case TCP_CLOSED: // Stato CLOSED
            if(event == APP_ACTIVE_OPEN) { // Richiesta di apertura attiva (client)
                tcb->rxbuffer = (unsigned char*) malloc(RXBUFSIZE); // Alloca buffer di ricezione
                tcb->txfree = TXBUFSIZE; // Inizializza spazio libero nel buffer di trasmissione
                tcb->seq_offs=rand(); // Genera numero di sequenza iniziale casuale
                tcb->ack_offs=0; // Inizializza offset ACK
                tcb->stream_end=0xFFFFFFFF; // Fine dello stream non definita
                tcb->mss = TCP_MSS; // MSS predefinito
                tcb->sequence=0; // Numero di sequenza iniziale
                tcb->rx_win_start=0; // Inizio finestra di ricezione
                tcb->cumulativeack =0; // ACK cumulativo
                tcb->timeout = INIT_TIMEOUT; // Timeout iniziale
                tcb->adwin =RXBUFSIZE; // Finestra pubblicizzata locale
                tcb->radwin =RXBUFSIZE; // Finestra pubblicizzata remota

#ifdef CONGCTRL // Inizializzazione per il controllo della congestione
                tcb->ssthreshold = INIT_THRESH * TCP_MSS;
                tcb->cgwin = INIT_CGWIN* TCP_MSS;
                tcb->timeout = INIT_TIMEOUT;
                tcb->rtt_e = 0;
                tcb->Drtt_e = 0;
                tcb->cong_st = SLOW_START;
#endif
                prepare_tcp(s,SYN,NULL,0,mssopt,sizeof(mssopt)); // Prepara e aggiunge un segmento SYN con opzione MSS
                tcb->st = SYN_SENT; // Passa allo stato SYN_SENT
            }
            break;

        case SYN_SENT: // Stato SYN_SENT
            if(event == PKT_RCV){ // Pacchetto ricevuto
                // Se è un SYN-ACK e l'ACK è corretto (seq_offs + 1)
                if((tcp->flags&SYN) && (tcp->flags&ACK) && (htonl(tcp->ack)==tcb->seq_offs + 1)){
                    tcb->seq_offs ++; // Aggiorna seq_offs (per includere il SYN ACKato)
                    tcb->ack_offs = htonl(tcp->seq) + 1; // Imposta ack_offs (basato sul numero di sequenza remoto)
                    free(tcb->txfirst->segment); // Libera il segmento SYN inviato
                    free(tcb->txfirst);
                    tcb->txfirst = tcb->txlast = NULL; // Azzera la coda di trasmissione
                    prepare_tcp(s,ACK,NULL,0,NULL,0); // Prepara e aggiunge un segmento ACK
                    tcb->st = ESTABLISHED; // Passa allo stato ESTABLISHED
                }
            }
            break;

        case ESTABLISHED: // Stato ESTABLISHED
            if(event == PKT_RCV && (tcp->flags&FIN)) // Se riceve un FIN
                tcb->st = CLOSE_WAIT; // Passa allo stato CLOSE_WAIT
            else if(event == APP_CLOSE ){ // Se l'applicazione richiede la chiusura
                prepare_tcp(s,FIN|ACK,NULL,0,NULL,0); // Prepara e invia un FIN-ACK
                tcb->st = FIN_WAIT_1; // Passa allo stato FIN_WAIT_1
            }
            break;

        case  CLOSE_WAIT: // Stato CLOSE_WAIT
            if(event == APP_CLOSE ){ // Se l'applicazione richiede la chiusura
                prepare_tcp(s,FIN|ACK,NULL,0,NULL,0); // Prepara e invia un FIN-ACK
                tcb->st = LAST_ACK; // Passa allo stato LAST_ACK
            }
            break;

        case LAST_ACK: // Stato LAST_ACK
            if((event == PKT_RCV) && (tcp->flags&ACK) ){ // Se riceve un ACK
                // Se l'ACK è corretto (conferma del FIN inviato)
                if(htonl(tcp->ack) == (tcb->seq_offs + tcb->sequence + 1)){
                    tcb->st = TCP_CLOSED; // Passa allo stato TCP_CLOSED
                    tcb->txfirst = tcb->txlast = NULL; // Azzera la coda di trasmissione
                }
            }
            break;

        case LISTEN: // Stato LISTEN (server)
            if((event == PKT_RCV) && ((tcp->flags)&SYN)){ // Se riceve un SYN
                tcb->rxbuffer=(unsigned char*)malloc(RXBUFSIZE); // Alloca buffer di ricezione per la nuova connessione
                tcb->seq_offs=rand(); // Genera seq_offs per la nuova connessione
                tcb->txfree = TXBUFSIZE;
                tcb->ack_offs=htonl(tcp->seq)+1; // Imposta ack_offs in base al SYN ricevuto
                tcb->r_port = tcp->s_port; // Porta remota
                tcb->r_addr = ip->srcaddr; // Indirizzo IP remoto
                tcb->rx_win_start=0;
                tcb->cumulativeack=0;
                tcb->adwin=RXBUFSIZE;
                tcb->radwin=RXBUFSIZE;
                tcb->mss=TCP_MSS;
                tcb->timeout = INIT_TIMEOUT;

#ifdef CONGCTRL // Inizializzazione per il controllo della congestione
                tcb->ssthreshold = INIT_THRESH * TCP_MSS;
                tcb->cgwin = INIT_CGWIN * TCP_MSS;
                tcb->timeout = INIT_TIMEOUT;
                tcb->rtt_e = 0;
                tcb->Drtt_e = 0;
                tcb->cong_st = SLOW_START;
#endif
                prepare_tcp(s,SYN|ACK,NULL,0,mssopt,sizeof(mssopt)); // Prepara e invia un SYN-ACK
                tcb->st = SYN_RECEIVED; // Passa allo stato SYN_RECEIVED
            }
            break;

        case SYN_RECEIVED: // Stato SYN_RECEIVED
            if(((event == PKT_RCV) && ((tcp->flags)&ACK)) &&!((tcp->flags)&SYN)){ // Se riceve un ACK (e non SYN)
                // Se l'ACK è corretto (conferma del SYN-ACK inviato)
                if(htonl(tcp->ack) == tcb->seq_offs + 1){
                    free(tcb->txfirst->segment); // Libera il SYN-ACK inviato
                    free(tcb->txfirst);
                    tcb->seq_offs++; // Aggiorna seq_offs
                    tcb->txfirst = tcb->txlast = NULL; // Azzera la coda di trasmissione

                    // Questo `ack_offs` qui è probabilmente un errore logico o una particolarità
                    // della gestione del seq/ack per i server.
                    // Generalmente, `ack_offs` dovrebbe essere impostato una volta e usato come base.
                    tcb->ack_offs=htonl(tcp->seq); // Imposta ack_offs (basato sul numero di sequenza remoto)

                    // Cerca uno slot libero nel backlog del socket di ascolto
                    for(i=0;i<fdinfo[s].bl && fdinfo[s].tcblist[i].st!=FREE;i++);
                    if (fdinfo[s].tcblist[i].st!=FREE)
                        prepare_tcp(s,RST,NULL,0,NULL,0); // Backlog pieno, invia RST
                    else {
                        // Copia il TCB corrente (che è il TCB del socket di ascolto) nello slot del backlog
                        // E imposta lo stato a ESTABLISHED per la nuova connessione
                        fdinfo[s].tcblist[i]=*tcb;
                        fdinfo[s].tcblist[i].st = ESTABLISHED;
                    }
                    // "Scollega" il TCB del socket di ascolto dalla connessione appena stabilita
                    // Questo permette al socket di ascolto di tornare nello stato LISTEN per accettare nuove connessioni
                    tcb->r_port = 0;
                    tcb->r_addr = 0;
                    tcb->st = LISTEN; // Torna allo stato LISTEN
                }
            }
            break;

        case FIN_WAIT_1: // Stato FIN_WAIT_1
            if((event == PKT_RCV) && ((tcp->flags)&FIN)){ // Se riceve un FIN
                tcb->st = CLOSING; // Passa allo stato CLOSING
                // L'ACK del FIN sarà inviato cumulativamente
            }
            else if((event == PKT_RCV)&&((tcp->flags)&ACK)) // Se riceve un ACK
                if(htonl(tcp->ack) == tcb->seq_offs + tcb->sequence + 1) // Se è l'ACK del nostro FIN
                    tcb->st = FIN_WAIT_2; // Passa allo stato FIN_WAIT_2
            break;

        case FIN_WAIT_2: // Stato FIN_WAIT_2
            if((event == PKT_RCV) && ((tcp->flags)&FIN)){ // Se riceve un FIN
                tcb->fsm_timer = tick + tcb->timeout *4; // Imposta il timer per TIME_WAIT (2MSL)
                tcb->st = TIME_WAIT; // Passa allo stato TIME_WAIT
                // Libera i segmenti in coda di trasmissione (ormai non più necessari)
                while(tcb->txfirst!=NULL){
                    struct txcontrolbuf * tmp = tcb->txfirst;
                    tcb->txfirst = tcb->txfirst->next;
                    free(tmp->segment); // Libera il segmento TCP
                    free(tmp);         // Libera la struttura di controllo
                }
            }
            break;

        case CLOSING: // Stato CLOSING
            if((event == PKT_RCV)&&((tcp->flags)&ACK)) // Se riceve un ACK (che ACKa il nostro FIN)
                if(htonl(tcp->ack) == tcb->seq_offs + tcb->sequence + 1){
                    tcb->fsm_timer = tick + tcb->timeout *4; // Imposta il timer per TIME_WAIT (2MSL)
                    tcb->st = TIME_WAIT; // Passa allo stato TIME_WAIT
                    // Libera i segmenti in coda di trasmissione
                    while(tcb->txfirst!=NULL){
                        struct txcontrolbuf * tmp = tcb->txfirst;
                        tcb->txfirst = tcb->txfirst->next;
                        free(tmp->segment);
                        free(tmp);
                    }
                }
            break;

        case TIME_WAIT: // Stato TIME_WAIT
            if(event == TIMEOUT){ // Se il timer di TIME_WAIT scade
                // Libera tutte le strutture associate al TCB
                while(tcb->unack!=NULL){ // Libera i segmenti ricevuti fuori ordine
                    struct rxcontrol * tmp = tcb->unack;
                    tcb->unack = tcb->unack->next;
                    free(tmp);
                }
                free(tcb->rxbuffer); // Libera il buffer di ricezione
                free(fdinfo[s].tcb); // Libera il TCB
                bzero(fdinfo+s,sizeof(struct socket_info)); // Azzera la struttura socket_info
                fdinfo[s].st=FREE; // Imposta lo stato del file descriptor a FREE
            }
            break;
    }
    printf("%.7ld: FSM: Socket: %d Next:State =%d, Input=%d \n",rtclock(0),s,tcb->st,event);
    return 0; // Successo
}

// Implementazione semplificata della funzione `connect()`
int myconnect(int s, struct sockaddr * addr, int addrlen){
    if((addr->sa_family == AF_INET)){ // Solo AF_INET (IPv4)
        struct sockaddr_in * a = (struct sockaddr_in*) addr;
        struct sockaddr_in local;
        if ( s >= 3 && s<MAX_FD){ // File descriptor valido
            if(fdinfo[s].st == TCP_UNBOUND){ // Se il socket non è ancora bindato, effettua un bind implicito
                local.sin_port=htons(0); // Porta dinamica
                local.sin_addr.s_addr = htonl(0); // IP locale predefinito
                local.sin_family = AF_INET;
                if(-1 == mybind(s,(struct sockaddr *) &local, sizeof(struct sockaddr_in)))     {myperror("implicit binding failed\n"); return -1; }
            }
            if(fdinfo[s].st == TCP_BOUND){ // Se il socket è bindato
                fdinfo[s].tcb = (struct tcpctrlblk *) malloc(sizeof(struct tcpctrlblk)); // Alloca un nuovo TCB
                bzero(fdinfo[s].tcb, sizeof(struct tcpctrlblk)); // Inizializza il TCB
                fdinfo[s].st = TCB_CREATED; // Imposta lo stato del file descriptor a TCB_CREATED
                fdinfo[s].tcb->st = TCP_CLOSED; // Imposta lo stato del TCB a TCP_CLOSED
                fdinfo[s].tcb->r_port = a->sin_port; // Imposta la porta remota
                fdinfo[s].tcb->r_addr = a->sin_addr.s_addr; // Imposta l'indirizzo IP remoto
                printf("%.7ld: Reset clock\n",rtclock(1)); // Resetta il clock per misurare il tempo di connessione
                fsm(s,APP_ACTIVE_OPEN,NULL); // Inizia la FSM TCP con l'evento APP_ACTIVE_OPEN
            } else {myerrno = EBADF; return -1; } // File descriptor in stato non valido
            // Attende che la connessione sia stabilita o fallisca
            while(sleep(10)){ // Utilizza sleep(10) che verrà interrotto dai segnali SIGIO/SIGALRM
                if(fdinfo[s].tcb->st == ESTABLISHED ) return 0; // Connessione stabilita
                if(fdinfo[s].tcb->st == TCP_CLOSED ){ myerrno = ECONNREFUSED; return -1;} // Connessione rifiutata
            }
            myerrno=ETIMEDOUT; return -1; // Timeout della connessione
        }
        else { myerrno = EBADF; return -1; } // File descriptor non valido
    }
    else { myerrno = EINVAL; return -1; } // Famiglia di indirizzi non valida
}

// Implementazione semplificata della funzione `write()`
int mywrite(int s, unsigned char * buffer, int maxlen){
    int len,totlen=0,j,actual_len;
    // Verifica lo stato del socket e del TCB
    if(fdinfo[s].st != TCB_CREATED || fdinfo[s].tcb->st != ESTABLISHED ){ myerrno = EINVAL; return -1; }
    if(maxlen == 0) return 0; // Non c'è nulla da scrivere

    do{
        actual_len = MIN(maxlen,fdinfo[s].tcb->txfree); // Calcola la quantità di dati da inviare (minimo tra richiesto e spazio libero)
        if ((actual_len !=0) || (fdinfo[s].tcb->st == TCP_CLOSED)) break; // Se c'è spazio o la connessione è chiusa, esci
    }while(pause()); // Altrimenti, metti in pausa e attendi eventi (es. ACK che liberano spazio)

    // Suddivide i dati in segmenti di dimensione MSS e li aggiunge alla coda di trasmissione
    for(j=0;j<actual_len; j+=fdinfo[s].tcb->mss){
        len = MIN(fdinfo[s].tcb->mss, actual_len-j); // Dimensione del segmento corrente
        if(-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)){perror("sigprocmask"); return -1 ;} // Blocca i segnali durante la manipolazione della coda TX
        prepare_tcp(s,ACK,buffer+j,len,NULL,0); // Prepara un segmento TCP con i dati e flag ACK
        if(-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return -1 ;} // Sblocca i segnali
        fdinfo[s].tcb->txfree -= len; // Aggiorna lo spazio libero nel buffer di trasmissione
        totlen += len; // Aggiorna i byte totali inviati
    }
    return totlen; // Restituisce i byte effettivamente inviati
}

// Implementazione semplificata della funzione `read()`
int myread(int s, unsigned char *buffer, int maxlen)
{
    int j,actual_len;
    // Verifica lo stato del socket e del TCB
    if((fdinfo[s].st != TCB_CREATED) || (fdinfo[s].tcb->st < ESTABLISHED )){ myerrno = EINVAL; return -1; }
    if (maxlen==0) return 0; // Nulla da leggere

    // Calcola la quantità di dati disponibili nel buffer di ricezione
    actual_len = MIN(maxlen,fdinfo[s].tcb->cumulativeack - fdinfo[s].tcb->rx_win_start);
    // Se è stata ricevuta la fine dello stream (FIN), decrementa la lunghezza (il FIN "consuma" 1 byte logico)
    if(fdinfo[s].tcb->cumulativeack > fdinfo[s].tcb->stream_end) actual_len --;

    if(actual_len==0){ // Se non ci sono dati disponibili immediatamente
        while(pause()){ // Metti in pausa e attendi eventi (es. arrivo di nuovi dati)
            actual_len = MIN(maxlen,fdinfo[s].tcb->cumulativeack - fdinfo[s].tcb->rx_win_start);
            if(actual_len>0 && (fdinfo[s].tcb->cumulativeack > fdinfo[s].tcb->stream_end)) actual_len --;
            if(actual_len!=0) break; // Dati disponibili, esci
            // Se la finestra di ricezione è alla fine dello stream e non ci sono più dati da leggere
            if(fdinfo[s].tcb->rx_win_start)
                if(fdinfo[s].tcb->rx_win_start==fdinfo[s].tcb->stream_end) {return 0;}
            // Se il socket è in CLOSE_WAIT e non ci sono segmenti non ACKati nel buffer, la lettura è finita
            if ((fdinfo[s].tcb->st == CLOSE_WAIT) && (fdinfo[s].tcb->unack == NULL ) ) {return 0;} // FIN received and acknowledged
        }
    }
    // Copia i dati dal buffer di ricezione nel buffer utente
    for(j=0; j<actual_len; j++){
        buffer[j]=fdinfo[s].tcb->rxbuffer[(fdinfo[s].tcb->rx_win_start + j)%RXBUFSIZE];
    }
    fdinfo[s].tcb->rx_win_start+=j; // Aggiorna l'inizio della finestra di ricezione
    return j; // Restituisce i byte letti
}

// Implementazione semplificata della funzione `close()`
int myclose(int s){
    // Verifica lo stato del socket
    if((fdinfo[s].st == TCP_CLOSED) || (fdinfo[s].st == TCP_UNBOUND)) { myerrno = EBADF; return -1;}
    fsm(s,APP_CLOSE,NULL); // Inizia la sequenza di chiusura TCP tramite la FSM
    return 0;
}

// Gestore del segnale SIGALRM (timer periodico)
void mytimer(int number){
    int i,tot,isfasttransmit, karn_invalidate=0;
    struct txcontrolbuf * txcb;
    // Blocca i segnali per evitare race condition
    if(-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)){perror("sigprocmask"); return ;}
    fl++; // Incrementa il flag di sovrapposizione
    tick++; // Incrementa il contatore dei tick

    if (fl > 1) printf("Overlap Timer\n"); // Debugging: indica se il timer si è sovrapposto

    // Itera su tutti i file descriptor per controllare i TCB
    for(i=0;i<MAX_FD;i++){
        if(fdinfo[i].st == TCB_CREATED){ // Se il socket ha un TCB associato
            struct tcpctrlblk * tcb = fdinfo[i].tcb;
            // Controlla i timer specifici della FSM (es. TIME_WAIT)
            if((tcb->fsm_timer!=0 ) && (tcb->fsm_timer < tick)){
                fsm(i,TIMEOUT,NULL); // Triggera l'evento TIMEOUT per la FSM
                continue; // Passa al prossimo socket
            }

#ifdef CONGCTRL // Logica di trasmissione con controllo congestione
            // Itera sui segmenti nella coda di trasmissione, limitando in base a cwnd e Limited Transmit Allowance
            for(tot=0,txcb=tcb->txfirst;  txcb!=NULL && (tot<(tcb->cgwin+tcb->lta)); tot+=txcb->totlen, txcb = txcb->next){
                if(txcb->retry==0) // Se è la prima trasmissione
                    fdinfo[i].tcb->flightsize+=txcb->payloadlen; // Aggiorna la dimensione dei dati in volo
                //else (commentato)
#else // Logica di trasmissione senza controllo congestione (in base a finestra remota, non implementato totalmente)
            for(tot=0,txcb=tcb->txfirst;  txcb!=NULL  /*&& (tot<tcb->radwin)*/;  txcb = txcb->next){
#endif
                if (karn_invalidate) txcb->retry++; // Se un segmento precedente è stato ritrasmesso (algoritmo di Karn)
                if(txcb->txtime+tcb->timeout > tick )  continue; // Se il timeout non è ancora scaduto per questo segmento
                isfasttransmit = (txcb->txtime == 0); // Flag per la ritrasmissione rapida (duplicate ACKs)
                txcb->txtime=tick; // Aggiorna il tempo di ultima trasmissione
                if(!karn_invalidate) txcb->retry ++; // Incrementa il contatore di tentativi (solo se non invalidato da Karn)
                karn_invalidate = (txcb->retry > 1 ); // Se è una ritrasmissione, invalida i prossimi segmenti per RTO
                update_tcp_header(i, txcb); // Aggiorna i campi ACK, Window e Checksum
                send_ip((unsigned char*) txcb->segment, (unsigned char*) &fdinfo[i].tcb->r_addr, txcb->totlen, TCP_PROTO); // Invia il segmento IP
                printf("%.7ld: TX SOCK: %d SEQ:%d:%d ACK:%d Timeout = %lld FLAGS:0x%.2X (%d times)\n",rtclock(0),i,htonl(txcb->segment->seq) - fdinfo[i].tcb->seq_offs,htonl(txcb->segment->seq) - fdinfo[i].tcb->seq_offs+txcb->payloadlen,htonl(txcb->segment->ack) - fdinfo[i].tcb->ack_offs,tcb->timeout*TIMER_USECS/1000,txcb->segment->flags,txcb->retry);
#ifdef CONGCTRL
                if((txcb->retry > 1) &&(tcb->st >= ESTABLISHED) && !isfasttransmit) // Se è una ritrasmissione (non fast retransmit) e la connessione è stabilita
                    congctrl_fsm(tcb,TIMEOUT,NULL,0); // Triggera la FSM di congestione con evento TIMEOUT
                printf(" Thresh: %d TxWin/MSS: %f, ST: %d RTT_E:%d\n",tcb->ssthreshold, tcb->cgwin/(float)tcb->mss,tcb->cong_st,tcb->rtt_e);
#endif
            }
        }
    }
    fl--; // Decrementa il flag di sovrapposizione
    if(-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return ;} // Sblocca i segnali
}

// Funzione helper per stampare la coda dei segmenti ricevuti fuori ordine
void printrxq(struct rxcontrol* n){
    printf(" RXQ: ");
    for( ; n!=NULL; n = n->next)
        printf("(%d %d) ",n->stream_offs, n->streamsegmentsize);
    printf("\n");
}

// Gestore del segnale SIGIO (input/output disponibili sul socket raw)
void myio(int number)
{
    int i,len,size,shifter;
    struct ethernet_frame * eth=(struct ethernet_frame *)l2buffer; // Buffer per il frame Ethernet ricevuto

    // Blocca i segnali per evitare race condition
    if(-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)){perror("sigprocmask"); return ;}
    fl++; // Incrementa il flag di sovrapposizione
    if (fl > 1) ;//printf("Overlap (%d) in myio\n",fl); // Debugging

    // Controlla se ci sono dati disponibili sul socket raw
    if( poll(fds,1,0) == -1) { perror("Poll failed"); return; }
    if (fds[0].revents & POLLIN){ // Se ci sono dati da leggere
        len = sizeof(struct sockaddr_ll);
        // Legge tutti i pacchetti disponibili dal socket raw
        while ( 0 <= (size = recvfrom(unique_s,eth,MAXFRAME,0, (struct sockaddr *) &sll,&len))){
            if(size >1000) ;//printf("Packet %d-bytes received\n",size);
            // Processa i pacchetti ARP
            if (eth->type == htons (0x0806)) { // Se è un pacchetto ARP (EtherType 0x0806)
                struct arp_packet * arp = (struct arp_packet *) eth->payload;
                if(htons(arp->op) == 2){ // Se è una risposta ARP (OpCode 2)
                    // Aggiorna o aggiunge l'entry nella cache ARP
                    for(i=0;(i<MAX_ARP) && (arpcache[i].key!=0);i++)
                        if(!memcmp(&arpcache[i].key,arp->srcip,4)){
                            memcpy(arpcache[i].mac,arp->srcmac,6); // Aggiorna MAC
                            break;
                        }
                    if(arpcache[i].key==0){ // Se non trovato, aggiungi nuova entry
                        ;//printf("New ARP cache entry inserted\n");
                        memcpy(arpcache[i].mac,arp->srcmac,6);
                        memcpy(&arpcache[i].key,arp->srcip,4);
                    }
                }
            } // Fine ARP processing
            // Processa i pacchetti IP
            else if(eth->type == htons(0x0800)){ // Se è un pacchetto IP (EtherType 0x0800)
                struct ip_datagram * ip = (struct ip_datagram *) eth->payload;
                if (ip->proto == TCP_PROTO){ // Se il protocollo IP è TCP (6)
                    struct tcp_segment * tcp = (struct tcp_segment *) ((char*)ip + (ip->ver_ihl&0x0F)*4); // Puntatore al segmento TCP

                    // Cerca il TCB associato alla porta destinazione e sorgente IP/porta del pacchetto
                    for(i=0;i<MAX_FD;i++)
                        if((fdinfo[i].st == TCB_CREATED) && (fdinfo[i].l_port == tcp->d_port)
                            && (tcp->s_port == fdinfo[i].tcb->r_port) && (ip->srcaddr == fdinfo[i].tcb->r_addr))
                            break;
                    if(i==MAX_FD)// Se non trovato in connessioni attive, cerca tra i socket in ascolto
                        for(i=0;i<MAX_FD;i++)
                            if((fdinfo[i].st == TCB_CREATED) &&(fdinfo[i].tcb->st==LISTEN) && (tcp->d_port == fdinfo[i].l_port))
                                break;

                    if(i<MAX_FD) { // Se è stato trovato un TCB corrispondente
                        struct tcpctrlblk * tcb = fdinfo[i].tcb;
                        printf("%.7ld: RX SOCK:%d ACK %d SEQ:%d SIZE:%d FLAGS:0x%.2X\n",rtclock(0),i,htonl(tcp->ack)-tcb->seq_offs,htonl(tcp->seq)-tcb->ack_offs,  htons(ip->totlen) - (ip->ver_ihl&0xF)*4 - (tcp->d_offs_res>>4)*4, tcp->flags);

                        // Simulazione della perdita di pacchetti in ricezione (solo se client 'C')
                        if(!(rand()%INV_LOSS_RATE) && g_argv[4][0]=='C') {printf("========== RX LOST ===============\n");break;}

                        fsm(i,PKT_RCV,ip); // Triggera la FSM TCP con l'evento PKT_RCV
                        if(tcb->st < ESTABLISHED)break; // Se lo stato non è ESTABLISHED, non processare il payload

                        unsigned int streamsegmentsize = htons(ip->totlen) - (ip->ver_ihl&0xF)*4 - (tcp->d_offs_res>>4)*4; // Dimensione payload TCP
                        unsigned int stream_offs = ntohl(tcp->seq)-tcb->ack_offs; // Offset del segmento nello stream
                        unsigned char * streamsegment = ((unsigned char*)tcp)+((tcp->d_offs_res>>4)*4); // Puntatore al payload TCP

                        struct rxcontrol * curr, *newrx, *prev;

                        // Elaborazione degli ACK ricevuti: rimozione dei segmenti ACKati dalla coda di trasmissione
                        if(tcb->txfirst !=NULL){
                            shifter = htonl(tcb->txfirst->segment->seq);
                            // Se l'ACK ricevuto è valido (entro i limiti dei segmenti inviati)
                            if((htonl(tcp->ack)-shifter >= 0) && (htonl(tcp->ack)-shifter-(tcb->stream_end)?1:0 <= htonl(tcb->txlast->segment->seq) + tcb->txlast->payloadlen - shifter)){ // -1 per compensare FIN
                                while((tcb->txfirst!=NULL) && ((htonl(tcp->ack)-shifter) >= (htonl(tcb->txfirst->segment->seq)-shifter + tcb->txfirst->payloadlen))){ // ACK >= Seq + payloadlen
                                    struct txcontrolbuf * temp = tcb->txfirst;
                                    tcb->txfirst = tcb->txfirst->next;
                                    fdinfo[i].tcb->txfree+=temp->payloadlen; // Libera spazio nel buffer TX
#ifdef CONGCTRL
                                    // Se l'ACK corrisponde esattamente a un segmento e non è una ritrasmissione
                                    if(htonl(tcp->ack)-shifter ==(htonl(temp->segment->seq)-shifter + temp->payloadlen))
                                        if(temp->payloadlen!=0) // Se non è un ACK "puro"
                                            if(temp->retry<=1) // Se non è stato ritrasmesso (algoritmo di Karn)
                                                rtt_estimate(tcb,temp); // Stima RTT e aggiorna RTO
                                    fdinfo[i].tcb->flightsize-=temp->payloadlen; // Rimuovi dal flightsize
#endif
                                    free(temp->segment);
                                    free(temp);
                                    if(tcb->txfirst == NULL) tcb->txlast = NULL; // Se la coda è vuota
                                }
#ifdef CONGCTRL
                                congctrl_fsm(tcb,PKT_RCV,tcp,streamsegmentsize); // Triggera la FSM di congestione
#endif
                                tcb->radwin =   htons(tcp->window); // Aggiorna la finestra remota pubblicizzata
                            }
                        }

                        // Elaborazione dei dati ricevuti (gestione dei segmenti fuori ordine)
                        // Se il segmento rientra nella finestra di ricezione
                        if(((stream_offs + streamsegmentsize - tcb->rx_win_start)<RXBUFSIZE)){
                            newrx = (struct rxcontrol *) malloc(sizeof(struct rxcontrol)); // Alloca nuova struttura di controllo
                            newrx->stream_offs = stream_offs; // Offset del segmento
                            newrx->streamsegmentsize = streamsegmentsize; // Dimensione del segmento
                            if(tcp->flags&FIN) { // Se è un FIN, segna la fine dello stream
                                printf("End of stream SEQ: %d\n",tcb->stream_end);
                                tcb->stream_end=stream_offs + streamsegmentsize;
                                printf("End of stream SEQ: %d\n",tcb->stream_end);
                                newrx->streamsegmentsize++; // Il FIN conta come un byte logico
                            }
                            // Inserisci il segmento nella lista ordinata dei segmenti non ACKati (unack)
                            for(prev = curr = tcb->unack; curr!=NULL && curr->stream_offs<stream_offs; curr = (prev = curr)->next);
                            // Se è un duplicato o un pacchetto vecchio, libera la memoria
                            if((stream_offs<tcb->cumulativeack) || (curr!=NULL && curr->stream_offs==stream_offs))
                                free(newrx);
                            else { // Inserisci il nuovo segmento
                                for(int k=0; k<streamsegmentsize;k++) // Copia i dati nel buffer di ricezione circolare
                                    tcb->rxbuffer[(stream_offs+k)%RXBUFSIZE] = streamsegment[k];

                                if ( prev == curr) { // Inserisci in testa
                                    tcb->unack = newrx;
                                    newrx->next = prev;
                                }
                                else { // Inserisci dopo prev
                                    prev->next = newrx;
                                    newrx->next = curr;
                                }
                                printf(" Inserted: ");printrxq(tcb->unack);

                                // Rimuovi i segmenti che ora formano un blocco contiguo all'inizio della finestra
                                while((tcb->unack != NULL) && (tcb->unack->stream_offs == tcb->cumulativeack)){
                                    struct rxcontrol * tmp;
                                    tmp = tcb->unack;
                                    tcb->cumulativeack += tcb->unack->streamsegmentsize; // Aggiorna l'ACK cumulativo
                                    tcb->adwin = RXBUFSIZE- (tcb->cumulativeack - tcb->rx_win_start); // Aggiorna la finestra pubblicizzata
                                    tcb->unack = tcb->unack->next;
                                    free(tmp);
                                }
                                printf(" Removed: ");printrxq(tcb->unack);
                            }
                            // Prepara un ACK se la coda di trasmissione è vuota (per piggyback) e lo stato non è TIME_WAIT
                            if(tcb->txfirst==NULL && tcb->st!=TIME_WAIT){
                                prepare_tcp(i,ACK,NULL,0,NULL,0);
                            }
                        }
                        break; // Fine elaborazione del segmento TCP
                    }// End of segment processing
                }//If TCP protocol
            }//IF ethernet
        }//While packet
    if (( errno != EAGAIN) && (errno!= EINTR )) { perror("Packet recvfrom Error\n"); } // Errori di recvfrom
}
    // Prepara i file descriptor per il prossimo poll
    fds[0].events= POLLIN|POLLOUT;
    fds[0].revents=0;
    if (fl > 1) ;//printf("Overlap (%d) in myio\n",fl); // Debugging
    fl--; // Decrementa il flag di sovrapposizione
    if(-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return ;} // Sblocca i segnali
}

// Implementazione semplificata della funzione `listen()`
int mylisten(int s, int bl){
    if (fdinfo[s].st!=TCP_BOUND) {myerrno=EBADF; return -1;} // Deve essere BOUND
    fdinfo[s].tcb = (struct tcpctrlblk *) malloc (sizeof(struct tcpctrlblk)); // Alloca un TCB per il socket di ascolto
    bzero(fdinfo[s].tcb,sizeof(struct tcpctrlblk)); // Inizializza il TCB
    fdinfo[s].st = TCB_CREATED; // Imposta lo stato del file descriptor
    fdinfo[s].tcb->st = LISTEN; /* Segna il socket come passivo (listener) */
    // Alloca la coda di backlog per le connessioni in attesa
    fdinfo[s].tcblist = (struct tcpctrlblk *) malloc (bl * sizeof(struct tcpctrlblk));
    bzero(fdinfo[s].tcblist,bl* sizeof(struct tcpctrlblk)); // Inizializza la coda
    fdinfo[s].bl = bl; // Imposta la lunghezza del backlog
    return 0;
}

// Implementazione semplificata della funzione `accept()`
int myaccept(int s, struct sockaddr * addr, int * len)
{
    int i,j;
    if (addr->sa_family == AF_INET){ // Solo AF_INET
        struct sockaddr_in * a = (struct sockaddr_in *) addr;
        *len = sizeof(struct sockaddr_in);
        if (fdinfo[s].tcb->st!=LISTEN) {myerrno=EBADF; return -1;} // Deve essere in stato LISTEN
        if (fdinfo[s].tcblist == NULL) {myerrno=EBADF; return -1;} // Backlog non allocato
        do{
            for(i=0;i<fdinfo[s].bl;i++){ // Scorre il backlog
                if(fdinfo[s].tcblist[i].st==ESTABLISHED){ // Se trova una connessione ESTABLISHED nel backlog
                    for(j=3;j<MAX_FD && fdinfo[j].st!=FREE;j++); // Cerca un file descriptor libero per la nuova connessione
                    if (j == MAX_FD) { myerrno=ENFILE; return -1;} // Nessun descrittore libero
                    else  { // Trovato un descrittore libero
                        // Copia le informazioni del socket di ascolto nel nuovo descrittore (ma senza backlog)
                        fdinfo[j]=fdinfo[s]; // Copia alcune proprietà del socket di ascolto
                        fdinfo[j].tcb=(struct tcpctrlblk *) malloc(sizeof(struct tcpctrlblk)); // Alloca un nuovo TCB
                        memcpy(fdinfo[j].tcb,fdinfo[s].tcblist+i,sizeof(struct tcpctrlblk)); // Copia il TCB dalla entry del backlog
                        a->sin_port = fdinfo[j].tcb->r_port; // Riporta la porta remota al chiamante
                        a->sin_addr.s_addr = fdinfo[j].tcb->r_addr;// Riporta l'indirizzo IP remoto
                        fdinfo[j].bl=0; // Il nuovo socket non ha backlog
                        fdinfo[s].tcblist[i].st=FREE; // Libera la entry nel backlog
                        printf("%.7ld: Reset clock\n",rtclock(1)); // Resetta il clock
                        prepare_tcp(j,ACK,NULL,0,NULL,0); // Invia un ACK per completare l'handshake (anche se il 3-way è già finito)
                        return j; // Restituisce il nuovo file descriptor connesso
                    }
                }//if pending connection
            }//for each fd
        } while(pause()); // Se nessun socket pronto, attendi con pause()
    }else { myerrno=EINVAL; return -1;} // Famiglia di indirizzi non valida
    return -1; // Non dovrebbe raggiungere qui
}


// Funzione principale del programma
int main(int argc, char **argv)
{
    clock_t start;
    fl = 0; // Inizializza il flag di sovrapposizione
    struct itimerval myt; // Struttura per il timer periodico

    // Configurazione del gestore per SIGIO (I/O)
    action_io.sa_handler = myio;
    // Configurazione del gestore per SIGALRM (timer)
    action_timer.sa_handler = mytimer;

    sigaction(SIGIO, &action_io, NULL);    // Registra il gestore per SIGIO
    sigaction(SIGALRM, &action_timer, NULL); // Registra il gestore per SIGALRM

    // Crea un socket raw per l'interfaccia di rete
    unique_s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (unique_s == -1 ) { perror("Socket Failed"); return 1;}

    // Configura il socket per ricevere segnali SIGIO quando ci sono dati disponibili
    if (-1 == fcntl(unique_s, F_SETOWN, getpid())){ perror("fcntl setown"); return 1;}
    fdfl = fcntl(unique_s, F_GETFL, NULL); if(fdfl == -1) { perror("fcntl f_getfl"); return 1;}
    fdfl = fcntl(unique_s, F_SETFL,fdfl|O_ASYNC|O_NONBLOCK); if(fdfl == -1) { perror("fcntl f_setfl"); return 1;}

    // Prepara la struttura pollfd per il polling del socket
    fds[0].fd = unique_s;
    fds[0].events= POLLIN|POLLOUT; // Interessa eventi di input e output
    fds[0].revents=0;

    // Configura l'indirizzo di livello link (per sendto/recvfrom)
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0"); // L'interfaccia è "eth0"

    // Configura il timer periodico (ITIMER_REAL)
    myt.it_interval.tv_sec=0;
    myt.it_interval.tv_usec=TIMER_USECS;
    myt.it_value.tv_sec=0;
    myt.it_value.tv_usec=TIMER_USECS;

    // Inizializza la maschera di segnali e aggiunge SIGIO e SIGALRM
    if( -1 == sigemptyset(&mymask)) {perror("Sigemtpyset"); return 1;}
    if( -1 == sigaddset(&mymask, SIGIO)){perror("Sigaddset");return 1;}
    if( -1 == sigaddset(&mymask, SIGALRM)){perror("Sigaddset");return 1;}
    // Sblocca i segnali (permettendone la consegna)
    if( -1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return 1;}
    // Avvia il timer periodico
    if( -1 == setitimer(ITIMER_REAL, &myt, NULL)){perror("Setitimer"); return 1;}

    // Gestione degli argomenti della linea di comando
    if(argc == 1){ printf(usage_string,argv[0]); return 1;}
    g_argv = argv; // Salva gli argomenti globalmente
    g_argc = argc;
    printf("Port: %d, TXBUFSIZE :%d , TIMEOUT: %d MODE:%s INV.LOSSRATE:%d\n", atoi(argv[1]), TXBUFSIZE, INIT_TIMEOUT*TIMER_USECS/1000,(argc>=5)?argv[4]:"SRV",INV_LOSS_RATE);

    // Modalità CLIENT (se il 5° argomento è "CLN")
    if(argc>=5 && !strcmp(argv[4],"CLN")){
        /************* USER WEB CLIENT CODE *************/
        int w,t;
        // Esempio di richiesta HTTP GET
        unsigned char * httpreq = "GET / HTTP/1.1\r\nAccept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: it-IT,it;q=0.9,en;q=0.8,fr;q=0.7,fr-CA;q=0.6,en-US;q=0.5\r\nCache-Control: no-cache\r\nConnection: close\r\nHost: www.midor.com.eg\r\nPragma: no-cache\r\nReferer: https://www.google.com/\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n\r\n";
        unsigned char httpresp[500000]; // Buffer per la risposta HTTP
        int s;
        struct sockaddr_in addr, loc_addr;

        s=mysocket(AF_INET,SOCK_STREAM,0); // Crea un socket
        addr.sin_family = AF_INET;
        addr.sin_port =htons(80); // Porta 80 per HTTP
        addr.sin_addr.s_addr = inet_addr("213.131.64.214");// Indirizzo IP del server (www.midor.com.eg)

        loc_addr.sin_family = AF_INET;
        loc_addr.sin_port =((argc>=2)?htons(atoi(argv[1])):htons(0)); // Porta locale (dal 2° argomento o dinamica)
        loc_addr.sin_addr.s_addr = htonl(0); // Indirizzo IP locale (qualsiasi)

        if( -1 == mybind(s,(struct sockaddr *) &loc_addr, sizeof(struct sockaddr_in))){myperror("mybind"); return 1;} // Binda il socket locale
        if (-1 == myconnect(s,(struct sockaddr * )&addr,sizeof(struct sockaddr_in))){myperror("myconnect"); return 1;} // Connette al server remoto
        printf("Sending Req... %s\n", httpreq);
        if ( mywrite(s,httpreq,strlen(httpreq))==1) { myperror("Mywrite Failed\n"); return -1;} // Invia la richiesta HTTP

        // Legge la risposta HTTP fino alla fine o al riempimento del buffer
        for (w=0; (t=myread(s,httpresp+w,500000-w)) > 0;w+=t)
            if(t== -1){myperror("myread"); return 1;}
        printf("Response size = %d\n",w);
        for(int u=0; u<w; u++){
            printf("%c",httpresp[u]); // Stampa la risposta
        }
        if (-1 == myclose(s)){myperror("myclose"); return 1;} // Chiude il socket

    }
    // Modalità SERVER (se il 5° argomento non è "CLN" o non specificato)
    else {
        /********** USER'S WEB SERVER CODE****************/
        struct sockaddr_in addr,remote_addr;
        int i,j,k,s,t,s2,len;
        int c;
        FILE * fin;
        char * method, *path, *ver;
        char request[5000],response[10000];
        if(argc>=5 && strcmp(argv[4],"SRV")){printf("Warning: unknown parameter \"%s\" -  assuming SRV...\n",argv[4]);}

        s =  mysocket(AF_INET, SOCK_STREAM, 0); // Crea un socket di ascolto
        if ( s == -1 ){ perror("Socket fallita"); return 1; }

        addr.sin_family = AF_INET;
        addr.sin_port =((argc>=2)?htons(atoi(argv[1])):htons(0)); // Porta di ascolto (dal 2° argomento o dinamica)
        addr.sin_addr.s_addr = 0; // Ascolta su tutte le interfacce
        if ( mybind(s,(struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {perror("bind fallita"); return 1;} // Binda
        if ( mylisten(s,5) == -1 ) { myperror("Listen Fallita"); return 1; } // Mette il socket in ascolto con backlog 5

        len = sizeof(struct sockaddr_in);
        while(1){ // Loop infinito per il server
            remote_addr.sin_family=AF_INET;
            s2 =  myaccept(s, (struct sockaddr *)&remote_addr,&len); // Accetta una nuova connessione in arrivo
            if ( s2 == -1 ) { myperror("Accept Fallita"); return 1;}

            t = myread(s2,request,4999); // Legge la richiesta HTTP dal client
            if ( t == -1 ) { myperror("Read fallita"); return 1;}
            request[t]=0; // Termina la stringa
            printf("\n=====================> %s\n",request);

            // Parsing della richiesta HTTP (metodo, percorso, versione)
            method = request;
            for(i=0;request[i]!=' ';i++){} request[i]=0; path = request+i+1;
            for(i++;request[i]!=' ';i++); request[i]=0; ver = request+i+1;
            for(i++;request[i]!='\r';i++); request[i]=0;

            if ((fin = fopen(path+1,"rt"))==NULL){ // Tenta di aprire il file richiesto
                sprintf(response,"HTTP/1.1 404 Not Found\r\n\r\n"); // Se il file non esiste, invia 404 Not Found
                mywrite(s2,response,strlen(response));
            }
            else {
                sprintf(response,"HTTP/1.1 200 OK\r\n\r\n"); // Se il file esiste, invia 200 OK
                mywrite(s2,response,strlen(response));

                // Legge il contenuto del file e lo invia al client in chunk di MSS
                while (t=fread(response,1,TCP_MSS,fin))
                    for(i=0;i<t;i=i+k)
                        k=mywrite(s2,response+i,t-i);
                fclose(fin); // Chiude il file
            }
            myclose(s2); // Chiude il socket della connessione servita
        } // end while (loop server)
    } //end else (server code)
    //end while
/******************* END OF SERVER CODE**************/

    // Attesa finale (non dovrebbe essere raggiunta in modalità server)
    start= tick;
    while (sleep(2)){
        if(((tick-start)*TIMER_USECS)>1000000) break; // Aspetta 1 secondo di tick
    }
    return 0;
}