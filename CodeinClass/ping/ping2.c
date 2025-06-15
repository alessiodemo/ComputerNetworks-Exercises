#include <stdio.h>               // Inclusione della libreria standard di I/O (input/output)
#include <net/if.h>              // Per la conversione del nome dell'interfaccia in indice
#include <arpa/inet.h>           // Per funzioni di conversione dell'ordine dei byte (es. htons, htonl)
#include <sys/socket.h>          // Per le funzioni di gestione dei socket (es. socket, sendto, recvfrom)
#include <linux/if_packet.h>     // Per le strutture a basso livello dei pacchetti (raw sockets)
#include <net/ethernet.h>        // Per le costanti del protocollo Ethernet (es. ETH_P_ALL, ETH_P_ARP, ETH_P_IP)
#include <errno.h>               // Per la gestione degli errori di sistema (variabile errno)

// Structure representing an ARP packet
struct arp_packet {
    unsigned short htype;        // Hardware type (Ethernet = 1) - Tipo di hardware (es. Ethernet)
    unsigned short ptype;        // Protocol type (IPv4 = 0x0800) - Tipo di protocollo (es. IPv4)
    unsigned char hlen;          // Hardware address length (MAC = 6) - Lunghezza dell'indirizzo hardware (MAC)
    unsigned char plen;          // Protocol address length (IP = 4) - Lunghezza dell'indirizzo di protocollo (IP)
    unsigned short op;           // Operation (1=request, 2=reply) - Tipo di operazione ARP (richiesta o risposta)
    unsigned char srcmac[6];     // Sender MAC address - Indirizzo MAC del mittente
    unsigned char srcip[4];      // Sender IP address - Indirizzo IP del mittente
    unsigned char dstmac[6];     // Target MAC address - Indirizzo MAC del destinatario
    unsigned char dstip[4];      // Target IP address - Indirizzo IP del destinatario
};

// Ethernet frame structure
struct eth_frame {
    unsigned char dst[6];        // Destination MAC - Indirizzo MAC di destinazione
    unsigned char src[6];        // Source MAC - Indirizzo MAC di origine
    unsigned short type;         // EtherType (0x0800 = IP, 0x0806 = ARP) - Tipo di protocollo incapsulato (es. IP, ARP)
    unsigned char payload[1];    // Payload (ARP, IP, etc.) - Carico utile del frame Ethernet (pacchetto ARP, IP, ecc.)
};

// IP packet structure
struct ip_datagram {
    unsigned char ver_ihl;       // Version (4 bits) + IHL (4 bits) - Versione IP (4 bit) + Lunghezza Intestazione IP (IHL, 4 bit)
    unsigned char tos;           // Type of Service - Tipo di Servizio (QoS)
    unsigned short totlen;       // Total length (IP header + payload) - Lunghezza totale del datagramma IP (intestazione + payload)
    unsigned short id;           // Identification - Identificativo del datagramma (per la frammentazione)
    unsigned short flags_offs;   // Flags and fragment offset - Flag e offset di frammentazione
    unsigned char ttl;           // Time to Live - Tempo di vita del pacchetto
    unsigned char proto;         // Protocol (ICMP = 1) - Protocollo del payload (es. ICMP)
    unsigned short checksum;     // Header checksum - Checksum dell'intestazione IP
    unsigned int src;            // Source IP - Indirizzo IP di origine
    unsigned int dst;            // Destination IP - Indirizzo IP di destinazione
    unsigned char payload[1];    // Payload (ICMP, etc.) - Carico utile del datagramma IP (pacchetto ICMP, ecc.)
};

// ICMP packet structure
struct icmp_packet {
    unsigned char type;          // Type (8=echo request, 0=echo reply) - Tipo di messaggio ICMP (richiesta o risposta echo)
    unsigned char code;          // Code (usually 0) - Codice del messaggio ICMP (solitamente 0)
    unsigned short checksum;     // Checksum - Checksum dell'intestazione e del payload ICMP
    unsigned short id;           // Identifier - Identificatore (per correlare richieste e risposte)
    unsigned short seq;          // Sequence number - Numero di sequenza (per correlare richieste e risposte)
    unsigned char payload[1];    // Data - Dati del messaggio ICMP
};

// Node configuration
unsigned char myip[4] = {212, 71, 252, 26};          // Local IP address - Indirizzo IP locale del mittente
unsigned char mymac[6] = {0xF2, 0x3C, 0x94, 0x90, 0x4F, 0x4b}; // Local MAC address - Indirizzo MAC locale del mittente
unsigned char gateway[4] = {212, 71, 252, 1};        // Default gateway IP - Indirizzo IP del gateway predefinito
unsigned char mask[4] = {255, 255, 255, 0};          // Subnet mask - Subnet mask della rete locale

// Target IP to ping
unsigned char target_ip[4] = {147, 162, 2, 100};    // Target IP address - Indirizzo IP del destinatario del ping
unsigned char broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast MAC - Indirizzo MAC di broadcast
int s; // Raw socket descriptor - Descrittore del socket raw

// Function prototypes - Prototipi delle funzioni
int resolve_ip(unsigned char *target, unsigned char *mac);
void print_buffer(unsigned char* buffer, int size);

// Calculates the Internet checksum - Calcola il checksum Internet (usato per IP e ICMP)
unsigned short int checksum(unsigned char *b, int len) {
    unsigned short *p = (unsigned short *)b; // Puntatore a short per l'accesso a 2 byte alla volta
    unsigned int tot = 0; // Accumulatore per la somma
    int i; // Contatore del ciclo

    // Itera su blocchi di 2 byte (short)
    for (i = 0; i < len / 2; i++) {
        tot += ntohs(p[i]); // Somma il valore del word in ordine host, gestendo l'endianness
        if (tot & 0x10000) tot = (tot + 1) & 0xFFFF; // Gestisce il carry-over (overflow a 16 bit)
    }

    // Handle odd byte - Gestisce l'eventuale byte rimanente se la lunghezza è dispari
    if (len & 0x1) {
        tot += ntohs(p[i]) & 0xFF00; // Somma il byte rimanente (più significativo)
        if (tot & 0x10000) tot = (tot + 1) & 0xFFFF; // Gestisce il carry-over
    }

    return (0xFFFF - ((unsigned short)tot)); // Restituisce il complemento a uno della somma
}

// Create an ICMP Echo Request - Costruisce un pacchetto ICMP Echo Request
void forge_icmp(struct icmp_packet *icmp, unsigned char type, unsigned char code, int payloadsize) {
    icmp->type = type;           // ICMP type - Imposta il tipo ICMP (es. 8 per echo request)
    icmp->code = code;           // ICMP code - Imposta il codice ICMP (es. 0)
    icmp->checksum = 0;          // Initially 0 for checksum calculation - Inizialmente a 0 per il calcolo del checksum
    icmp->id = htons(0xABCD);    // Identifier - Imposta l'identificatore (in ordine di rete)
    icmp->seq = htons(1);        // Sequence number - Imposta il numero di sequenza (in ordine di rete)

    for (int i = 0; i < payloadsize; i++) // Itera per riempire il payload
        icmp->payload[i] = i;    // Fill payload with incremental bytes - Riempie il payload con valori incrementali

    // Calculate checksum - Calcola il checksum ICMP
    icmp->checksum = htons(checksum((unsigned char*)icmp, payloadsize + 8)); // Calcola e imposta il checksum in ordine di rete
}

// Construct an IP header - Costruisce un'intestazione IP
void forge_ip(struct ip_datagram *ip, unsigned short payloadlen, unsigned char *dst) {
    ip->ver_ihl = 0x45;                      // IPv4 and header length = 20 bytes - Versione IPv4 e IHL (5 * 4 = 20 byte)
    ip->tos = 0;                             // No special TOS - Nessun Tipo di Servizio speciale
    ip->totlen = htons(payloadlen + 20);    // Total length - Lunghezza totale (payload + 20 byte di intestazione IP) in ordine di rete
    ip->id = htons(0x1234);                  // Arbitrary ID - ID arbitrario (in ordine di rete)
    ip->flags_offs = htons(0);               // No fragmentation - Nessun flag di frammentazione e offset 0 (in ordine di rete)
    ip->ttl = 128;                           // TTL - Time To Live
    ip->proto = 1;                           // ICMP protocol - Protocollo del payload (1 per ICMP)
    ip->checksum = 0;                        // Reset checksum for calculation - Inizialmente a 0 per il calcolo del checksum
    ip->src = *((unsigned int *)myip);       // Source IP - Indirizzo IP di origine (copia diretta dei 4 byte)
    ip->dst = *((unsigned int *)dst);        // Destination IP - Indirizzo IP di destinazione (copia diretta dei 4 byte)
    ip->checksum = htons(checksum((unsigned char *)ip, 20)); // Calculate checksum - Calcola e imposta il checksum dell'intestazione IP in ordine di rete
}

// Print raw bytes in buffer for debugging - Stampa i byte raw di un buffer per il debugging
void print_buffer(unsigned char* buffer, int size) {
    for (int i = 0; i < size; i++) { // Itera su ogni byte del buffer
        printf("%.3d (%.2X) ", buffer[i], buffer[i]); // Stampa il valore decimale e esadecimale del byte
        if (i % 4 == 3) printf("\n"); // Va a capo ogni 4 byte per una migliore leggibilità
    }
    printf("\n"); // Stampa una riga vuota alla fine
}

// Resolve target IP to MAC using ARP request - Risolve un indirizzo IP in un indirizzo MAC tramite una richiesta ARP
int resolve_ip(unsigned char *target, unsigned char *mac) {
    int len; // Variabile per la lunghezza
    unsigned char buffer[1500]; // Buffer per il frame Ethernet
    struct sockaddr_ll sll; // Struttura per l'indirizzo del link layer
    struct arp_packet *arp; // Puntatore alla struttura del pacchetto ARP
    struct eth_frame *eth; // Puntatore alla struttura del frame Ethernet
    int i, j, n; // Contatori e variabile per il numero di byte ricevuti

    eth = (struct eth_frame *) buffer; // Il frame Ethernet inizia all'inizio del buffer
    arp = (struct arp_packet *) eth->payload; // Il pacchetto ARP si trova nel payload del frame Ethernet

    // Fill Ethernet header - Riempie l'intestazione Ethernet
    for (i = 0; i < 6; i++) { // Itera per copiare gli indirizzi MAC
        eth->src[i] = mymac[i]; // Indirizzo MAC sorgente: il mio MAC
        eth->dst[i] = 0xFF; // Broadcast - Indirizzo MAC destinazione: broadcast (FF:FF:FF:FF:FF:FF)
    }
    eth->type = htons(0x0806); // ARP - Tipo Ethernet: ARP (0x0806 in ordine di rete)

    // Fill ARP packet - Riempie il pacchetto ARP
    arp->htype = htons(1); // Ethernet - Tipo di hardware: Ethernet (1 in ordine di rete)
    arp->ptype = htons(0x0800); // IP - Tipo di protocollo: IP (0x0800 in ordine di rete)
    arp->hlen = 6; // Lunghezza dell'indirizzo hardware: 6 byte (MAC)
    arp->plen = 4; // Lunghezza dell'indirizzo di protocollo: 4 byte (IP)
    arp->op = htons(1); // ARP request - Operazione ARP: richiesta (1 in ordine di rete)

    for (i = 0; i < 6; i++) { // Itera per copiare gli indirizzi MAC
        arp->srcmac[i] = mymac[i]; // MAC del mittente: il mio MAC
        arp->dstmac[i] = 0; // MAC del destinatario: sconosciuto (00:00:00:00:00:00)
    }
    for (i = 0; i < 4; i++) { // Itera per copiare gli indirizzi IP
        arp->srcip[i] = myip[i]; // IP del mittente: il mio IP
        arp->dstip[i] = target[i]; // IP del destinatario: l'IP target da risolvere
    }

    // Clear sockaddr_ll - Azzera la struttura sockaddr_ll
    for (i = 0; i < sizeof(struct sockaddr_ll); i++) ((char *) &sll)[i] = 0;

    sll.sll_family = AF_PACKET; // Famiglia di indirizzi: livello di link
    sll.sll_ifindex = if_nametoindex("eth0"); // Imposta l'indice dell'interfaccia "eth0"
    len = sizeof(struct sockaddr_ll); // Lunghezza della struttura dell'indirizzo

    // Send ARP request - Invia la richiesta ARP
    if (-1 == sendto(s, buffer, 1500, 0, (struct sockaddr *) &sll, len)) { // Invia il pacchetto ARP
        perror("Send Failed"); // Stampa un messaggio di errore se l'invio fallisce
        return 1; // Ritorna errore
    }

    // Wait for ARP reply - Attende una risposta ARP
    j = 100; // Contatore per il numero massimo di tentativi di ricezione
    while (j--) { // Cicla per ricevere risposte
        n = recvfrom(s, buffer, 1500, 0, (struct sockaddr *) &sll, &len); // Riceve un pacchetto dal socket raw
        if (n == -1) { // Se la ricezione fallisce
            printf("Errno = %d\n", errno); // Stampa il codice di errore
            perror("Recvfrom Failed"); // Stampa un messaggio di errore
            return 1; // Ritorna errore
        }

        // Controlla se il pacchetto ricevuto è una risposta ARP per noi
        if (eth->type == htons(0x0806) && arp->op == htons(2)) { // Se è un frame ARP (0x0806) e un'operazione di risposta (2)
            printf("ARP REPLY RECEIVED:\n"); // Stampa un messaggio di ricezione
            print_buffer(buffer, n); // Stampa il contenuto del pacchetto ricevuto per il debugging

            for (i = 0; i < 6; i++) // Itera per copiare il MAC risolto
                mac[i] = arp->srcmac[i]; // Copia l'indirizzo MAC del mittente della risposta ARP (che è il MAC del target)
            return 0; // Ritorna successo
        }
    }

    return 1; // Se non viene ricevuta nessuna risposta ARP entro il timeout, ritorna errore
}

// Main function: forge and send ICMP Echo Request - Funzione principale: crea e invia una richiesta ICMP Echo
int main() {
    unsigned char buffer[1500]; // Buffer per il frame Ethernet completo (pacchetto IP + ICMP)
    struct icmp_packet *icmp; // Puntatore alla struttura del pacchetto ICMP
    struct ip_datagram *ip; // Puntatore alla struttura del datagramma IP
    struct eth_frame *eth; // Puntatore alla struttura del frame Ethernet
    struct sockaddr_ll sll; // Struttura per l'indirizzo del link layer
    int len, n, i, j; // Contatori e variabili per lunghezze e byte ricevuti
    unsigned char target_mac[6]; // Array per memorizzare l'indirizzo MAC risolto del target

    // Create raw socket - Crea un socket raw
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // Crea un socket raw per tutti i tipi di protocollo Ethernet
    if (s == -1) { // Se la creazione del socket fallisce
        printf("Errno = %d\n", errno); // Stampa il codice di errore
        perror("Socket Failed"); // Stampa un messaggio di errore
        return 1; // Ritorna errore
    }

    eth = (struct eth_frame *) buffer; // Il frame Ethernet inizia all'inizio del buffer
    ip = (struct ip_datagram *) eth->payload; // Il datagramma IP si trova nel payload del frame Ethernet
    icmp = (struct icmp_packet *) ip->payload; // Il pacchetto ICMP si trova nel payload del datagramma IP

    // Create ICMP and IP packets - Crea i pacchetti ICMP e IP
    forge_icmp(icmp, 8, 0, 40); // Echo request with 40-byte payload - Costruisce un pacchetto ICMP Echo Request (tipo 8, codice 0, 40 byte di payload)
    forge_ip(ip, 48, target_ip); // Costruisce l'intestazione IP (lunghezza payload ICMP + ICMP header = 40+8=48, IP destinazione)

    // Check if target is on same subnet - Controlla se il target è nella stessa sottorete
    if ((*(unsigned int *)myip & *(unsigned int *)mask) == // Esegue AND bit a bit tra il mio IP e la maschera
        (*(unsigned int *)target_ip & *(unsigned int *)mask)) { // Esegue AND bit a bit tra il target IP e la maschera
        if (resolve_ip(target_ip, target_mac)) printf("Resolution Failed\n"); // Se sono nella stessa sottorete, risolve il MAC del target IP
    } else { // Se il target non è nella stessa sottorete
        if (resolve_ip(gateway, target_mac)) printf("Resolution Failed\n"); // Risolve il MAC del gateway predefinito
    }

    // Fill Ethernet frame with resolved MACs - Riempie il frame Ethernet con gli indirizzi MAC risolti
    for (i = 0; i < 6; i++) { // Itera per copiare gli indirizzi MAC
        eth->dst[i] = target_mac[i]; // Indirizzo MAC destinazione: il MAC risolto (del target o del gateway)
        eth->src[i] = mymac[i]; // Indirizzo MAC sorgente: il mio MAC
    }
    eth->type = htons(0x0800); // IP - Tipo Ethernet: IP (0x0800 in ordine di rete)

    // Debug print - Stampa per il debugging
    printf("Ethernet header\n"); // Stampa "Ethernet header"
    print_buffer((unsigned char *)eth, 14); // Stampa i primi 14 byte (lunghezza dell'intestazione Ethernet)
    printf("Ethernet payload\n"); // Stampa "Ethernet payload"
    print_buffer((unsigned char *)ip, 68); // Stampa 68 byte (20 byte IP header + 48 byte ICMP)

    // Prepare sockaddr_ll - Prepara la struttura sockaddr_ll
    for (i = 0; i < sizeof(struct sockaddr_ll); i++) ((char *)&sll)[i] = 0; // Azzera la struttura
    sll.sll_family = AF_PACKET; // Famiglia di indirizzi: livello di link
    sll.sll_ifindex = if_nametoindex("eth0"); // Imposta l'indice dell'interfaccia "eth0"
    len = sizeof(struct sockaddr_ll); // Lunghezza della struttura dell'indirizzo

    // Send ICMP request - Invia la richiesta ICMP
    if (-1 == sendto(s, buffer, 1500, 0, (struct sockaddr *)&sll, len)) { // Invia il pacchetto
        perror("Send Failed"); // Stampa un messaggio di errore se l'invio fallisce
        return 1; // Ritorna errore
    }

    // Wait for ICMP reply - Attende una risposta ICMP
    j = 100; // Contatore per il numero massimo di tentativi di ricezione
    while (j--) { // Cicla per ricevere risposte
        n = recvfrom(s, buffer, 1500, 0, (struct sockaddr *)&sll, &len); // Riceve un pacchetto dal socket raw
        if (n == -1) { // Se la ricezione fallisce
            printf("Errno = %d\n", errno); // Stampa il codice di errore
            perror("Recvfrom Failed"); // Stampa un messaggio di errore
            return 1; // Ritorna errore
        }

        // Controlla se il pacchetto ricevuto è una risposta ICMP Echo
        if (eth->type == htons(0x0800) && ip->proto == 1) { // IP and ICMP - Se è un frame IP (0x0800) e il protocollo è ICMP (1)
            printf("ICMP PKT RECEIVED:\n"); // Stampa un messaggio di ricezione
            if (icmp->type == 0 && icmp->id == htons(0xABCD)) { // Se è una risposta Echo (tipo 0) e l'ID corrisponde
                printf("ICMP REPLY DETECTED\n"); // Stampa un messaggio di rilevamento della risposta
                print_buffer((unsigned char *)ip, 20 + 48); // Stampa il datagramma IP (intestazione IP + payload ICMP)
                break; // Esce dal ciclo di ricezione
            }
        }
    }

    return 0; // Ritorna successo
}