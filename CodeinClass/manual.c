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