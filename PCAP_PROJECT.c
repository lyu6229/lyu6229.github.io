/* 전체 코드 */
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ether.h> 
/* Ethernet header */
struct ethheader {
    unsigned char ether_dhost[6]; /* destination host address */
    unsigned char ether_shost[6]; /* source host address */
    unsigned short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                       iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                       iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};
/* TCP Header */
struct tcpheader {
    unsigned short tcp_sport;               /* source port */
    unsigned short tcp_dport;               /* destination port */
    unsigned int   tcp_seq;                 /* sequence number */
    unsigned int   tcp_ack;                 /* acknowledgement number */
    unsigned char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    unsigned char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    unsigned short tcp_win;                 /* window */
    unsigned short tcp_sum;                 /* checksum */
    unsigned short tcp_urp;                 /* urgent pointer */
};

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ethheader));
  struct tcpheader *tcp = (struct tcpheader *) (packet + sizeof(struct ethheader) + (ip -> iph_ihl * 4));
  
  printf("Ethernet Header src mac : %s\n", ether_ntoa((struct ether_addr *)(eth->ether_shost)));
  printf("Ethernet Header dst mac : %s\n", ether_ntoa((struct ether_addr *)(eth->ether_dhost)));

  printf("IP Header src ip : %s\n", inet_ntoa(*(struct in_addr *)&ip->iph_sourceip));
  printf("IP Header dst ip : %s\n", inet_ntoa(*(struct in_addr *)&ip->iph_destip));

  printf("TCP Header src port : %d\n", ntohs(tcp->tcp_sport));
  printf("TCP Header dst port : %d\n", ntohs(tcp->tcp_dport));  
  
}
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3",BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap session: %s\n", errbuf);
        return 1;  // Exit if pcap_open_live failed
    }
  pcap_loop(handle, 0, got_packet, NULL);

  pcap_close(handle);

  return 0;
}