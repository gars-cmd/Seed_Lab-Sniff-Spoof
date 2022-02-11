
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
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

struct sniff_tcp
{
	unsigned short th_sport; /* source port */
	unsigned short th_dport; /* destination port */
	unsigned char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	unsigned char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
	unsigned short th_win; /* window */
	unsigned short th_sum; /* checksum */
	unsigned short th_urp; /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    printf("\n");

    struct ipheader* ip_h = (struct ipheader*)(packet + sizeof(struct ethheader)); 
    struct sniff_tcp* tcp_h = (struct sniff_tcp*)(packet + sizeof(struct ethheader)+sizeof(struct ipheader));
    char *buffer = (u_char*)packet + sizeof(struct ethheader) + sizeof(struct ipheader)+ sizeof(struct sniff_tcp);
    int sized =  ntohs(ip_h->iph_len) - (sizeof(struct ipheader) + sizeof(struct sniff_tcp));
    // printf("       IP_source: %s\n", inet_ntoa(ip_h->iph_sourceip));   
    // printf("       IP_dest: %s\n", inet_ntoa(ip_h->iph_destip));
    // printf("       data:");
    for (int i = 0; i < sized; i++)
    {
      if (islower(*buffer))
      {
        printf("%c",*buffer);

      }
      else
      {
        printf("");
      }
      buffer++;
    }
    printf("");
        
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  // char filter_exp[] = "icmp";
  // char filter_exp[] = "proto ICMP and (host 10.9.0.5 and 10.9.0.6)";
  char filter_exp[] = "proto TCP and dst portrange 10-100";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("br-78035c09e487", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
