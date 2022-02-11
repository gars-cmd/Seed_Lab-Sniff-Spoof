#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"


// send the spoofed packet prepared in the got_packet function
void send_spoof(struct ipheader* ip_h){
    struct sockaddr_in sin;
    int sm=1;
    const int *val=&sm;

     //STEP1
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) {
        perror("socket() error");
    }

    //STEP2
    int ans = setsockopt(sd , IPPROTO_IP  , IP_HDRINCL , val , sizeof(sm) );
    if (ans < 0)
    {
        perror("the kernel didn't allowed ip spoofing");
    }

    //STEP3
    sin.sin_family = AF_INET;
    sin.sin_addr = ip_h->iph_destip;

     //STEP4
    sendto(sd , ip_h , ntohs(ip_h->iph_len) , 0 , (struct sockaddr*)&sin , sizeof(sin));
    printf("spoofed packet sent :\n");
    printf("    from :  %s\n",inet_ntoa(ip_h->iph_sourceip));
    printf("    to : %s\n",inet_ntoa(ip_h->iph_destip));
    close(sd);

}


// processing the packet we catch , modification of the specific headers  
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
printf("Got a packet\n");

struct ethheader* et_h = (struct ethheader*)packet;

//print what we get 
struct ipheader* ip_h = (struct ipheader*)(packet+sizeof(struct ethheader));
printf("    from: %s\n" , inet_ntoa(ip_h->iph_sourceip));
printf("    to: %s\n" , inet_ntoa(ip_h->iph_destip));

    if (ip_h->iph_protocol == IPPROTO_ICMP)
    {
        int ip_len = ip_h->iph_ihl * 4;
        struct icmpheader *icmp_h = (struct icmpheader*)(packet + sizeof(struct ethheader) + ip_len);

        // if we catch an icmp request
        if (icmp_h->icmp_type == 8)
        {
            // we create the icmp reply
            icmp_h->icmp_type = 0;
            struct in_addr source = ip_h->iph_sourceip;
            struct in_addr destination = ip_h->iph_destip;

            ip_h->iph_ver = 4;
            ip_h->iph_ihl = 5;
            ip_h->iph_ttl = 25;
            // we inverse the source and destination
            ip_h->iph_sourceip = destination;
            ip_h->iph_destip = source;
            //send it
            send_spoof(ip_h);
        }  
    }
}



int main(){


// same as the task 2.1
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "proto ICMP";
  bpf_u_int32 net;

  handle = pcap_open_live("br-78035c09e487" , BUFSIZ , 1 , 1000 , errbuf);

  pcap_compile(handle , &fp , filter_exp , 0 ,net);
  if (pcap_setfilter(handle , &fp)!= 0)
  {
      perror("error occur while filtering");
  }
  pcap_loop(handle , -1 , got_packet , NULL);
  pcap_close(handle);
  return 0;

  
  
}