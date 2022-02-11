#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>



static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}


void compute_ip_checksum(struct ip* iphdrp){
  iphdrp->ip_sum = 0;
  iphdrp->ip_sum = compute_checksum((unsigned short*)iphdrp, iphdrp->ip_hl<<2);
}





void send_spoof(struct ip* ip_h){
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
    sin.sin_addr = ip_h->ip_dst;

    //STEP4
    sendto(sd , ip_h , ntohs(ip_h->ip_len) , 0 , (struct sockaddr*)&sin , sizeof(sin));
    printf("from :  %s",inet_ntoa(ip_h->ip_src));
    printf("    to : %s",inet_ntoa(ip_h->ip_dst));
    close(sd);

}

int main(){
    char buffer[1500];
    memset(buffer , 0 , 1500);

    struct icmp *icmp_h = (struct icmp*) (buffer + sizeof(struct ip));
    icmp_h->icmp_type = 8;
    // icmp_h->icmp_cksum = chksum( (unsigned short*)icmp_h ,sizeof(struct icmp)); 
    
    
    struct ip *ip_h = (struct ip*) buffer;
    ip_h->ip_v = 4;
    // converting the wanted address from string to a 32bit integer 
    ip_h->ip_src.s_addr = inet_addr("1.2.3.4");
    ip_h->ip_dst.s_addr = inet_addr("10.9.0.5");
    
    //intent header len 
    ip_h->ip_hl = sizeof(struct ip) / 4;
    // time to live
    ip_h->ip_ttl = 25;
    // protocol 
    ip_h->ip_p = IPPROTO_ICMP;
    //total length convert from unsigned short int from host to network byte order
    ip_h->ip_len = htons(sizeof(struct ip)+ sizeof(struct icmp));
    compute_ip_checksum(ip_h);


    send_spoof(ip_h);
    return 0;
}
