#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];
    u_char  ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct sniff_ip {
    u_char  ip_vhl;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct  in_addr ip_src, ip_dst;
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char  th_offx2;
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

void hextoascii(const u_char *payload, int len, int offset) {
    int i;
    int gap;
    const u_char *ch;

    printf("%05d", offset);

    ch = payload;
    for (i = 0; i < len; i++) {
        printf("%02x", *ch);
        ch++;
        if (i == 7)
            printf("\t");
    }

    if (len < 8) {
        printf(" ");
    }

    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("\t");
        }
    }
    printf("\t\t");

    ch = payload;
    for (i = 0; i < len; i++) {
        if (isprint(*ch)){
            printf("%c", *ch);
        }
        else{
            printf(".");
        }
        ch++;
    }
    printf("\n");
}

void packetCapture() {

    const u_char *packet;
    const char *payload;
    char srcbuf[20];
    char dstbuf[20];

    int size_ip;
    int size_tcp;
    int size_payload;

    int line_len;
    int offset = 0;
    int num=0;

     struct sniff_ethernet *ethernet;
     struct sniff_ip *ip;
     struct sniff_tcp *tcp;
    struct pcap_pkthdr *header;

    pcap_t *handle;
    //char *dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    ethernet = (struct sniff_ethernet *)(packet);


    handle = pcap_open_live("eth0", SNAP_LEN, 1, 1000, errbuf);

    while(pcap_next_ex(handle, &header, &packet)){
        if(num>5)
            break;
        num++;
        printf("%d\n", num);
        /* inet_ntoa -> inet_ntop */
        //printf("Src IP: %s\n", inet_ntoa(ip->ip_src));
        //printf("Dst IP: %s\n", inet_ntoa(ip->ip_dst));
        //printf("Src IP: %s\n", inet_ntop(AF_INET, &(ip->ip_src), srcbuf, sizeof(srcbuf)));
        //printf("Dst IP: %s\n", inet_ntop(AF_INET, &(ip->ip_dst), dstbuf, sizeof(dstbuf)));

        for(int i=0; i<6; i++){
              printf("%02x", ethernet->ether_shost[i]);
              if(i!=5)
                  printf(":");
        }
        printf("\n");

        for(int i=0; i<6; i++){
              printf("%02x", ethernet->ether_dhost[i]);
              if(i!=5)
                  printf(":");
        }
        printf("\n");

        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;

        printf("Src IP: %s\n", inet_ntoa(ip->ip_src));
        printf("Dst IP: %s\n", inet_ntoa(ip->ip_dst));

        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;

        printf("Src port: %d\n", ntohs(tcp->th_sport));
        printf("Dst port: %d\n", ntohs(tcp->th_dport));

        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        if (size_payload > 0) {
            printf("Data :\n");

            if (size_payload <= 16) {
                hextoascii(payload, size_payload, offset);
                return;
            }

            for (;; ) {
                line_len = 16 % size_payload;
                hextoascii(payload, line_len, offset);
                size_payload = size_payload - line_len;
                payload = payload + line_len;
                offset = offset + 16;
                if (size_payload <= 16) {
                    hextoascii(payload, size_payload, offset);
                    break;
                }
            }
        }
    }
    pcap_close(handle);
}

int main(int argc, char **argv)
{


    //handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);

    //capturePacket;
    //pcap_loop(handle, 5, capturePacket, NULL);

    /*while(pcap_next_ex(handle, &handle, &pkt_data)){
        if(i>5)
            return;
        capturePacket;
        i++;
    }*/

    packetCapture();


    return 0;
}
