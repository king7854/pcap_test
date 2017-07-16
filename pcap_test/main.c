#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ip *iph;
struct tcphdr *tcph;
struct ether_header *eph;



void capturePcap(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    unsigned short ether_type;
    int lengthtmp =0;
    int length=pkthdr->len;

    eph = (struct ether_header*)packet;

    packet += sizeof(struct ether_header);
    ether_type = ntohs(eph->ether_type);

    if(ether_type == ETHERTYPE_IP){
        iph = (struct ip*)packet;
        printf("Src IP : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst IP : %s\n", inet_ntoa(iph->ip_dst));
    }
}

int main(int argc, char *argv[]){
        pcap_t *handle;			/* Session handle */
        char *dev;			/* The device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
        struct bpf_program fp;		/* The compiled filter */
        char filter_exp[] = "port 80";	/* The filter expression */
        bpf_u_int32 mask;		/* Our netmask */
        bpf_u_int32 net;		/* Our IP */
        struct pcap_pkthdr header;	/* The header that pcap gives us */
        const u_char *packet;		/* The actual packet */



        while(1){
            /* Define the device */
            dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
            }
            /* Find the properties for the device */
            if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
            }/* Define the device */
            dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
            }
            /* Find the properties for the device */
            if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
            }
            /* Open the session in promiscuous mode */
            handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return(2);
            }
            /* Compile and apply the filter */
            if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
            }
            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
            }
            /* Grab a packet */
            packet = pcap_next(handle, &header);
            /* Print its length */
            printf("Jacked a packet with length of [%d]\n", header.len);
            /* And close the session */
            pcap_close(handle);
            /* Open the session in promiscuous mode */
            handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return(2);
            }
            /* Compile and apply the filter */
            if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
            }
            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
            }
            /* Grab a packet */
            packet = pcap_next(handle, &header);
            /* Print its length */
            printf("Jacked a packet with length of [%d]\n", header.len);
            /* And close the session */
            pcap_close(handle);
        }
        return(0);
}
