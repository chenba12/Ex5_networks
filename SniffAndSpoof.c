#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdlib.h>          // for exit()
#include <netinet/udp.h>     //Provides declarations for udp header
#include <netinet/ip.h>      //Provides declarations for ip header
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <errno.h>

char *destIP = NULL;
char *srcIP = NULL;
struct sockaddr_in destInfo;

unsigned short in_cksum(unsigned short *buf, int length);

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    unsigned int size = h->len;
    if (size > 0) {
        printf("Got a new packet!\n");
        struct ether_header *ether_header = (struct ether_header *) bytes;
        if (ether_header->ether_type == ETH_P_IP) {
            struct iphdr *ip_header = (struct iphdr *) (bytes + sizeof(struct ether_header));
            struct icmphdr *icmphdr = (struct icmphdr *) (bytes + sizeof(struct iphdr));
            if (icmphdr->type == ICMP_ECHO) {
                printf("Found ICMP ECHO from source IP: %s to %s\n", inet_ntoa(*(struct in_addr *) &ip_header->saddr),
                       inet_ntoa(*(struct in_addr *) &ip_header->daddr));

                icmphdr->type = ICMP_ECHOREPLY; //ICMP Type: 8 is request, 0 is reply.

                // Calculate the checksum for integrity
                icmphdr->checksum = 0;
                icmphdr->checksum = in_cksum((unsigned short *) icmphdr,
                                             sizeof(struct icmphdr));

                ip_header->version = 4;
                ip_header->ihl = 5;
                ip_header->ttl = 60;
                ip_header->saddr = inet_addr(srcIP);
                ip_header->daddr = inet_addr(destIP);
                ip_header->protocol = IPPROTO_ICMP;
                ip_header->tot_len = htons(sizeof(struct iphdr) +
                                           sizeof(struct icmphdr));

                struct sockaddr_in dest_info;
                int enable = 1;
                // Step 1: Create a raw network socket.
                int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
                if (sock == -1) {
                    printf("Error: in opening new raw socket\n", errno);
                    exit(-1);
                }
                // Step 2: Set socket option.
                int set = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
                if (set == -1) {
                    printf("Error: in setting enable option in socket\n", errno);
                    exit(-1);
                }
                // Step 3: Provide needed information about destination.
                destInfo.sin_family = AF_INET;
                memset(&destInfo, 0, sizeof(destInfo));
                destInfo.sin_addr.s_addr = ip_header->daddr;
                // Step 4: Send the packet out.
                int bytesSent = sendto(sock, ip_header, ntohs(ip_header->tot_len), 0, (struct sockaddr *) &destInfo,
                                       sizeof(dest_info));
                if (bytesSent == -1) {
                    printf("Error in sending ICMP echo reply \n", errno);
                    exit(-1);
                }
            }
        }
    }

}

unsigned short in_cksum(unsigned short *buf, int length) {
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;
    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *) (&temp) = *(u_char *) w;
        sum += temp;
    }

    /* add back carry out from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
    sum += (sum >> 16);                  // add carry
    return (unsigned short) (~sum);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net = 0;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("failed\n");
        exit(-1);
    }
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}