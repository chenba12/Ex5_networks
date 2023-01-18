#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>

struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};
struct ipheader {
    unsigned char iph_ihl: 4, //IP header length
    iph_ver: 4; //IP version
    unsigned char iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag: 3, //Fragmentation flags
    iph_offset: 13; //Flags offset
    unsigned char iph_ttl; //Time to Live
    unsigned char iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct in_addr iph_sourceip; //Source IP address
    struct in_addr iph_destip;   //Destination IP address
};
struct ethheader {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

unsigned short calculate_checksum(unsigned short *paddress, int len);

void createRawSocket(const struct ipheader *ip_header);

void swapSrcDest(struct ipheader *ip_header);

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) {
    unsigned int header_size = header->len;
    struct ethheader *eth_header = (struct ethheader *) bytes;
    struct ipheader *ip_header = (struct ipheader *) (bytes + sizeof(struct ethheader));
    struct icmpheader *icmp_header = (struct icmpheader *) ((u_char *) ip_header + sizeof(struct ipheader));
    if (header_size > 0) {
        if (icmp_header->icmp_type == 8) {
            if (ip_header->iph_protocol == IPPROTO_ICMP) {
                if (ntohs(eth_header->ether_type) == 0x0800) {
                    printf("Sniffed a new ICMP request... Generating a fake reply...\n");
                    // sendping back
                    icmp_header->icmp_type = 0;
                    icmp_header->icmp_chksum = calculate_checksum((unsigned short *) (bytes), 8 + 24);

                    ip_header->iph_ident = 0;
                    ip_header->iph_ver = 4;
                    ip_header->iph_ihl = 5;
                    ip_header->iph_protocol = IPPROTO_ICMP;
                    ip_header->iph_flag = 0;
                    ip_header->iph_ttl = 64;

                    //swap src and dest
                    swapSrcDest(ip_header);
                    // Create raw socket for IP-RAW
                    struct sockaddr_in dest_in;
                    memset(&dest_in, 0, sizeof(struct sockaddr_in));
                    dest_in.sin_family = AF_INET;
                    dest_in.sin_addr = ip_header->iph_destip;
                    createRawSocket(ip_header);
                }
            }
        }
    }
}

void swapSrcDest(struct ipheader *ip_header) {
    unsigned int oldSrc = ip_header->iph_sourceip.s_addr;
    ip_header->iph_sourceip.s_addr = ip_header->iph_destip.s_addr;
    ip_header->iph_destip.s_addr = oldSrc;
}


void createRawSocket(const struct ipheader *ip_header) {
    int enable = 1;
    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) {
        printf("Error: in opening new raw socket %d\n", errno);
        exit(-1);
    }
    // Step 2: Set socket option.
    int set = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    if (set == -1) {
        printf("Error: in setting enable option in socket %d\n", errno);
        exit(-1);
    }
    // Step 3: Provide needed information about destination.
    struct sockaddr_in inAddr;
    inAddr.sin_family = AF_INET;
    inAddr.sin_addr = ip_header->iph_destip;
//     Step 4: Send the packet out.
    int bytesSent = sendto(sock, ip_header, ntohs(ip_header->iph_len), 0, (struct sockaddr *) &inAddr,
                           sizeof(inAddr));
    if (bytesSent == -1) {
        printf("Error in sending ICMP echo reply %d \n", errno);
        exit(-1);
    }
    printf("Sent a fake ICMP ECHO reply\n");
}


//checksum function to add to the icmp header
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

int main(int argc, char **argv) {
    char *dev = argv[1];
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 mask;      /* Our netmask */

    bpf_u_int32 net = 0;
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Failed to connect to device\n");
        exit(-1);
    }
    printf("Connect to %s\n", dev);
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);   //Close the handle
    return 0;
}