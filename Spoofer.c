#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include<netinet/udp.h>    //Provides declarations for udp header
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

char *destIP = NULL;
char *srcIP = NULL;
struct sockaddr_in destInfo;
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


void send_raw_ip_packet(struct iphdr *ip_header) {
    char packetBuffer[IP_MAXPACKET];
    struct sockaddr_in dest_info;
    int enable = 1;
    // Step 1: Create a raw network socket.
    int rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rawSocket == -1) {
        printf("Error: in opening new raw socket %d\n", errno);
        exit(-1);
    }
    // Step 2: Set socket option.
    int set = setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    if (set == -1) {
        printf("Error: in setting enable option in socket %d\n", errno);
        exit(-1);
    }
    // Step 3: Provide needed information about destination.
    memset(&destInfo, 0, sizeof(destInfo));
    destInfo.sin_family = AF_INET;
    destInfo.sin_addr.s_addr = ip_header->daddr;
    // Step 4: Send the packet out.
    int bytesSent = sendto(rawSocket, ip_header, ntohs(ip_header->tot_len), 0, (struct sockaddr *) &dest_info,
                           sizeof(dest_info));
    if (bytesSent == -1) {
        printf("Error in sending ICMP message %d\n", errno);
        exit(-1);
    }
    printf("Sent a spoofed packet using the fake IP: %s to src IP: %s\n", srcIP, destIP);
    close(rawSocket);
}

int main(int argc, char **argv) {
    char buffer[1500];
    memset(buffer, 0, 1500);
    destIP = argv[2];
    srcIP = argv[1];
    /*********************************************************
       Step 1: Fill in the ICMP header.
     ********************************************************/
    struct icmphdr *icmp = (struct icmphdr *) (buffer + sizeof(struct iphdr));
    icmp->type = ICMP_ECHO; //ICMP Type: 8 is request, 0 is reply.

    // Calculate the checksum for integrity
    icmp->checksum = 0;
    icmp->checksum = in_cksum((unsigned short *) icmp,
                              sizeof(struct icmphdr));

    /*********************************************************
       Step 2: Fill in the IP header.
     ********************************************************/
    struct iphdr *ip_header = (struct iphdr *) buffer;
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->ttl = 60;
    ip_header->saddr = inet_addr(srcIP);
    ip_header->daddr = inet_addr(destIP);
    ip_header->protocol = IPPROTO_ICMP;
    ip_header->tot_len = htons(sizeof(struct iphdr) +
                               sizeof(struct icmphdr));
    /*********************************************************
       Step 3: Finally, send the spoofed packet
     ********************************************************/
    send_raw_ip_packet(ip_header);
    return 0;
}