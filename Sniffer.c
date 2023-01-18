#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdlib.h>         // for exit()
#include <netinet/udp.h>    //Provides declarations for udp header
#include <netinet/tcp.h>    //Provides declarations for tcp header
#include <netinet/ip.h>     //Provides declarations for ip header
#include <netinet/ether.h>
#include <time.h>

void printData(const u_char *data, unsigned int size);

FILE *file;

typedef struct app_header {
    uint32_t unixtime;
    uint16_t total_length;
    union {
        uint16_t flags;
        uint16_t _: 3, c_flag: 1, s_flag: 1, t_flag: 1, status: 10;
    };
    uint16_t cache;
    uint16_t padding;
} cpack, *pcpack;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    unsigned int size = header->len;
    if (size > 0) {
        printf("Got a new packet!\n");
        struct ether_header *ether_header = (struct ether_header *) packet;

        struct iphdr *ip_header = (struct iphdr *) (packet + sizeof(struct ether_header));
        int iphdrlen = ip_header->ihl * 4;

        struct tcphdr *tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + iphdrlen);
        unsigned long tcphdrlen = tcp_header->doff * 4;

        pcpack app_header = (pcpack) (packet + sizeof(struct ether_header) + iphdrlen + tcphdrlen);
        unsigned long header_size = sizeof(struct ether_header) + iphdrlen + tcphdrlen + 12;
        //Print out ethernet, IP and TCP headers
        fprintf(file, "******************************************************\n");
        fprintf(file, "Ethernet Layer\n");
        fprintf(file, "Source MAC: %s\n", ether_ntoa((const struct ether_addr *) &ether_header->ether_shost));
        fprintf(file, "Destination MAC: %s\n",
                ether_ntoa((const struct ether_addr *) &ether_header->ether_dhost));
        fprintf(file, "******************************************************\n");
        fprintf(file, "IP Layer\n");
        fprintf(file, "Source IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->saddr));
        fprintf(file, "Destination IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->daddr));
        fprintf(file, "******************************************************\n");
        fprintf(file, "TCP Layer\n");
        if ((tcp_header->th_flags & TH_SYN) && (tcp_header->th_flags & TH_ACK)) {
            fprintf(file, "This is a SYN-ACK packet\n");
        } else if (tcp_header->th_flags & TH_SYN) {
            fprintf(file, "This is a SYN packet\n");
        }
        if (tcp_header->th_flags & TH_ACK) {
            fprintf(file, "This is a ACK packet\n");
        }
        if ((tcp_header->th_flags & TH_FIN) && (tcp_header->th_flags & TH_ACK)) {
            fprintf(file, "This is a FIN-ACK packet\n");
        } else if (tcp_header->th_flags & TH_FIN) {
            fprintf(file, "This is a FIN packet\n");
        }
        if ((tcp_header->th_flags & TH_PUSH) && (tcp_header->th_flags & TH_ACK)) {
            fprintf(file, "This is a PSH-ACK packet\n");
        } else if (tcp_header->th_flags & TH_PUSH) {
            fprintf(file, "This is a PSH packet\n");
        }
        fprintf(file, "Source Port: %d\n", ntohs(tcp_header->source));
        fprintf(file, "Destination Port: %d\n", ntohs(tcp_header->dest));
        fprintf(file, "******************************************************\n");
        fprintf(file, "Application Layer\n");
        time_t seconds = ntohl(app_header->unixtime) / 1000;
        struct tm *timeinfo = gmtime(&seconds);
        uint16_t flags = app_header->flags;
        u_char c_flag = flags >> 14 & 1;
        u_char s_flag = flags >> 13 & 1;
        u_char t_flag = flags >> 12 & 1;
        uint16_t status = (app_header->flags >> 2) & 0x03FF;
        uint16_t cache = ntohs(app_header->cache);
        uint16_t padding = ntohs(app_header->padding);
        fprintf(file, "Timestamp: %s", asctime(timeinfo));
        fprintf(file, "Length: %hu\n", ntohs(app_header->total_length));
        fprintf(file, "c_flag: %d\n", c_flag);
        fprintf(file, "s_flag: %d\n", s_flag);
        fprintf(file, "t_flag: %d\n", t_flag);
        fprintf(file, "Status: %d\n", status);
        fprintf(file, "Cache: %d\n", cache);
        fprintf(file, "Padding: %d\n", padding);
        fprintf(file, "******************************************************\n");
        printData(packet + header_size, size);

    }
}

void printData(const u_char *data, unsigned int size) {
    int i, j;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)   //if one line of hex printing is complete...
        {
            fprintf(file, "         ");
            for (j = i - 16; j < i; j++) {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(file, "%c", (unsigned char) data[j]); //if its a number or alphabet

                else fprintf(file, "."); //otherwise print a dot
            }
            fprintf(file, "\n");
        }

        if (i % 16 == 0) fprintf(file, "   ");
        fprintf(file, " %02X", (unsigned int) data[i]);

        if (i == size - 1)  //print the last spaces
        {
            for (j = 0; j < 15 - i % 16; j++) {
                fprintf(file, "   "); //extra spaces
            }

            fprintf(file, "         ");

            for (j = i - i % 16; j <= i; j++) {
                if (data[j] >= 32 && data[j] <= 128) {
                    fprintf(file, "%c", (unsigned char) data[j]);
                } else {
                    fprintf(file, ".");
                }
            }
            fprintf(file, "\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Failed to connect to device \n");
        exit(-1);
    }
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    file = fopen("315800961_318417763.txt", "w");
    if (file == NULL) {
        printf("Unable to create file.");
    }
    // Step 3: Capture packets
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);   //Close the handle
    fclose(file);
    return 0;
}