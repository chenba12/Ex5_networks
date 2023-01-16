#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include<stdlib.h> // for exit()
#include<netinet/udp.h>    //Provides declarations for udp header
#include<netinet/tcp.h>    //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include <netinet/ether.h>
#include <time.h>

FILE *file;

void printData(const u_char *data, int size);

typedef struct calculatorPacket {
    uint32_t unixtime;
    uint16_t length;
    uint16_t reserved: 3, c_flag: 1, s_flag: 1, t_flag: 1, status: 10;
    uint16_t cache;
    uint16_t padding;
} cpack, *pcpack;

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    unsigned int size = h->len;
    struct ether_header *ether_header = (struct ether_header *) bytes;
    struct iphdr *ip_header = (struct iphdr *) (bytes + sizeof(struct ether_header));
    struct tcphdr *tcp_header = (struct tcphdr *) (bytes + sizeof(struct ether_header) + sizeof(struct iphdr));
    pcpack app_header = (pcpack) (bytes + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    int iphdrlen = ip_header->ihl * 4;
//    unsigned long header_size = sizeof(struct ether_header) + iphdrlen + tcp_header->doff * 4 + sizeof(app_header) + 12;
    unsigned long header_size = sizeof(struct ether_header) + iphdrlen + iphdrlen + sizeof(pcpack);
    //Print out ethernet, IP and TCP headers
    fprintf(file, "******************************************************\n");
    fprintf(file, "Ethernet Layer\n");
    fprintf(file, "Source MAC: %s\n", ether_ntoa((const struct ether_addr *) &ether_header->ether_shost));
    fprintf(file, "Destination MAC: %s\n", ether_ntoa((const struct ether_addr *) &ether_header->ether_dhost));
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
    time_t seconds = app_header->unixtime / 1000;
    struct tm *timeinfo = gmtime(&seconds);
    fprintf(file, "Timestamp: %s", asctime(timeinfo));
    fprintf(file, "Length: %d\n", app_header->length);
    fprintf(file, "Reserved: %d\n", app_header->reserved);
    fprintf(file, "c_flag: %d\n", app_header->c_flag);
    fprintf(file, "s_flag: %d\n", app_header->s_flag);
    fprintf(file, "t_flag: %d\n", app_header->t_flag);
    fprintf(file, "Status: %d\n", app_header->status);
    fprintf(file, "Cache: %d\n", app_header->cache);
    fprintf(file, "Padding: %d\n", app_header->padding);
    fprintf(file, "******************************************************\n");
    printData(bytes + header_size-62, size);

}

void printData(const u_char *data, int size) {
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
        printf("failed\n");
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