#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

//constants
#define ICMP_HDRLEN 8
#define SERVER_PORT 3000
#define SERVER_IP "127.0.0.1"

//functions signatures
unsigned short calculate_checksum(unsigned short *paddress, int len);

int clientTCPSocketSetup();

void
pingFlow(const char *destIP, int rawSocket, int ttl, struct sockaddr_in *dest_in, int clientTCPSocket,
         struct timeval *start, struct timeval *end, struct icmp *icmphdr, const char *data, size_t dataLen);

void createRawSocket(int *rawSocket, int *ttl);

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Destination IP parameter is undecleared%d\n", errno);
        exit(-1);
    }

    char *args[2];
    char *destIP = argv[1];
    args[0] = "./watchdog";
    args[1] = NULL;
    //create a raw socket
    int rawSocket;
    int ttl;
    createRawSocket(&rawSocket, &ttl);
    //start a new process and execute ./watchdog1
    int pid = fork();
    if (pid == 0) {

        printf("in watchdog process \n");
        execvp(args[0], args);
    }
    sleep(1);
    printf("better ping process\n");
    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr(destIP);

    // Opening a new socket connection
    int clientTCPSocket = clientTCPSocketSetup();
    if (clientTCPSocket == -1) {
        printf("error\n");
        close(clientTCPSocket);
        close(rawSocket);
        exit(-1);
    }

    struct timeval start, end;
    struct icmp icmphdr; // ICMP-header
    struct icmp *pointerIcmp = &icmphdr;
    char data[IP_MAXPACKET] = "Sending a ping message\n";
    size_t dataLen = strlen(data) + 1;
    icmphdr.icmp_seq = 0;
    printf("PING %s (%s) %zu data bytes \n", destIP, destIP, dataLen);
    while (1) {
        icmphdr.icmp_cksum = 0;
        icmphdr.icmp_type = ICMP_ECHO;
        icmphdr.icmp_code = 0;
        icmphdr.icmp_id = 18;
        pingFlow(destIP, rawSocket, ttl, &dest_in, clientTCPSocket, &start, &end, &icmphdr, data, dataLen);
    }
    return 0;
}

//create a raw socket and set the ttl to 64
void createRawSocket(int *rawSocket, int *ttl) {
    (*rawSocket) = -1;
    (*ttl) = 64;
    if (((*rawSocket) = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        close((*rawSocket));
        exit(-1);
    }
    if (setsockopt((*rawSocket), IPPROTO_IP, IP_TTL, ttl, sizeof(*ttl)) < 0) {
        fprintf(stderr, "setsockopt() failed with error: %d", errno);
        close((*rawSocket));
        exit(-1);
    }
}

void
pingFlow(const char *destIP, int rawSocket, int ttl, struct sockaddr_in *dest_in, int clientTCPSocket,
         struct timeval *start, struct timeval *end, struct icmp *icmphdr, const char *data, size_t dataLen) {
    char packet[IP_MAXPACKET];
    memcpy((packet), icmphdr, ICMP_HDRLEN);
    memcpy(packet + ICMP_HDRLEN, data, dataLen);
    (*icmphdr).icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + dataLen);
    memcpy((packet), icmphdr, ICMP_HDRLEN);
    // Calculate the ICMP header checksum
    gettimeofday(start, NULL);
    // Send the packet using sendto() for sending using rawsocket to the given ip.
    int bytes_sent = sendto(rawSocket, packet, ICMP_HDRLEN + dataLen, 0, (struct sockaddr *) dest_in,
                            sizeof(*dest_in));
    if (bytes_sent == -1) {
        fprintf(stderr, "sendto() failed with error: %d", errno);
        close(clientTCPSocket);
        close(rawSocket);
        exit(-1);
    }

    //send a message to the watchdog in order to let it know everything works correctly
    char *ping = "ping";
    int signalSend = send(clientTCPSocket, ping, strlen(ping), 0);
    if (signalSend == -1) {
        printf("Send() failed with error code : %d\n", errno);
        close(clientTCPSocket);
        close(rawSocket);
        exit(-1);
    } else if (signalSend == 0) {
        printf("Peer has closed the TCP connection prior to send().\n");
        close(clientTCPSocket);
        close(rawSocket);
        exit(-1);
    }

    bzero(packet, IP_MAXPACKET);
    socklen_t len = sizeof(*dest_in);
    ssize_t bytes_received;
    int status = 0;
    // Get the ping response
    while ((bytes_received = recvfrom(rawSocket, packet, sizeof(packet), MSG_DONTWAIT, (struct sockaddr *) dest_in,
                                      &len))) {
        if (waitpid(0, &status, WNOHANG) != 0) {
            printf("server <%s> cannot be reached\n",destIP);
            close(rawSocket);
            close(clientTCPSocket);
            exit(-1);
        }
        if (bytes_received > 0) {
            struct iphdr *iphdr = (struct iphdr *) packet;
            struct icmphdr *icmphdr = (struct icmphdr *) (packet + (iphdr->ihl * 4));
            break;
        }
    }
    gettimeofday(end, NULL);
    float milliseconds = ((*end).tv_sec - (*start).tv_sec) * 1000.0f + ((*end).tv_usec - (*start).tv_usec) / 1000.0f;
    //print the info about the ping and the time it took in milliseconds
    printf("%d bytes from %s icmp_seq=%d ttl=%d time=%.2f ms\n",
           bytes_sent, destIP, ++icmphdr->icmp_seq, ttl, (milliseconds));
    sleep(1);
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

//create a new tcp socket and connect to the watchdog's tcp socket
int clientTCPSocketSetup() {
    int pingSocket;
    //creating a new tcp socket
    if ((pingSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("Failed to open a TCP connection : %d", errno);
        exit(-1);
    }
    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    int binaryAddress = inet_pton(AF_INET, (const char *) SERVER_IP, &serverAddress.sin_addr);
    if (binaryAddress <= 0) {
        printf("Failed to convert from text to binary : %d", errno);
    }
    // Connecting to the watchdog's socket
    int connection = connect(pingSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
    if (connection == -1) {
        printf("Connection error : %d\n", errno);
        close(pingSocket);
        exit(-1);
    }
    return pingSocket;
}
