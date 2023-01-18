#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>

int port;

int clientSocketUDPSetup();

int serverSocketUDPSetup();

int main(int argc, char **argv) {
    char *host = argv[1];
    sscanf(host, "%d", &port);
    char *packet[BUFSIZ];
    int clientSocketUDP = clientSocketUDPSetup();
    int serverSocketUDP = serverSocketUDPSetup();

    struct sockaddr_in clientAddress;
    socklen_t clientAddressLen;
    printf("waiting for messages...\n");

    while (1) {
        memset((char *) &clientAddress, 0, sizeof(clientAddress));
        clientAddressLen = sizeof(clientAddress);
        int receivedBytes = recvfrom(serverSocketUDP, packet, BUFSIZ, 0, (struct sockaddr *) &clientAddress,
                                     &clientAddressLen);
        if (receivedBytes == -1) {
            printf("recvfrom() failed with error code : %d", errno);
            close(clientSocketUDP);
            close(serverSocketUDP);
            exit(-1);
        }
        printf("received message\n");
        float randomNumber = ((float) random()) / ((float) RAND_MAX);
        printf("random is %f\n", randomNumber);
        //echo -n this-is-a-message | nc -4u -w1 10.9.0.0 8000
        if (randomNumber > 0.5) {
            //send
            int sentBytes = sendto(clientSocketUDP, packet, receivedBytes, 0, (struct sockaddr *) &clientAddress,
                                   clientAddressLen);
            if (sentBytes == -1) {
                printf("sendto() failed with error code : %d", errno);
                close(clientSocketUDP);
                close(serverSocketUDP);
                exit(-1);
            }
            printf("sent message\n");
        }
    }
    close(clientSocketUDP);
    close(serverSocketUDP);
    return 0;
}

//create a new tcp socket and connect to the watchdog's tcp socket
int clientSocketUDPSetup() {
    int clientSocketUDP;
    //Opening a new TCP socket
    if ((clientSocketUDP = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        printf("Failed to open a server UDP connection : %d", errno);
        close(clientSocketUDP);
        exit(-1);
    }
    //Enabling reuse of the port
    int enableReuse = 1;
    int ret = setsockopt(clientSocketUDP, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(int));
    if (ret < 0) {
        printf("setSockopt() reuse failed with error code : %d", errno);
        close(clientSocketUDP);
        exit(-1);
    }

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port + 1);
    //bind() associates the socket with its local address 127.0.0.1
    int bindResult = bind(clientSocketUDP, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
    if (bindResult == -1) {
        printf("Bind failed with error code : %d\n", errno);
        close(clientSocketUDP);
        exit(-1);
    }

    return clientSocketUDP;
}

int serverSocketUDPSetup() {
    int serverSocketUDP;
    //Opening a new TCP socket
    if ((serverSocketUDP = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        printf("Failed to open a server UDP connection : %d", errno);
        close(serverSocketUDP);
        exit(-1);
    }
    //Enabling reuse of the port
    int enableReuse = 1;
    int ret = setsockopt(serverSocketUDP, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(int));
    if (ret < 0) {
        printf("setSockopt() reuse failed with error code : %d", errno);
        close(serverSocketUDP);
        exit(-1);
    }

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);
    //bind() associates the socket with its local address 127.0.0.1
    int bindResult = bind(serverSocketUDP, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
    if (bindResult == -1) {
        printf("Bind failed with error code : %d\n", errno);
        close(serverSocketUDP);
        exit(-1);
    }
    return serverSocketUDP;
}
