#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>

//constants
#define SERVER_PORT 3000
#define SERVER_IP "127.0.0.1"

//functions signatures
int watchdogSocketSetup();

int watchdogTimer(int pingSocket);


int main() {
    //create a new tcp socket for the watchdog
    int watchdogSocket = watchdogSocketSetup();
    printf("Waiting for incoming TCP-connections...\n");
    struct sockaddr_in clientAddress;  //
    socklen_t clientAddressLen = sizeof(clientAddress);
    memset(&clientAddress, 0, sizeof(clientAddress));
    clientAddressLen = sizeof(clientAddress);
    //watchdog is ready to get new tcp messages
    while (1) {
        //Accepting a new client connection
        int pingSocket = accept(watchdogSocket, (struct sockaddr *) &clientAddress, &clientAddressLen);
        if (pingSocket == -1) {
            printf("accept failed with error code : %d\n", errno);
            close(pingSocket);
            close(watchdogSocket);
            exit(-1);
        }
        printf("A new client connection accepted\n");
        //setup the timer and receive messages
        watchdogTimer(pingSocket);
        //if the timer passed 10 seconds without receiving anything it will close the sockets and let the better ping process
        //that the program ended
        close(pingSocket);
        close(watchdogSocket);
        exit(-1);
    }
    return 0;
}

int watchdogSocketSetup() {
    int watchdogSocket;
    //Opening a new TCP socket
    if ((watchdogSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("Failed to open a TCP connection : %d", errno);
        close(watchdogSocket);
        exit(-1);
    }
    //Enabling reuse of the port
    int enableReuse = 1;
    int ret = setsockopt(watchdogSocket, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(int));
    if (ret < 0) {
        printf("setSockopt() reuse failed with error code : %d", errno);
        close(watchdogSocket);
        exit(-1);
    }

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP);
    serverAddress.sin_port = htons(SERVER_PORT);
    //bind() associates the socket with its local address 127.0.0.1
    int bindResult = bind(watchdogSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
    if (bindResult == -1) {
        printf("Bind failed with error code : %d\n", errno);
        close(watchdogSocket);
        exit(-1);
    }
    //Preparing to accept new in coming requests
    int listenResult = listen(watchdogSocket, 10);
    if (listenResult == -1) {
        printf("Bind failed with error code : %d\n", errno);
        close(watchdogSocket);
        exit(-1);
    }
    return watchdogSocket;
}

//receiving a message every second if nothing has been received break the loop and return
int watchdogTimer(int pingSocket) {
    int timer = 0;
    char messageReceived[5];
    while (timer < 10) {
        sleep(1);
        int bytes;
        timer++;
        if (timer == 10) {
            break;
        }
        while ((bytes = recv(pingSocket, messageReceived, 5, MSG_DONTWAIT))) {
            if (bytes > 0) {
                timer = 0;
            } else {
                break;
            }
        }
    }
    return -1;
}

