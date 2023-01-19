CC = gcc
CFLAGS = -Wall -g
all: Sniffer Spoofer Gateway SniffAndSpoof
Sniffer: Sniffer.c
	$(CC) $(CFLAGS) Sniffer.c -o Sniffer -lpcap

Spoofer: Spoofer.c
	$(CC) $(CFLAGS) Spoofer.c -o Spoofer -lpcap

SniffAndSpoof: SniffAndSpoof.c
	$(CC) $(CFLAGS) SniffAndSpoof.c -o SniffAndSpoof -lpcap

Gateway: Gateway.c
	$(CC) $(CFLAGS) Gateway.c -o Gateway -lpcap

clean:
	rm -f *.o
