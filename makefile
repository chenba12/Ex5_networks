CC = gcc
CFLAGS = -Wall -g
all: Sniffer Spoofer
Sniffer: Sniffer.c
	$(CC) $(CFLAGS) Sniffer.c -o Sniffer -lpcap

Spoofer: Spoofer.c
	$(CC) $(CFLAGS) Spoofer.c -o Spoofer -lpcap
clean:
	rm -f *.o Sniffer Spoofer
