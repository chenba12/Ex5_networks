CC = gcc
CFLAGS = -Wall -g
all: Sniffer Spoofer
Sniffer: Sniffer.c
	$(CC) $(CFLAGS) Sniffer.c -o Sniffer -lpcap

Spoofer: Spoofer2.c
	$(CC) $(CFLAGS) Spoofer2.c -o Spoofer -lpcap
clean:
	rm -f *.o Sniffer Spoofer
