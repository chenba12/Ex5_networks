CC = gcc
CFLAGS = -Wall -g
all: SniffAndSpoof watchdog betterping

SniffAndSpoof: SniffAndSpoof.c
	$(CC) $(CFLAGS) SniffAndSpoof.c -o SniffAndSpoof -lpcap
watchdog: watchdog.c
	$(CC) $(CFLAGS) watchdog.c -o watchdog
PartB:betterping.c
	$(CC) $(CFLAGS) betterping.c -o PartB
clean:
	rm -f *.o  PartB watchdog SniffAndSpoof
