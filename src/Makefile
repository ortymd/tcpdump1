CFLAGS+=-g3 -Wall -I../include_pcap -I../include
LDFLAGS+=-L../

.PHONY: all
all: filter.o functions.o

filter.o:	filter.c
	$(CC) -c $(CFLAGS) -o $@ $^

functions.o:	functions.c
	$(CC) -c $(CFLAGS) -o $@ $^
