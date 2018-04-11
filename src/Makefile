CFLAGS+=-g3 -Wall -I../include_pcap -I../include
LDFLAGS+=-L../
LDLIBS+=-l:libpcap.a

functions.o:	functions.c
	$(CC) -c $(CFLAGS) -o $@ $^
