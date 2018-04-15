CFLAGS=-g3 -Wall -I./include_pcap -I./include
LDFLAGS=-L./
LDLIBS=-l:libpcap.a -l:functions.o

all: main functions

main: main.o functions ./include/functions.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ main.o $(LDLIBS)

export LDFLAGS+=-L./src/

.PHONY:	functions clean

functions:
	$(MAKE) -C src/

clean:
	rm *.o src/*.o

