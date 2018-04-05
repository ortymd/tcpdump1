#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>    //For ETH_P_ALL
#include <net/ethernet.h>        //For ether_header
#include <arpa/inet.h>
#include <string.h>

#include <pcap.h>
#include "functions.h"

struct sockaddr_in source,dest;
extern GTree *tree_dest;

int main(int argc, char **argv) {

	int sock_raw;
	struct sockaddr_in saddr;
	const size_t entries = 1<<10;
	const size_t saddr_size = sizeof saddr;
	FILE *log_dest, *log_source;
	size_t data_size;
	const size_t bufsize = 4096;
	size_t space_left = bufsize;
  unsigned char *buffer = (unsigned char *) malloc(bufsize); 
	unsigned char *bufptr = buffer;

	sock_raw = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sock_raw < 0)
	{
		perror( "error in socket\n" );
		return 1;
	}

	if(open_files(&log_dest, &log_source) != 0)
	{
		perror("Unable to create log.txt file.");
		return 1;
	}
	create_trees();

	printf("Starting...\n");

	while (space_left > 0)
	{
		data_size = recvfrom(sock_raw , bufptr, space_left, 0, (struct sockaddr*)&saddr , (socklen_t*)&saddr_size);
		store_mac(bufptr);
		bufptr += data_size;
		space_left -= data_size;
	}

	dump_tree(tree_dest);

	return 0;
}

int open_files(FILE **log_out, FILE **log_in)
{
  *log_out=fopen("log_out.txt","a");
  *log_in=fopen("log_in.txt","a");
	if (log_in && log_out != NULL)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

void print_ethernet_header(unsigned char* buffer, FILE *log_out, FILE *log_in)
{
	struct ethhdr *eth = (struct ethhdr *)buffer;

	fprintf(log_out , "dest : %.2x%.2x%.2x%.2x%.2x%.2x \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(log_in , "source: %.2x%.2x%.2x%.2x%.2x%.2x \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
}

char *get_active_devices(void)
{
    char *device; /* Name of device (e.g. eth0, wlan0) */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

    /* Find a device */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    printf("Network device found: %s\n", device);
    return 0;
}
