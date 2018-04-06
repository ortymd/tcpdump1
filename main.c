#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>    //For ETH_P_ALL
#include <net/ethernet.h>        //For ether_header
#include <arpa/inet.h>
#include <string.h>

#include "functions.h"

struct sockaddr_in source,dest;
extern mac_data mac_dest_arr[];
extern mac_data mac_source_arr[];

int main(int argc, char **argv) {

	int sock_raw;
	struct sockaddr_in saddr;
	const size_t saddr_size = sizeof saddr;
	size_t data_size;
	const size_t bufsize = 4096;	
	size_t space_left = bufsize;
  unsigned char *buffer = malloc(bufsize); 
	unsigned char *bufptr = buffer;

	sock_raw = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sock_raw < 0)
	{
		perror( "error in socket\n" );
		return 1;
	}

	printf("Starting...\n");

	while (space_left > 0)
	{
		data_size = recvfrom(sock_raw , bufptr, space_left, 0, (struct sockaddr*)&saddr , (socklen_t*)&saddr_size);
		store_mac(bufptr);
		bufptr += data_size;
		space_left -= data_size;
	}

	dump_data(mac_dest_arr, mac_source_arr);

	return 0;
}
