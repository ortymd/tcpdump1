#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <functions.h>

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const size_t num_of_devices = 1<<3;
	pcap_if_t **alldevsp = malloc( num_of_devices * sizeof(pcap_if_t) );
	pcap_t *dev_handle;

	if( pcap_findalldevs(alldevsp, errbuf) != 0 ) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
  }
	
	int i = request_device(alldevsp);
	if ( i == -1) {
		printf("Exiting.\n");
		return 0;
	}

	return(0);
}

