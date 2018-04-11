#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <functions.h>

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const size_t num_of_devices = 1<<3;
	pcap_if_t **alldevsp = malloc( num_of_devices * sizeof(pcap_if_t) );
	pcap_if_t *chosen_dev = NULL;
	pcap_t *dev_handle;

	if( pcap_findalldevs(alldevsp, errbuf) != 0 ) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
  }
	
	chosen_dev = request_device(alldevsp);
	if (chosen_dev == NULL) {
		printf("Exiting.\n");
		return 0;
	}

	return(0);
}

