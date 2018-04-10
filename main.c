#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

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
	
	unsigned i = 0;
	while(alldevsp[i] != NULL){
		printf("Device %d:\n %s\n", i, alldevsp[i]->name);
		++i;
	}

	// if( dev_handle = pcap_open_live(alldevsp[0]
	
	return(0);
}

