#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <functions.h>

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const size_t num_of_devices = 1<<3;
	int snaplen = 1<<12;
	int timeout = 1<<10;
	int promisc_mode = 0, result;
	int cnt = 1<<5;		// num of packets to parse. -1 for infinity
	pcap_if_t **alldevsp = malloc( num_of_devices * sizeof(pcap_if_t) );
	pcap_if_t *chosen_dev = NULL;
	pcap_t *dev_handle;

	if( pcap_findalldevs(alldevsp, errbuf) != 0 ) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return 2;
  }
	
	chosen_dev = request_device(alldevsp);
	if (chosen_dev == NULL) {
		printf("Exiting.\n");
		return 0;
	}

	dev_handle = pcap_open_live(chosen_dev->name, snaplen, promisc_mode, timeout, errbuf);
	if(dev_handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", chosen_dev->name, errbuf);
		return 2;
	}

	result = pcap_loop(dev_handle, cnt, parse_packet, NULL);

	printf("Done.\n");
	return 0;
}

