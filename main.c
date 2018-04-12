#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <functions.h>
#include <signal.h>
#include <errno.h>

pcap_t *dev_handle;
int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const size_t num_of_devices = 1<<3;
	int snaplen = 1<<12;
	int timeout = 1<<10;
	int promisc_mode = 0, result;
#ifdef TEST
	int	cnt = -1;
#else
	int cnt = 1<<10;		// num of packets to parse. -1 for infinity
#endif
	pcap_if_t **alldevsp = malloc( num_of_devices * sizeof(pcap_if_t) );
	pcap_if_t *chosen_dev = NULL;

	struct sigaction act;
	result = setup_signal(&act);
	if(result < 0){
		fprintf(stderr, "Failed to setup signal for application: %d\n", errno );
		return 2;
	}


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

	printf("Starting pcap:\n");
	result = pcap_loop(dev_handle, cnt, parse_packet, NULL);
	if(result == -1) {
		fprintf(stderr, "pcap_loop failed:\t%s\n", errbuf);
		pcap_perror(dev_handle, "pcap failed reason:\t");
	}
	else if(result == -2 ){	// pcap_breakloop called
		printf("Stopping pcap:\n");
		printf("Dump data\n");
		dump_data();
	}
	else if(result == 0){
		printf("Dump data\n");
		dump_data();
	}

	pcap_close(dev_handle);
	printf("Done.\n");
	return 0;
}

