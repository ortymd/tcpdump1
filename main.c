#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <functions.h>
#include <filter.h>
#include <signal.h>
#include <errno.h>

pcap_t *dev_handle;
char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const size_t num_of_devices = 1<<3;
	int snaplen = 1<<12;
	int timeout = 1<<10;
	int promisc_mode = 0, check;
#if TEST
	int cnt = 40;
#else
	int	cnt = -1;
#endif
	pcap_if_t **alldevsp = malloc( num_of_devices * sizeof(pcap_if_t) );
	pcap_if_t *chosen_dev = NULL;

	struct sigaction act;
	check = setup_signal(&act);
	if(check < 0){
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

	check = setup_filter(dev_handle);
	if(check < 0){
		fprintf(stderr, "pcap_compile failed:\t%s\n", errbuf);
		pcap_perror(dev_handle, "pcap failure reason:\t");
		fprintf(stdin, "\nCapturing on all ports!\n");
	}
	else{
		;
	}
	
	printf("Starting pcap:\n");
	check = pcap_loop(dev_handle, cnt, parse_packet, NULL);
	if(check == -1) {
		fprintf(stderr, "pcap_loop failed:\t%s\n", errbuf);
		pcap_perror(dev_handle, "pcap failed reason:\t");
	}
	else if(check == -2 ){	// pcap_breakloop called
		printf("Stopping pcap:\n");
		printf("Dump data\n");
		dump_data();
	}
	else if(check == 0){
		printf("Dump data\n");
		dump_data();
	}

	pcap_close(dev_handle);
	printf("Done.\n");
	return 0;
}

