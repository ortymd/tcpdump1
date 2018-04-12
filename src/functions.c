#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>

#include <functions.h>
#include <mac_data.h>

static const unsigned input_sz = 1<<3;
#define arr_sz 1<<5 
mac_data mac_arr[arr_sz];	// here we store macs and their quantity
static unsigned cur_sz = 0;
extern pcap_t *dev_handle;

pcap_if_t* request_device(pcap_if_t **alldevsp){
	char user_input[input_sz];
	pcap_if_t *chosen_dev = NULL;

	print_active_devs(alldevsp);
	while ( chosen_dev == NULL ) {
#ifdef TEST
		strncpy(user_input, "enp0s8", 6);
		printf("Chosen device: %s\n", user_input);
#else
		printf("Input device. Input 0 for exit:\n");
		scanf("%[^\n]%*c", user_input);
#endif

		if(strncmp(user_input, "0", 1) == 0){
			break;
		}
		else{
			chosen_dev = find_device(user_input, alldevsp);
			if (chosen_dev != NULL){
				break;
			}
		}
		printf("\nDevice not found.\n");
		print_active_devs(alldevsp);
	}

	return chosen_dev;
}

void print_active_devs(pcap_if_t **alldevsp){
	pcap_if_t *dev = alldevsp[0]; 
	printf("Checking active devices...\n");

	while (dev != NULL && (dev->flags & PCAP_IF_UP)){
		printf("Device:\t%s\n", dev->name);	
		dev = dev->next;
	}
}

pcap_if_t* find_device(char *user_input, pcap_if_t **alldevsp){
	pcap_if_t *check = alldevsp[0]; 
	pcap_if_t *dev = NULL; 

	while (dev == NULL && (check->flags & PCAP_IF_UP)){
		if(strncmp(user_input, check->name, input_sz) == 0){
			dev = check;
			break;
		}
		check = check->next;
	}

	return dev;
}

void parse_packet(u_char *args, const struct pcap_pkthdr *h, const u_char *bufptr){
	static u_char mac_dest[macsize];
	static u_char mac_src[macsize];
	static mac_data *mac_tmp;

	get_mac(bufptr, mac_dest, mac_src);	

	mac_tmp = find(mac_dest, mac_src, mac_arr, cur_sz);
	if( mac_tmp == NULL )
	{
		for (unsigned j=0; j < macsize; ++j){
			mac_arr[cur_sz].dest[j] |= mac_dest[j];
			mac_arr[cur_sz].src[j] |= mac_src[j];
		}
		mac_arr[cur_sz].cnt += 1;
		++cur_sz;
	}
	else
	{
		mac_tmp->cnt += 1;
	}
}

mac_data* find(u_char *mac_dest, u_char *mac_src, mac_data *arr, unsigned cur_sz) {
	for (unsigned i=0; i < cur_sz; ++i) {
		if( memcmp(mac_dest, arr[i].dest, macsize) == 0 && memcmp(mac_src, arr[i].src, macsize) == 0 ) 
				return &arr[i];
		}
	return NULL;
}

int get_mac1(const u_char *bufptr, u_char *mac_dest,  u_char *mac_src)
{
	struct ethhdr *eth = (struct ethhdr *)bufptr;

	for (unsigned j=0; j < macsize; ++j){
			mac_dest[j] |= eth->h_dest[j];
			mac_src[j] |= eth->h_source[j];
	}

	return 0;
}

int get_mac(const u_char *bufptr, u_char *mac_dest,  u_char *mac_src)
{
	struct ethhdr *eth = (struct ethhdr *)bufptr;
	memcpy(mac_dest, eth->h_dest, macsize);
	memcpy(mac_src, eth->h_source, macsize);
			
	return 0;
}

int dump_data() {
	FILE *log;
	log = fopen("log.txt", "a");

	for( unsigned i = 0; i < cur_sz; ++i) {
			fprintf(log, "\ndest:\t%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx\n", mac_arr[i].dest[0], mac_arr[i].dest[1],mac_arr[i].dest[2],mac_arr[i].dest[3],mac_arr[i].dest[4],mac_arr[i].dest[5]);
			fprintf(log, "src:\t%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx\n", mac_arr[i].src[0], mac_arr[i].src[1],mac_arr[i].src[2],mac_arr[i].src[3],mac_arr[i].src[4],mac_arr[i].src[5]);
			fprintf(log, "count:\t%d\n", mac_arr[i].cnt);
	}
	fclose(log);
	return 0;
}

int setup_signal(struct sigaction *act){
	act->sa_handler = call_pcap_breakloop;
	sigaction(SIGINT, act, 0);

	return 0;
}

void call_pcap_breakloop(int signal){
	printf("Stopping pcap.\n");
	pcap_breakloop(dev_handle);
}
