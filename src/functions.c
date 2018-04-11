#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <linux/if_ether.h>

#include <functions.h>
#include <mac_data.h>

static const unsigned input_sz = 1<<3;
#define arr_sz 1<<5 
mac_data mac_dest_arr[arr_sz];	// here we store macs and their quantity
mac_data mac_source_arr[arr_sz];

pcap_if_t* request_device(pcap_if_t **alldevsp){
	char user_input[input_sz];
	pcap_if_t *chosen_dev = NULL;

	print_active_devs(alldevsp);
	while ( chosen_dev == NULL ) {
		printf("Choose device. Input 0 for exit:\n");
		//FILE *in = fdopen(stdin->_fileno, "r");
		//fread(user_input, 1, input_sz, in);
		scanf("%[^\n]%*c", user_input);	//	sz indicates max len to scan. see man 3 scanf(line 83)

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

void parse_packet(u_char *args, const struct pcap_pkthdr *h, const u_char *buf_ptr){
	static char mac_dest[macsize +1];
	static char mac_source[macsize +1];

	get_mac(buf_ptr, mac_dest, mac_source);	
}

int get_mac(const u_char *bufptr, char *mac_dest,  char *mac_source)
{
	struct ethhdr *eth = (struct ethhdr *)bufptr;

	sprintf(mac_dest,
	 "%.2x%.2x%.2x%.2x%.2x%.2x",
	  eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] 
	);

	sprintf(mac_source,
	 "%.2x%.2x%.2x%.2x%.2x%.2x",
	  eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] 
	);

	return 0;
}
