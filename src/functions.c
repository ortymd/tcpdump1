#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <linux/if_ether.h>

#include <functions.h>
#include <mac_data.h>

static const unsigned input_sz = 1<<3;
#define arr_sz 1<<5 
mac_data mac_arr[arr_sz];	// here we store macs and their quantity

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

void parse_packet(u_char *args, const struct pcap_pkthdr *h, const u_char *bufptr){
	static u_char mac_dest[macsize];
	static u_char mac_src[macsize];
	static mac_data *mac_tmp;
	static unsigned cur_sz = 0;

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

mac_data* find(char *mac_dest, char *mac_src, mac_data *arr, unsigned cur_sz) {
	for (unsigned i=0; i < cur_sz; ++i) {
		for (unsigned j=0; j < macsize; ++j){
			if( (mac_dest[j] ^ arr[i].dest[j]) == 0 && (mac_src[j] ^ arr[i].src[j]) == 0 ) 
				return &arr[j];
		}
	}
	return NULL;
}

int get_mac(const u_char *bufptr, u_char *mac_dest,  u_char *mac_src)
{
	struct ethhdr *eth = (struct ethhdr *)bufptr;

	for (unsigned j=0; j < macsize; ++j){
			mac_dest[j] ^= eth->h_dest[j];
			mac_src[j] ^= eth->h_source[j];
	}

	return 0;
}
