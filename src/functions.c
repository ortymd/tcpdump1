#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/ether.h>

#include <functions.h>
#include <log_data.h>

#define arr_sz 1<<5 
log_data log_arr[arr_sz];	// here we store logs and their quantity
static unsigned cur_sz = 0;
const unsigned input_sz = 1<<3;
extern pcap_t *dev_handle;

pcap_if_t* request_device(pcap_if_t **alldevsp){
	char user_input[input_sz];
	pcap_if_t *chosen_dev = NULL;

	print_active_devs(alldevsp);
	while ( chosen_dev == NULL ) {

#if TEST
		strncpy(user_input, "enp0s8", 6);
		printf("Chosen device: %s\n", user_input);
#else
		printf("Input device. Input 0 for exit:\n");
		get_user_input(user_input);
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
	static u_char *mac_dest = NULL;
	static u_char *mac_src = NULL;
	static u_char *ip_dest = NULL;
	static u_char *ip_src = NULL;
	static log_data *log_tmp = NULL;

	if (get_log(bufptr, &mac_dest, &mac_src, &ip_dest, &ip_src) == 0){

		log_tmp = find(ip_dest, ip_src, log_arr, cur_sz);
		if( log_tmp == NULL )
		{
			memcpy(log_arr[cur_sz].ip.dest, ip_dest, ipsize);
			memcpy(log_arr[cur_sz].ip.src, ip_src, ipsize);
			memcpy(log_arr[cur_sz].mac.dest, mac_dest, macsize);
			memcpy(log_arr[cur_sz].mac.src, mac_src, macsize);
			log_arr[cur_sz].cnt += 1;
			++cur_sz;
		}
		else
		{
			log_tmp->cnt += 1;
		}
	}
}

log_data* find(u_char *ip_dest, u_char *ip_src, log_data *arr, unsigned cur_sz) {
	for (unsigned i=0; i < cur_sz; ++i) {
		if( memcmp(ip_dest, log_arr[i].ip.dest, ipsize) == 0 && memcmp(ip_src, log_arr[i].ip.src, ipsize) == 0 ) 
				return &log_arr[i];
		}
	return NULL;
}

int get_log(const u_char *bufptr, u_char **mac_dest,  u_char **mac_src, u_char **ip_dest,  u_char **ip_src)
{
	static const unsigned ethsz = sizeof(struct ethhdr); 
	static const unsigned min_iphdr_sz = 20;
	unsigned check = 0;
	#define IP_HL(ip) ((((ip)->ihl) & 0x0f)*4)
	struct ethhdr *eth = (struct ethhdr*)bufptr;

	*mac_dest = eth->h_dest;
	*mac_src = eth->h_source;

	struct iphdr *ip = (struct iphdr*)(bufptr + ethsz);
	unsigned iphdr_sz = IP_HL(ip);
	if (iphdr_sz < min_iphdr_sz){
		check = 1;	// corrupted IP header -> discard
	}
	else{
		*ip_dest = &ip->daddr;
		*ip_src = &ip->saddr;
	}

	return check;
}

int dump_data() {
	FILE *log;
	log = fopen("log.txt", "a");

	for( unsigned i = 0; i < cur_sz; ++i) {
		fprintf(log, "\nip dest:\t%hhu.%hhu.%hhu.%hhu\n", log_arr[i].ip.dest[0], log_arr[i].ip.dest[1], log_arr[i].ip.dest[2], log_arr[i].ip.dest[3]);
		fprintf(log, "ip  src:\t%hhu.%hhu.%hhu.%hhu\n", log_arr[i].ip.src[0], log_arr[i].ip.src[1], log_arr[i].ip.src[2], log_arr[i].ip.src[3]);

		fprintf(log, "mac dest:\t%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx\n", log_arr[i].mac.dest[0], log_arr[i].mac.dest[1],log_arr[i].mac.dest[2],log_arr[i].mac.dest[3],log_arr[i].mac.dest[4],log_arr[i].mac.dest[5]);
		fprintf(log, "mac src:\t%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx\n", log_arr[i].mac.src[0], log_arr[i].mac.src[1],log_arr[i].mac.src[2],log_arr[i].mac.src[3],log_arr[i].mac.src[4],log_arr[i].mac.src[5]);

		fprintf(log, "count:\t%d\n", log_arr[i].cnt);
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

void get_user_input(char *user_input){
	fgets(user_input, input_sz, stdin);
	unsigned len = strlen(user_input) - 1;
	if(user_input[len] == '\n')
		user_input[len] = '\0';
}
