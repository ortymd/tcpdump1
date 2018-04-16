#include <pcap.h>
#include <functions.h>
#include <string.h>

extern char errbuf[PCAP_ERRBUF_SIZE];
static const unsigned input_sz = 1 << 6;

int setup_filter(pcap_t *dev_handle){
	char user_input[input_sz];
	int check = -1;
	int optimize = 0;
	struct bpf_program fp;

	get_port(user_input);

	check = pcap_compile(dev_handle, &fp, user_input, optimize, PCAP_NETMASK_UNKNOWN);
	if(check < 0){
		return check;
	}

	check = pcap_setfilter(dev_handle, &fp);
	return check;
}

int get_port(char *user_input){
	#if TEST

	printf("Capture packets on port 80(http)\n");
	strncpy(user_input, "port 80", input_sz);

	#else

	int check = -1;

	while(check != 0){
		printf("Input port number:\n");
		get_user_input(user_input);
		check = check_user_input(user_input);
	}

	#endif

}
