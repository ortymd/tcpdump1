#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <functions.h>

static const unsigned sz = 1<<3;
enum status_codes{not_found = -2, exit = -1};

int request_device(pcap_if_t **alldevsp){

	enum status_codes{not_found = -2, exit = -1};
	char user_input[sz];
	print_active_devs(alldevsp);

	memset (user_input, 0, sz);
	int index = not_found;
	while (index == not_found){
		printf("Choose device. Input 0 for exit:\n");
		scanf("%s", user_input);

		if(strncmp(user_input, "0", 1) == 0){
			index = exit;
		}
		else{
			index = find_device(user_input, alldevsp);
			if ( index != not_found ){
				break;
			}
		}
		printf("Device not found.\n");
		print_active_devs(alldevsp);
	}
	return index;
}

void print_active_devs(pcap_if_t **alldevsp){
	pcap_if_t *check = alldevsp[0];
	printf("Checking active devices...\n");
	while (check != NULL && (check->flags & PCAP_IF_UP)){
		printf("Device:\t%s\n", check->name);	
		check = check->next;
	}
}

int find_device(char *user_input, pcap_if_t **alldevsp){
	int index = not_found;
	int iter = 0;
	pcap_if_t *check = alldevsp[iter];

	while (check != NULL && (check->flags & PCAP_IF_UP)){
		if(strncmp(user_input, check->name, sz) == 0){
			index = iter;
			break;
		}
		check = check->next;
		++iter;
	}

	return index;
}
