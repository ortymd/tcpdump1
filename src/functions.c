#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <functions.h>

static const unsigned sz = 1<<3;

pcap_if_t* request_device(pcap_if_t **alldevsp){
	char user_input[sz];
	pcap_if_t *chosen_dev = NULL;

	print_active_devs(alldevsp);
	while ( chosen_dev == NULL ) {
		printf("Choose device. Input 0 for exit:\n");
		FILE *in = fdopen(stdin->_fileno, "r");
		fread(user_input, 1, sz, in);
		//scanf("%8s", user_input);	//	sz indicates max len to scan. see man 3 scanf(line 83)

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
		if(strncmp(user_input, check->name, sz) == 0){
			dev = check;
			break;
		}
		check = check->next;
	}

	return dev;
}
