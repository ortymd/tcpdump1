#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>    //For ETH_P_ALL
#include <net/ethernet.h>        //For ether_header
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

#include "functions.h"

struct sockaddr_in source,dest;
extern mac_data mac_dest_arr[];
extern mac_data mac_source_arr[];


sem_t bin_sem;

int main(int argc, char **argv) {

	const size_t bufsize = 1<<12;	
	size_t space_left = bufsize;
	char buffer[bufsize]; 
	char *bufptr = buffer;

	const size_t arr_size = 1<<10;
	char *arr[arr_size];
	char **arr_ptr = arr;

	int sock_raw;
	struct sockaddr_in saddr;
	const size_t saddr_size = sizeof saddr;
	size_t data_size;
	pthread_t store_mac_thread;
	int res;
	void *thread_res;

	sem_init(&bin_sem, 0, 0);

	sock_raw = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sock_raw < 0)
	{
		perror( "error in socket\n" );
		return 1;
	}

	printf("Starting...\n");
	res = pthread_create(&store_mac_thread, NULL, store_mac, arr_ptr);

	while (space_left > 0)
	{
		data_size = recvfrom(sock_raw , bufptr, space_left, 0, (struct sockaddr*)&saddr , (socklen_t*)&saddr_size);

		*arr_ptr = bufptr;
		arr_ptr++;
		bufptr += data_size;
		space_left -= data_size;
		sem_post(&bin_sem);
		// sem_wait
	}

	res = pthread_join(store_mac_thread, &thread_res);
	dump_data(mac_dest_arr, mac_source_arr);

	sem_destroy(&bin_sem);

	return 0;
}
