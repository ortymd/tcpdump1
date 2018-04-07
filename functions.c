#include <string.h>
#include <linux/if_ether.h>
#include <semaphore.h>

#include "functions.h"

#define sz 32
mac_data mac_dest_arr[sz];	// here we store macs and their quantity
mac_data mac_source_arr[sz];
static unsigned dest_sz=0, source_sz=0;
extern sem_t bin_sem;

void* store_mac(void *arr)
{
		static char mac_dest[macsize +1];
		static char mac_source[macsize +1];
		static mac_data *mac_tmp;
		char **arr_ptr = (char**)arr;

		sem_wait(&bin_sem);
		while (1) {
			get_mac(*arr_ptr, mac_dest, mac_source);

			mac_tmp = find(mac_dest, mac_dest_arr, dest_sz);
			if( mac_tmp == NULL )
			{
				strcpy(mac_dest_arr[dest_sz].addr, mac_dest);
				mac_dest_arr[dest_sz].cnt += 1;
				++dest_sz;
			}
			else
			{
				mac_tmp->cnt += 1;
			}

			mac_tmp = find(mac_source, mac_source_arr, source_sz);
			if( mac_tmp == NULL )
			{
				strcpy(mac_source_arr[source_sz].addr, mac_source);
				mac_source_arr[source_sz].cnt += 1;
				++source_sz;
			}
			else
			{
				mac_tmp->cnt += 1;
			}
			sem_wait(&bin_sem);
			arr_ptr++;
		}

	return NULL;
}

mac_data* find(char *mac_addr, mac_data *arr, size_t space)
{
	for (unsigned i=0; i < space; ++i)
	{
		if(strcmp(arr[i].addr, mac_addr) == 0)
			return &arr[i];
	}
	return NULL;
}

int dump_data(mac_data *dest, mac_data *source)
{
	FILE *log_dest;
	FILE *log_source;
	log_dest = fopen("log_dest.txt", "a");
	log_source = fopen("log_source.txt", "a");

	for( unsigned k = 0; k < dest_sz; ++k)
	{
		fprintf(log_dest, "%s\t%d\n", dest[k].addr, dest[k].cnt);
	}

	for( unsigned k = 0; k < source_sz; ++k)
	{
		fprintf(log_source, "%s\t%d\n", source[k].addr, source[k].cnt);
	}

	fclose(log_dest);
	fclose(log_source);

	return 0;
}

int get_mac(const char *arr_ptr, char *mac_dest,  char *mac_source)
{
	struct ethhdr *eth = (struct ethhdr *)arr_ptr;

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
