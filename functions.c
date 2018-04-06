#include "functions.h"
#include <linux/if_ether.h>

GTree *tree_dest;
GTree *tree_source;
static FILE *log_dest;

static mac_data mac_dest_arr[256] = {0, {'0','0','0','0','0','0','0','0','0','0','0','0','\0'}};
static mac_data mac_source_arr[256] = {0, {'0','0','0','0','0','0','0','0','0','0','0','0','\0'}};

int store_mac(unsigned char *bufptr)
{
		struct ethhdr *mac_dest = NULL;
		struct ethhdr *mac_source = NULL;
		get_mac_hdr(bufptr, &mac_dest, &mac_source);

		void *lookup_addr = NULL;
		void *lookup_cnt = NULL;

		if(g_tree_lookup_extended(tree_dest, mac_dest, &lookup_addr, &lookup_cnt) )
		{
			*(unsigned*)lookup_cnt += 1;
		}
		else
		{
			g_tree_insert(tree_dest, mac_dest, 1); 
		}

	return 0;
}

int dump_tree(GTree *tree)
{
	log_dest = fopen("log_dest.txt", "a");
	g_tree_foreach(tree, dump_node, 0);
	fclose(log_dest);
}

gboolean dump_node(void *mac_addr, void *cnt)
{
	fprintf(log_dest, "%s\t%d\n",  mac_addr, cnt);
	return TRUE;
}

int create_trees()
{
	tree_dest = g_tree_new(comparator);
	tree_source = g_tree_new(comparator);
	return 0;
}

gint comparator(gconstpointer mac1, gconstpointer mac2)
{
	return(strncmp((const char*)mac1, (const char*)mac2, macsize));
}

int get_mac_hdr(const unsigned char *bufptr, 	char **mac_dest, char **mac_source)
{
	struct ethhdr *eth = (struct ethhdr *)bufptr;
	*mac_dest = eth->h_dest;
	*mac_source = eth->h_source;

	return 0;
}

int get_mac(const unsigned char *bufptr, mac_data *mac_dest,  mac_data *mac_source)
{
	struct ethhdr *eth = (struct ethhdr *)bufptr;

	sprintf(mac_dest->addr,
	 "%.2x%.2x%.2x%.2x%.2x%.2x",
	  eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] 
	);

	sprintf(mac_source->addr,
	 "%.2x%.2x%.2x%.2x%.2x%.2x",
	  eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] 
	);

	return 0;
}
