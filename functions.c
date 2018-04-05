#include "functions.h"
#include <linux/if_ether.h>

GTree *tree_dest;
GTree *tree_source;
static FILE *log_dest;

static mac_data mac_dest = {1, {'0','0','0','0','0','0','0','0','0','0','0','0','\0'}};
static mac_data mac_source = {1, {'0','0','0','0','0','0','0','0','0','0','0','0','\0'}};

int store_mac(unsigned char *bufptr)
{
		get_mac(bufptr, &mac_dest, &mac_source);
		mac_data mac_lookup;
		void *lookup_addr = &(mac_lookup.addr);
		void *lookup_cnt = &(mac_lookup.cnt);

		if(g_tree_lookup_extended(tree_dest, mac_dest.addr, lookup_addr, lookup_cnt) )
		{
			*(unsigned*)lookup_cnt += mac_dest.cnt;
		}
		else
		{
			g_tree_insert(tree_dest, mac_dest.addr, mac_dest.cnt);
		}

	return 0;
}

int dump_tree(GTree *tree)
{
	log_dest = fopen("log_dest.txt", "a");
	g_tree_foreach(tree, dump_node, 0);
}

gboolean dump_node(unsigned char *mac_addr, unsigned cnt)
{
	fprintf(log_dest, "%s\t%d",  mac_addr, cnt);
	return FALSE;
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
