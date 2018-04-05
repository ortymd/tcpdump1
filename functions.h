#ifndef FUNCTIONS
#define FUNCTIONS

#include <stdio.h>
#include <gmodule.h>
#include "mac_data.h"

char *get_active_devices(void);
int print_mac(void);
int print_ip(void);
void print_ethernet_header(unsigned char*, FILE*, FILE* );
void store_ethernet_header(unsigned char*, FILE*, FILE* );
int store_mac(unsigned char *bufptr);
int create_trees();
int dump_tree(GTree *tree);
gboolean dump_node(unsigned char *mac_addr, unsigned cnt );
int get_mac(const unsigned char *bufptr, mac_data *mac_dest, mac_data *mac_source);
int open_files(FILE **log_out, FILE **log_in);
gint comparator(gconstpointer mac1, gconstpointer mac2);

#endif
