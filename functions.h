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
int dump_data(mac_data *dest, mac_data *source);
gboolean dump_node(void *mac_addr, void *cnt );
int get_mac(const unsigned char *bufptr, char *mac_dest,  char *mac_source);
int open_files(FILE **log_out, FILE **log_in);
gint comparator(gconstpointer mac1, gconstpointer mac2);
int get_mac_hdr(const unsigned char *bufptr, unsigned	char **mac_dest, unsigned char **mac_source);
mac_data* find(char *mac_addr, mac_data *arr, size_t space);
#endif
