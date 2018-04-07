#ifndef FUNCTIONS
#define FUNCTIONS

#include <stdio.h>
#include "mac_data.h"

void* store_mac(void *bufptr);
int dump_data(mac_data *dest, mac_data *source);
int get_mac(const char *bufptr, char *mac_dest,  char *mac_source);
mac_data* find(char *mac_addr, mac_data *arr, size_t space);
#endif
