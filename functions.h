#ifndef FUNCTIONS
#define FUNCTIONS

#include <stdio.h>
#include "mac_data.h"

int store_mac(unsigned char *bufptr);
int dump_data(mac_data *dest, mac_data *source);
int get_mac(const unsigned char *bufptr, char *mac_dest,  char *mac_source);
mac_data* find(char *mac_addr, mac_data *arr, size_t space);
#endif
