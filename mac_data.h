#ifndef MACDATA
#define MACDATA

#define macsize 12 
typedef struct
{
	char addr[macsize+1];
	unsigned cnt;
} mac_data;

#endif
