#ifndef MACDATA
#define MACDATA

#define macsize 12 
typedef struct
{
	unsigned cnt;
	char addr[macsize+1];
} mac_data;

#endif
