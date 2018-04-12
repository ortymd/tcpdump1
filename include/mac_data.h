#ifndef MACDATA
#define MACDATA

#define macsize 6 
typedef struct
{
	char dest[macsize];
	char src[macsize];
	unsigned cnt;
} mac_data;

#endif
