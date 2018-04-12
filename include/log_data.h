#ifndef MACDATA
#define MACDATA

#define macsize 6 
#define ipsize 4 

typedef struct {
	char dest[macsize];
	char src[macsize];
} mac_data;

typedef struct{
	char dest[ipsize];
	char src[ipsize];
} ip_data;

typedef struct{
	ip_data ip;
	mac_data mac;
	unsigned cnt;
} log_data;
#endif
