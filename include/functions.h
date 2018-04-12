#include <pcap.h>
#include <mac_data.h>

pcap_if_t* request_device(pcap_if_t **alldevsp);
void print_active_devs(pcap_if_t **alldevsp);
pcap_if_t* find_device(char *user_input, pcap_if_t **alldevsp);
void parse_packet(u_char *args, const struct pcap_pkthdr *h, const u_char *bytes);
int get_mac(const u_char *bufptr,  u_char *mac_dest,  u_char *mac_source);
int print_to_file(void);
mac_data* find(u_char *mac_dest, u_char *mac_src, mac_data *arr, unsigned space);
int dump_data();
