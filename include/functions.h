#include <pcap.h>
#include <log_data.h>
#include <signal.h>

#define TEST 1
pcap_if_t* request_device(pcap_if_t **alldevsp);
void print_active_devs(pcap_if_t **alldevsp);
pcap_if_t* find_device(char *user_input, pcap_if_t **alldevsp);
void parse_packet(u_char *args, const struct pcap_pkthdr *h, const u_char *bytes);
int get_mac(const u_char *bufptr,  u_char *mac_dest,  u_char *mac_source);
int get_ip(const u_char *bufptr, u_char *ip_dest,  u_char *ip_src);
int print_to_file(void);
int dump_data();
int setup_signal(struct sigaction *act);
void call_pcap_breakloop(int signal);
int get_log(const u_char *bufptr, u_char **mac_dest,  u_char **mac_src, u_char **ip_dest,  u_char **ip_src);
log_data* find(u_char *ip_dest, u_char *ip_src, log_data *arr, unsigned cur_sz);
