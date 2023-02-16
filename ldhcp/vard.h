char usruid[16]="";
int sock_packet, iface = 2;	
struct sockaddr_ll ll = { 0 };	
u_int16_t vlan = 0;
u_int8_t l3_tos = 0;
u_int16_t l2_hdr_size = 14;
u_int16_t l3_hdr_size = 20;
u_int16_t l4_hdr_size = 8;
u_int16_t dhcp_hdr_size = sizeof(struct dhcpv4_hdr);

struct DHCP_Info {
	char dhcp[16];
	char dns2[32];
	char myip[16];
	char subnet[16];
	char dns1[32];
	char gateway[16];
	char black[32];
	unsigned long long time;
};

/* DHCP packet, option buffer and size of option buffer */
u_char dhcp_packet_disc[1518] = { 0 };
u_char dhcp_packet_offer[1518] = { 0 };
u_char dhcp_packet_request[1518] = { 0 };
u_char dhcp_packet_ack[1518] = { 0 };
u_char dhcp_packet_release[1518] = { 0 };
u_char dhcp_packet_decline[1518] = { 0 };

u_char dhopt_buff[500] = { 0 };
u_int32_t dhopt_size = { 0 };
u_char dhmac[ETHER_ADDR_LEN] = { 0 };
u_char rtrmac[ETHER_ADDR_LEN] = { 0 };
u_char dmac[ETHER_ADDR_LEN];
u_char iface_mac[ETHER_ADDR_LEN] = { 0 };

/*
* For Custom DHCP options
* Static arrays for custom_dhcp_option_hdr
*/
#define MAX_CUSTOM_DHCP_OPTIONS 64
u_int8_t no_custom_dhcp_options = { 0 };
struct custom_dhcp_option_hdr custom_dhcp_options[MAX_CUSTOM_DHCP_OPTIONS];

char dhmac_fname[20];
char rtrmac_fname[20];
char iface_name[30] = { 0 };
char ip_str[128];
u_int8_t dhmac_flag = 0;
u_int8_t rtrmac_flag = 0;
u_int8_t strict_mac_flag = 0;
u_int32_t server_id = { 0 }, option50_ip = { 0 };
u_int32_t dhcp_xid = 0;
u_int16_t bcast_flag = 0; /* DHCP broadcast flag */
u_int8_t vci_buff[256] = { 0 }; /* VCI buffer*/
u_int16_t vci_flag = 0;
u_int8_t hostname_buff[256] = { 0 }; /* Hostname buffer*/
u_int16_t hostname_flag = 0;
u_int8_t fqdn_buff[256] = { 0 }; /* FQDN buffer*/
u_int16_t fqdn_flag = 0;
u_int16_t fqdn_n = 0;
u_int16_t fqdn_s = 0;
u_int32_t option51_lease_time = 0;
u_int8_t option55_req_flag = 0;
u_int8_t option55_req_list[256] = { 0 }; /* option55 request list buffer */
u_int32_t option55_req_len = 0; /* option55 request list buffer */
u_int32_t port = 67;
u_int8_t unicast_flag = 0;
u_int8_t nagios_flag = 0;
u_int8_t json_flag = 0;
u_int8_t dhcp_decline_flag = 0;
u_int8_t json_first = 1;
char *giaddr = "0.0.0.0";
char *server_addr = "255.255.255.255";

/* Pointers for all layer data structures */
struct ethernet_hdr *eth_hg = { 0 };
struct vlan_hdr *vlan_hg = { 0 };
struct iphdr *iph_g = { 0 };
struct udphdr *uh_g = { 0 };
struct dhcpv4_hdr *dhcph_g = { 0 };


u_int8_t *dhopt_pointer_g = { 0 };
u_int8_t verbose = 0;
u_int8_t dhcp_release_flag = 0;
u_int8_t padding_flag = 0;
u_int16_t timeout = 0;
time_t time_now, time_last;

/* Used for ip listening functionality */
struct arp_hdr *arp_hg = { 0 };
struct icmp_hdr *icmp_hg = { 0 };

u_int32_t unicast_ip_address = 0;
u_int32_t ip_address;
u_char ip_listen_flag = 0;
struct timeval tval_listen = { 3600, 0 };
u_int32_t listen_timeout = 3600;
u_char arp_icmp_packet[1514] = { 0 };
u_char arp_icmp_reply[1514] = { 0 };
u_int16_t icmp_len = 0;
struct DHCP_Info DHCPINFO;