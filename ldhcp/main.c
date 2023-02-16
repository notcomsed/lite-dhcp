
int main(int argc, char *argv[])
{
	int get_tmp = 1, get_cmd;

	if(argc < 3) {
	fprintf(stdout, "Usage: %s [ options ]\n", argv[0]);
	fprintf(stdout, "  -p, --padding\t\t\t\t# Add padding to packet to be at least 300 bytes\n");
	fprintf(stdout, "  -h, --hostname [ hostname_string ] # Client hostname string\n");
	fprintf(stdout, "  -i, --interface\t[ interface ]\t# Interface to use. Default eth0\n");
	fprintf(stdout, "  -u, --user\t[username]\t set user\n");
	exit(1);
	}

	int option_index = 0;
	static struct option long_options[] = {
		{ "interface", required_argument, 0, 'i' },
		{ "option12-hostname", required_argument, 0, 'h' },
		{ "padding", no_argument, 0, 'p'},
		{ "user", required_argument, 0, 'u'},
		{ 0, 0, 0, 0 }
	};
	/*getopt routine to get command line arguments*/
	while(get_tmp < argc) {
		get_cmd  = getopt_long(argc, argv, "i:h:u:p:",\
				long_options, &option_index);
		if(get_cmd == -1 ) {
			break;
		}
		switch(get_cmd) {
			case 'i':
				iface = if_nametoindex(optarg);
				if(iface == 0) {
					fprintf(stdout, "Interface not exist\n");
					exit(-1);
				}
				strncpy(iface_name, optarg, 29);
				break;
			case 'h':
				if(strlen(optarg) > 256) {
					fprintf(stdout, "Hostname string size should be less than 256\n");
					exit(2);
				}
				hostname_flag = 1;
				memcpy(hostname_buff, optarg, sizeof(hostname_buff));
				break;
			case 'p':
				padding_flag = 1;
				break;
			case 'u':
			    if(strlen(optarg) < 16) {memcpy(usruid,optarg,strlen(optarg));}
				break;	
			default:
				exit(-1);
		}
		get_tmp++;
	}

	if(!*iface_name) {
		fprintf(stdout, "  -i interface is mandatory option\n");
		exit(-1);
	}


	  if(get_if_mac_address(iface_name, iface_mac) != 0) {exit(-1);}
	    memcpy (dhmac, iface_mac, ETHER_ADDR_LEN);
	    memcpy (iface_mac, dhmac, ETHER_ADDR_LEN);
	    fprintf (stderr, "Using Ethernet source addr: %s\n", mac2str (iface_mac));
	    fprintf (stderr, "Using DHCP chaddr: %s\n", mac2str (dhmac));
		strcpy(dhmac_fname, mac2str(dhmac));


	/* Opens the PF_PACKET socket */
	
	sock_packet = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock_packet < 0) {
		perror("--Error on creating the socket--");
		fprintf(stdout, "Socket error\n");
		exit(-1);
	}
	/* Set link layer parameters */
	ll.sll_family = AF_PACKET;
	ll.sll_protocol = htons(ETH_P_ALL);
	ll.sll_ifindex = iface;
	ll.sll_hatype = ARPHRD_ETHER;
	ll.sll_pkttype = PACKET_OTHERHOST;
	ll.sll_halen = 6;
	bind(sock_packet, (struct sockaddr *)&ll, sizeof(struct sockaddr_ll));
	
	
    setUidGid();
	if(dhcp_xid == 0) {
	dhcp_xid = (((dhcp_xid = time(NULL) ^ (getpid() << 16)* 214013LL + 2531011LL) >> 16) & 0x7fff) % 0xffffffff;
	}
	 pthread_t worker;
     if (pthread_create(&worker,NULL, Threadwork, NULL)){perror("Error: can't create pthread\n");}
	 //ok
	 while(1){

	build_option53(DHCP_MSGDISCOVER);	/* Option53 for DHCP discover */
	
	if(hostname_flag) {
		build_option12_hostname();
	}
	
	if(option50_ip) {
		build_option50();		/* Option50 - renew. IP  */
	}
        build_option55();   
		/* Option55 - parameter request list */
	if(option51_lease_time) {
		build_option51();               /* Option51 - DHCP lease time requested */
	}

        /* Build custom options */
        if(no_custom_dhcp_options) {
            build_custom_dhcp_options();
        }
	build_optioneof();			/* End of option */
	build_dhpacket(DHCP_MSGDISCOVER);	/* Build DHCP discover packet */

	int dhcp_offer_state = 0;
	while(dhcp_offer_state != DHCP_OFFR_RCVD) {

		/* Sends DHCP discover packet */
		send_packet(DHCP_MSGDISCOVER);
		/*
		 * recv_packet functions returns when the specified
		 * packet is received
		 */
		dhcp_offer_state = recv_packet(DHCP_MSGOFFER);



		if(dhcp_offer_state == DHCP_OFFR_RCVD) {
				fprintf(stdout, "DHCP offer received\t - ");
				set_serv_id_opt50();
				//print_dhinfo(DHCP_MSGOFFER);
				print_dhcpinfo(DHCP_MSGACK);
			
		}
	}
	/* Reset the dhopt buffer to build DHCP request options  */
	reset_dhopt_size();
	build_option53(DHCP_MSGREQUEST);
	build_option50();
	build_option54();
	if(hostname_flag) {
		build_option12_hostname();
	}


	if(option51_lease_time) {
		build_option51();                       /* Option51 - DHCP lease time requested */
	}
        build_option55();                               /* Option55 - parameter request list */
        /* Build custom options */
        if(no_custom_dhcp_options) {
                build_custom_dhcp_options();
        }
	build_optioneof();
	build_dhpacket(DHCP_MSGREQUEST); 		/* Builds specified packet */
	int dhcp_ack_state = 1;
	while(dhcp_ack_state != DHCP_ACK_RCVD) {

		send_packet(DHCP_MSGREQUEST);
		dhcp_ack_state = recv_packet(DHCP_MSGACK);

		if(dhcp_ack_state == DHCP_ACK_RCVD) {
				fprintf(stdout, "OK: Acquired IP: %s", get_ip_str(dhcph_g->dhcp_yip));
				fprintf(stdout, "DHCP ack received\t - ");
				fprintf(stdout, "Acquired IP: %s\n", get_ip_str(dhcph_g->dhcp_yip));
			

			/* Logs DHCP IP details to log file. This file is used for DHCP release */
			//log_dhinfo();
			//print_dhinfo(DHCP_MSGACK);
			print_dhcpinfo(DHCP_MSGACK);
			
		} else if (dhcp_ack_state == DHCP_NAK_RCVD) {
				fprintf(stdout, "DHCP nack received\t - ");
				fprintf(stdout, "Client MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", \
					dhmac[0], dhmac[1], dhmac[2], dhmac[3], dhmac[4], dhmac[5]);
		}
	}
    
	    unsigned long long SleepTime=0;
		printf("dhcp is %s\n",DHCPINFO.dhcp);
		printf("gateway is %s\n",DHCPINFO.gateway);
		printf("time is %lld\n",DHCPINFO.time);
		printf("subnet is %s\n",DHCPINFO.subnet);
		printf("myip is %s\n",DHCPINFO.myip);
		SleepTime=DHCPINFO.time/2;
	printf("sleeping %lld s....\n",SleepTime);
	sleep(SleepTime);
	 }
	 
	close_socket();
	return 0;
}
