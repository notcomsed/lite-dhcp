void print_dhcpinfo(int pkt_type){
	u_int16_t tmp;
	if(pkt_type == DHCP_MSGOFFER) {
		map_all_layer_ptr(DHCP_MSGOFFER);
	} else if( pkt_type == DHCP_MSGACK) {
		map_all_layer_ptr(DHCP_MSGACK);
	}
    sprintf(DHCPINFO.myip, "%s", get_ip_str(dhcph_g->dhcp_yip));
	while(*(dhopt_pointer_g) != DHCP_END) {

		switch(*(dhopt_pointer_g)) {
			case DHCP_SERVIDENT:
			//DHCP server
					sprintf(DHCPINFO.dhcp,"%s\0", get_ip_str(*(u_int32_t *)(dhopt_pointer_g + 2)));
				
				break;

			case DHCP_LEASETIME:
				    DHCPINFO.time=(ntohl(*(u_int32_t *)(dhopt_pointer_g + 2)));
				break;

			case DHCP_SUBNETMASK:
				
					sprintf(DHCPINFO.subnet, "%s\0", get_ip_str(*(u_int32_t *)(dhopt_pointer_g + 2)));
				
				break;

			case DHCP_ROUTER:
				for(tmp = 0; tmp < (*(dhopt_pointer_g + 1) / 4); tmp++) {
					
						sprintf(DHCPINFO.gateway, "%s\0", get_ip_str(*(u_int32_t *)(dhopt_pointer_g + 2 + (tmp * 4))));
					
				}
				break;

			case DHCP_DNS:
				for(tmp = 0; tmp < ((*(dhopt_pointer_g + 1)) / 4); tmp++) {
					
						fprintf(stdout, "DNS server - %s\n", get_ip_str(*(u_int32_t *)(dhopt_pointer_g + 2 + (tmp * 4))));
					
				}
				break;


                        default:break;
		}

                if (*(dhopt_pointer_g) == DHCP_PAD) {
                    /* DHCP_PAD option - increment dhopt_pointer_g by one */
                    dhopt_pointer_g = dhopt_pointer_g + 1;
                } else {
                    dhopt_pointer_g = dhopt_pointer_g + *(dhopt_pointer_g + 1) + 2;
                }
	}
}

unsigned int get_uid(char *usrName){
	FILE *pwdf = fopen("/etc/passwd", "r");
	char usrline[128];
	unsigned int uid=0;
	//char *tmpuid;
	char *uidchar;
	char startd=1;
	char readbuf[8192]="";
	char *Xline;
	char *token;
	
		if (!pwdf) {
		fprintf(stderr, "Error: can't open /etc/passwd \n");
		startd=0;
	} else {
		if (fread(readbuf,1,8192,pwdf)>=8192){
		fprintf(stderr, "Error: /etc/passwd too big \n");
		startd=0;
		}else{readbuf[8191]=0;token = strchr(readbuf,'\n');
			memcpy(usrline,readbuf,128);
			usrline[127]=0;}}
		while (startd) {
		if (token == NULL) {
			break;
		}
		Xline = strtok(usrline,":x:");
		if (Xline[0] == '\n'){Xline++;}
		if (!strcmp(Xline, usrName)){
			Xline = strtok(NULL, ":x:");
			uidchar = Xline;
			//tmpuid = Xline + 2;
			//uidchar = strtok(tmpuid,":");
			uid=atoi(uidchar);
			break;
		}
		memset(usrline,0,64);
		memcpy(usrline,token,128);
		usrline[127]=0;
		token = strchr(token+1,'\n');

        }
	fclose(pwdf);
    printf("Info: change uid %d with %s \n",uid,usrName);
	if (uid>0){return uid;} else {return 65534;}
}

void setUidGid(){
	if (getuid() == 0){
	if (usruid[0] != 0){
	setgid((uid_t)65534);setuid(get_uid(usruid));
}}}

int close_socket()
{
	close(sock_packet);
	return 0;
}

u_int32_t get_interface_address()
{
	int status;
	struct ifreq ifr;

	if(!strlen((const char *) iface_name)) {
		strcpy(iface_name, "eth0");
	}
	strcpy(ifr.ifr_name, iface_name);
	ifr.ifr_addr.sa_family = AF_INET;
	status = ioctl(sock_packet, SIOCGIFADDR, &ifr);

	if(status < 0) {
		if (nagios_flag) {
			fprintf(stdout, "CRITICAL: Error getting interface address.");
		} else if(0) {
		} else {
			perror("Error getting interface address.");
		}

		exit(2);
	}
	return ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
}

/*
 * Sends DHCP packet on the socket. Packet type
 * is passed as argument. Extended to send ARP and ICMP packets
 */
int send_packet(int pkt_type)
{
	int ret = -1;
	if(pkt_type == DHCP_MSGDISCOVER) {
		ret = sendto(sock_packet,\
				dhcp_packet_disc,\
				(l2_hdr_size + l3_hdr_size + l4_hdr_size + dhcp_hdr_size + dhopt_size),\
				0,\
				(struct sockaddr *) &ll,\
				sizeof(ll));
	} else if(pkt_type == DHCP_MSGREQUEST) {
		ret = sendto(sock_packet,\
				dhcp_packet_request,\
				(l2_hdr_size + l3_hdr_size + l4_hdr_size + dhcp_hdr_size + dhopt_size),\
				0,\
				(struct sockaddr *) &ll,\
				sizeof(ll));
	} else if(pkt_type == DHCP_MSGRELEASE) {
		ret = sendto(sock_packet,\
				dhcp_packet_release,\
				(l2_hdr_size + l3_hdr_size + l4_hdr_size + dhcp_hdr_size + dhopt_size),\
				0,\
				(struct sockaddr *) &ll,\
				sizeof(ll));
	} else if(pkt_type == DHCP_MSGDECLINE) {
		ret = sendto(sock_packet,\
				dhcp_packet_decline,\
				(l2_hdr_size + l3_hdr_size + l4_hdr_size + dhcp_hdr_size + dhopt_size),\
				0,\
				(struct sockaddr *) &ll,\
				sizeof(ll));
	} else if(pkt_type == ARP_SEND) {
		ret = sendto(sock_packet,\
				arp_icmp_reply,\
				60,\
				0,\
				(struct sockaddr *) &ll,\
				sizeof(ll));
	} else if(pkt_type == ICMP_SEND) {
		ret = sendto(sock_packet,\
				arp_icmp_reply,\
				(l2_hdr_size + l3_hdr_size + ICMP_H + icmp_len),\
				0,\
				(struct sockaddr *) &ll,\
				sizeof(ll));
	}

	if(ret < 0) {
		if (nagios_flag) {
			fprintf(stdout, "CRITICAL: Packet send failure.");
		} else if(0) {
		} else {
			perror("Packet send failure");
		}

		close(sock_packet);
		exit(2);
		return PACK_SEND_ERR;
	} else {
		if(pkt_type == DHCP_MSGDISCOVER) {
			if (!nagios_flag && !json_flag) {
				fprintf(stdout, "DHCP discover sent\t - ");
				fprintf(stdout, "Client MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", \
					dhmac[0], dhmac[1], dhmac[2], dhmac[3], dhmac[4], dhmac[5]);
			} else if(0) {
			}
		} else if (pkt_type == DHCP_MSGREQUEST) {
			if (!nagios_flag && !json_flag) {
				fprintf(stdout, "DHCP request sent\t - ");
				fprintf(stdout, "Client MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", \
					dhmac[0], dhmac[1], dhmac[2], dhmac[3], dhmac[4], dhmac[5]);
			} else if(0) {
			}
		} else if (pkt_type == DHCP_MSGRELEASE) {
			if (!nagios_flag && !json_flag) {
				fprintf(stdout, "DHCP release sent\t - ");
				fprintf(stdout, "Client MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", \
					dhmac[0], dhmac[1], dhmac[2], dhmac[3], dhmac[4], dhmac[5]);
			} else if(0) {
			}
		} else if (pkt_type == DHCP_MSGDECLINE) {
			if (!nagios_flag && !json_flag) {
				fprintf(stdout, "DHCP decline sent\t - ");
				fprintf(stdout, "Client MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", \
					dhmac[0], dhmac[1], dhmac[2], dhmac[3], dhmac[4], dhmac[5]);
			} else if(0) {
			}
		}
	}
	return 0;
}

/*
 * Receives DHCP packet. Packet type is passed as argument
 * Extended to recv ARP and ICMP packets
 */
int recv_packet(int pkt_type)
{
	int ret = -1, sock_len, retval, chk_pkt_state;
	fd_set read_fd;
	struct timeval tval;
	tval.tv_sec = 5;
	tval.tv_usec = 0;

	if(pkt_type == DHCP_MSGOFFER) {
		while(tval.tv_sec != 0) {
			FD_ZERO(&read_fd);
			FD_SET(sock_packet, &read_fd);
			retval = select(sock_packet + 1, &read_fd, NULL, NULL, &tval);
			if(retval == 0) {
				return DHCP_DISC_RESEND;
				break;
			} else if ( retval > 0 && FD_ISSET(sock_packet, &read_fd)) {
				bzero(dhcp_packet_offer, sizeof(dhcp_packet_offer));
				sock_len = sizeof(ll);
				ret = recvfrom(sock_packet,\
						dhcp_packet_offer,\
						sizeof(dhcp_packet_offer),\
						0,\
						(struct sockaddr *)&ll,
						(socklen_t *) &sock_len);
			}
			if(ret >= 60) {
				chk_pkt_state = check_packet(DHCP_MSGOFFER);
				if(chk_pkt_state == DHCP_OFFR_RCVD) {
					return DHCP_OFFR_RCVD;
				}
			}
		}
		return DHCP_DISC_RESEND;
	} else if(pkt_type == DHCP_MSGACK) {
		while(tval.tv_sec != 0) {
			FD_ZERO(&read_fd);
			FD_SET(sock_packet, &read_fd);
			retval = select(sock_packet + 1, &read_fd, NULL, NULL, &tval);
			if(retval == 0) {
				return DHCP_REQ_RESEND;
				break;
			} else if ( retval > 0 && FD_ISSET(sock_packet, &read_fd)){
				bzero(dhcp_packet_ack, sizeof(dhcp_packet_ack));
				sock_len = sizeof(ll);
				ret = recvfrom(sock_packet,\
						dhcp_packet_ack,\
						sizeof(dhcp_packet_ack),\
						0,\
						(struct sockaddr *)&ll,
                                                (socklen_t *) &sock_len);
			}
			if(ret >= 60) {
				chk_pkt_state = check_packet(DHCP_MSGACK);
				if(chk_pkt_state == DHCP_ACK_RCVD) {
					return DHCP_ACK_RCVD;
				} else if(chk_pkt_state == DHCP_NAK_RCVD) {
					return DHCP_NAK_RCVD;
				}
			}
		}
		return DHCP_REQ_RESEND;
	} else if(pkt_type == ARP_ICMP_RCV) {
		while(tval_listen.tv_sec != 0) {
			FD_ZERO(&read_fd);
			FD_SET(sock_packet, &read_fd);
			retval = select(sock_packet + 1, &read_fd, NULL, NULL, &tval_listen);
			if(retval == 0) {
				return LISTEN_TIMOUET;
				break;
			} else if ( retval > 0 && FD_ISSET(sock_packet, &read_fd)) {
				bzero(arp_icmp_packet, sizeof(arp_icmp_packet));
				sock_len = sizeof(ll);
				ret = recvfrom(sock_packet,\
						arp_icmp_packet,\
						sizeof(arp_icmp_packet),\
						0,\
						(struct sockaddr *)&ll,
                                                (socklen_t *) &sock_len);
			}
			if(ret >= 60) {
				chk_pkt_state = check_packet(ARP_ICMP_RCV);
				if(chk_pkt_state == ARP_RCVD) {
					return ARP_RCVD;
					break;
				} else if(chk_pkt_state == ICMP_RCVD) {
					return ICMP_RCVD;
					break;
				}
			}
		}
		return LISTEN_TIMOUET;
	}

    return UNKNOWN_PACKET;
}

/* Debug function - Prints the buffer on HEX format */
int print_buff(u_int8_t *buff, int size)
{
	int tmp;
	fprintf(stdout, "\n---------Buffer data---------\n");
	for(tmp = 0; tmp < size; tmp++) {
		fprintf(stdout, "%02X ", buff[tmp]);
		if((tmp % 16) == 0 && tmp != 0) {
			fprintf(stdout, "\n");
		}
	}
	fprintf(stdout, "\n");
	return 0;
}

/* Reset the DHCP option buffer to zero and dhopt_size to zero */
int reset_dhopt_size()
{
	bzero(dhopt_buff, sizeof(dhopt_buff));
	dhopt_size = 0;
	return 0;
}

u_int16_t ipchksum(u_int16_t *buff, int words)
{
	unsigned int sum, i;
	sum = 0;
	for(i = 0;i < words; i++){
		sum = sum + *(buff + i);
	}
	sum = (sum >> 16) + sum;
	return (u_int16_t)~sum;
}

u_int16_t icmpchksum(u_int16_t *buff, int words)
{
	unsigned int sum, i;
	unsigned int last_word = 0;
	/* Checksum enhancement for odd packets */
	if((icmp_len % 2) == 1) {
		last_word = *((u_int8_t *)buff + icmp_len + ICMP_H - 1);
		last_word = (htons(last_word) << 8);
		sum = 0;
		for(i = 0;i < words; i++){
			sum = sum + *(buff + i);
		}
		sum = sum + last_word;
		sum = (sum >> 16) + sum;
		return (u_int16_t)~sum;
	} else {
		sum = 0;
		for(i = 0;i < words; i++){
			sum = sum + *(buff + i);
		}
		sum = (sum >> 16) + sum;
		return (u_int16_t)~sum;
	}
}

u_int16_t l4_sum(u_int16_t *buff, int words, u_int16_t *srcaddr, u_int16_t *dstaddr, u_int16_t proto, u_int16_t len)
{
	unsigned int i, last_word;
	uint32_t sum;

	/* Checksum enhancement - Support for odd byte packets */
	if((htons(len) % 2) == 1) {
		last_word = *((u_int8_t *)buff + ntohs(len) - 1);
		last_word = (htons(last_word) << 8);
	} else {
		/* Original checksum function */
		last_word = 0;
	}

	sum = 0;
	for(i = 0;i < words; i++){
		sum = sum + *(buff + i);
	}
	sum = sum + last_word;
	sum = sum + *(srcaddr) + *(srcaddr + 1) + *(dstaddr) + *(dstaddr + 1) + proto + len;
	sum = (sum >> 16) + sum;
	return ~sum;
}
