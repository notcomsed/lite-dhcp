int build_custom_dhcp_options()
{
        int option_index;
        for(option_index = 0; option_index < no_custom_dhcp_options; option_index++) {

            u_int8_t msgtype = custom_dhcp_options[option_index].option_no;
            u_int8_t msglen = custom_dhcp_options[option_index].option_len;
            u_int8_t option_type = custom_dhcp_options[option_index].option_type;

            memcpy((dhopt_buff + dhopt_size), &msgtype, 1);
            memcpy((dhopt_buff + dhopt_size + 1), &msglen, 1);
            if(option_type == CUST_DHCP_OPTION_IP) {
                memcpy((dhopt_buff + dhopt_size + 2), &custom_dhcp_options[option_index].option_value_ip, msglen);
            } else if(option_type == CUST_DHCP_OPTION_NUMBER) {
                memcpy((dhopt_buff + dhopt_size + 2), &custom_dhcp_options[option_index].option_value_num, msglen);
            } else {
                memcpy((dhopt_buff + dhopt_size + 2), custom_dhcp_options[option_index].option_value, msglen);
            }
            //memcpy((dhopt_buff + dhopt_size + 2), hostname_buff, strlen((const char *) hostname_buff));

            dhopt_size = dhopt_size + 2 + msglen;
        }

        return 0;
}

/*
 * Builds DHCP end of option on dhopt_buff
 */
int build_optioneof()
{
	u_int8_t eof = 0xff;
	memcpy((dhopt_buff + dhopt_size), &eof, 1);
	dhopt_size = dhopt_size + 1;
	return 0;
}

/*
 * Build DHCP packet. Packet type is passed as argument
 */
int build_dhpacket(int pkt_type)
{
	u_int32_t dhcp_packet_size = dhcp_hdr_size + dhopt_size;
	if(!dhcp_release_flag) {
		if (!rtrmac_flag) {
			u_char dmac_tmp[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
			memcpy(dmac, dmac_tmp, ETHER_ADDR_LEN);
		} else {
			memcpy (dmac, rtrmac, ETHER_ADDR_LEN);
		}
	}
	if(pkt_type == DHCP_MSGDISCOVER) {
		if(vlan == 0) {
			struct ethernet_hdr *ethhdr = (struct ethernet_hdr *)dhcp_packet_disc;
			memcpy(ethhdr->ether_dhost, dmac, ETHER_ADDR_LEN);
			memcpy(ethhdr->ether_shost, iface_mac, ETHER_ADDR_LEN);
			ethhdr->ether_type = htons(ETHERTYPE_IP);
		} else {
			struct vlan_hdr *vhdr = (struct vlan_hdr *)dhcp_packet_disc;
			memcpy(vhdr->vlan_dhost, dmac, ETHER_ADDR_LEN);
			memcpy(vhdr->vlan_shost, iface_mac, ETHER_ADDR_LEN);
			vhdr->vlan_tpi = htons(ETHERTYPE_VLAN);
			vhdr->vlan_priority_c_vid = htons(vlan);
			vhdr->vlan_len = htons(ETHERTYPE_IP);
		}
		//print_buff(dhcp_packet_disc, sizeof(struct ethernet_hdr));

		if (padding_flag && dhcp_packet_size < MINIMUM_PACKET_SIZE) {
			memset(dhopt_buff + dhopt_size, 0, MINIMUM_PACKET_SIZE - dhcp_packet_size);
			dhopt_size += MINIMUM_PACKET_SIZE - dhcp_packet_size;
		}

		struct iphdr *iph = (struct iphdr *)(dhcp_packet_disc + l2_hdr_size);
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = l3_tos;
		iph->tot_len = htons(l3_hdr_size +  l4_hdr_size + dhcp_hdr_size + dhopt_size);
		iph->id = 0;
		iph->frag_off = 0;
		iph->ttl = 64;
		iph->protocol = 17;
		iph->check = 0; // Filled later;
		if (unicast_flag)
			iph->saddr = unicast_ip_address;
		else
			iph->saddr = inet_addr("0.0.0.0");
		iph->daddr = inet_addr((const char *) server_addr);
		iph->check = ipchksum((u_int16_t *)(dhcp_packet_disc + l2_hdr_size), iph->ihl << 1);

		struct udphdr *uh = (struct udphdr *) (dhcp_packet_disc + l2_hdr_size + l3_hdr_size);
		uh->source = htons(port + 1);
		uh->dest = htons(port);
		u_int16_t l4_proto = 17;
		u_int16_t l4_len = (l4_hdr_size + dhcp_hdr_size + dhopt_size);
		uh->len = htons(l4_len);
		uh->check = 0; /* UDP checksum will be done after dhcp header*/

		struct dhcpv4_hdr *dhpointer = (struct dhcpv4_hdr *)(dhcp_packet_disc + l2_hdr_size + l3_hdr_size + l4_hdr_size);
		dhpointer->dhcp_opcode = DHCP_REQUEST;
		dhpointer->dhcp_htype = ARPHRD_ETHER;
		dhpointer->dhcp_hlen = ETHER_ADDR_LEN;
		dhpointer->dhcp_hopcount = 0;
		dhpointer->dhcp_xid = htonl(dhcp_xid);
		dhpointer->dhcp_secs = 0;
		dhpointer->dhcp_flags = bcast_flag;
		if (unicast_flag)
			dhpointer->dhcp_cip = unicast_ip_address;
		else
			dhpointer->dhcp_cip = 0;
		dhpointer->dhcp_yip = 0;
		dhpointer->dhcp_sip = 0;
		dhpointer->dhcp_gip = inet_addr((const char *) giaddr);
		memcpy(dhpointer->dhcp_chaddr, dhmac, ETHER_ADDR_LEN);
		/*dhpointer->dhcp_sname
		  dhpointer->dhcp_file*/
		dhpointer->dhcp_magic = htonl(DHCP_MAGIC);

		/* DHCP option buffer is copied here to DHCP packet */
		u_char *dhopt_pointer = (u_char *)(dhcp_packet_disc + l2_hdr_size + l3_hdr_size + l4_hdr_size + dhcp_hdr_size);
		memcpy(dhopt_pointer, dhopt_buff, dhopt_size);

		/* UDP checksum is done here */
		uh->check = l4_sum((u_int16_t *) (dhcp_packet_disc + l2_hdr_size + l3_hdr_size), ((dhcp_hdr_size + dhopt_size + l4_hdr_size) / 2), (u_int16_t *)&iph->saddr, (u_int16_t *)&iph->daddr, htons(l4_proto), htons(l4_len));
	}
	if(pkt_type == DHCP_MSGREQUEST) {
		if(vlan == 0) {
			struct ethernet_hdr *ethhdr = (struct ethernet_hdr *)dhcp_packet_request;
			memcpy(ethhdr->ether_dhost, dmac, ETHER_ADDR_LEN);
			memcpy(ethhdr->ether_shost, iface_mac, ETHER_ADDR_LEN);
			ethhdr->ether_type = htons(ETHERTYPE_IP);
		} else {
			struct vlan_hdr *vhdr = (struct vlan_hdr *)dhcp_packet_request;
			memcpy(vhdr->vlan_dhost, dmac, ETHER_ADDR_LEN);
			memcpy(vhdr->vlan_shost, iface_mac, ETHER_ADDR_LEN);
			vhdr->vlan_tpi = htons(ETHERTYPE_VLAN);
			vhdr->vlan_priority_c_vid = htons(vlan);
			vhdr->vlan_len = htons(ETHERTYPE_IP);
		}
		//print_buff(dhcp_packet_request, sizeof(struct ethernet_hdr));

		if (padding_flag && dhcp_packet_size < MINIMUM_PACKET_SIZE) {
			memset(dhopt_buff + dhopt_size, 0, MINIMUM_PACKET_SIZE - dhcp_packet_size);
			dhopt_size += MINIMUM_PACKET_SIZE - dhcp_packet_size;
		}

		struct iphdr *iph = (struct iphdr *)(dhcp_packet_request + l2_hdr_size);
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = l3_tos;
		iph->tot_len = htons(l3_hdr_size +  l4_hdr_size + dhcp_hdr_size + dhopt_size);
		iph->id = 0;
		iph->frag_off = 0;
		iph->ttl = 64;
		iph->protocol = 17;
		iph->check = 0; // Filled later;
		if (unicast_flag)
			iph->saddr = unicast_ip_address;
		else
			iph->saddr = inet_addr("0.0.0.0");
		iph->daddr = inet_addr((const char *) server_addr);
		iph->check = ipchksum((u_int16_t *)(dhcp_packet_request + l2_hdr_size), iph->ihl << 1);

		struct udphdr *uh = (struct udphdr *) (dhcp_packet_request + l2_hdr_size + l3_hdr_size);
		uh->source = htons(port + 1);
		uh->dest = htons(port);
		u_int16_t l4_proto = 17;
		u_int16_t l4_len = (l4_hdr_size + dhcp_hdr_size + dhopt_size);
		uh->len = htons(l4_len);
		uh->check = 0; /* UDP checksum will be done after building dhcp header*/

		struct dhcpv4_hdr *dhpointer = (struct dhcpv4_hdr *)(dhcp_packet_request + l2_hdr_size + l3_hdr_size + l4_hdr_size);
		dhpointer->dhcp_opcode = DHCP_REQUEST;
		dhpointer->dhcp_htype = ARPHRD_ETHER;
		dhpointer->dhcp_hlen = ETHER_ADDR_LEN;
		dhpointer->dhcp_hopcount = 0;
		dhpointer->dhcp_xid = htonl(dhcp_xid);
		dhpointer->dhcp_secs = 0;
		dhpointer->dhcp_flags = bcast_flag;
		if (unicast_flag)
			dhpointer->dhcp_cip = unicast_ip_address;
		else
			dhpointer->dhcp_cip = 0;
		dhpointer->dhcp_yip = 0;
		dhpointer->dhcp_sip = 0;
		dhpointer->dhcp_gip = inet_addr((const char *) giaddr);
		memcpy(dhpointer->dhcp_chaddr, dhmac, ETHER_ADDR_LEN);
		/*dhpointer->dhcp_sname
		  dhpointer->dhcp_file*/
		dhpointer->dhcp_magic = htonl(DHCP_MAGIC);

		/* DHCP option buffer is copied here to DHCP packet */
		u_char *dhopt_pointer = (u_char *)(dhcp_packet_request + l2_hdr_size + l3_hdr_size + l4_hdr_size + dhcp_hdr_size);
		memcpy(dhopt_pointer, dhopt_buff, dhopt_size);

		/* UDP checksum is done here */
		uh->check = l4_sum((u_int16_t *) (dhcp_packet_request + l2_hdr_size + l3_hdr_size), ((dhcp_hdr_size + dhopt_size + l4_hdr_size) / 2), (u_int16_t *)&iph->saddr, (u_int16_t *)&iph->daddr, htons(l4_proto), htons(l4_len));
	}
	if(pkt_type == DHCP_MSGRELEASE) {
		if(vlan == 0) {
			struct ethernet_hdr *ethhdr = (struct ethernet_hdr *)dhcp_packet_release;
			memcpy(ethhdr->ether_dhost, dmac, ETHER_ADDR_LEN);
			memcpy(ethhdr->ether_shost, iface_mac, ETHER_ADDR_LEN);
			ethhdr->ether_type = htons(ETHERTYPE_IP);
		} else {
			struct vlan_hdr *vhdr = (struct vlan_hdr *)dhcp_packet_release;
			memcpy(vhdr->vlan_dhost, dmac, ETHER_ADDR_LEN);
			memcpy(vhdr->vlan_shost, iface_mac, ETHER_ADDR_LEN);
			vhdr->vlan_tpi = htons(ETHERTYPE_VLAN);
			vhdr->vlan_priority_c_vid = htons(vlan);
			vhdr->vlan_len = htons(ETHERTYPE_IP);
		}
		//(dhcp_packet_disc, sizeof(struct ethernet_hdr));

		if (padding_flag && dhcp_packet_size < MINIMUM_PACKET_SIZE) {
			memset(dhopt_buff + dhopt_size, 0, MINIMUM_PACKET_SIZE - dhcp_packet_size);
			dhopt_size += MINIMUM_PACKET_SIZE - dhcp_packet_size;
		}

		struct iphdr *iph = (struct iphdr *)(dhcp_packet_release + l2_hdr_size);
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = l3_tos;
		iph->tot_len = htons(l3_hdr_size +  l4_hdr_size + dhcp_hdr_size + dhopt_size);
		iph->id = 0;
		iph->frag_off = 0;
		iph->ttl = 64;
		iph->protocol = 17;
		iph->check = 0; // Filled later;
		iph->saddr = option50_ip; //inet_addr("0.0.0.0");
		iph->daddr = server_id; //inet_addr("255.255.255.255");
		iph->check = ipchksum((u_int16_t *)(dhcp_packet_release + l2_hdr_size), iph->ihl << 1);

		struct udphdr *uh = (struct udphdr *) (dhcp_packet_release + l2_hdr_size + l3_hdr_size);
		uh->source = htons(port + 1);
		uh->dest = htons(port);
		u_int16_t l4_proto = 17;
		u_int16_t l4_len = (l4_hdr_size + dhcp_hdr_size + dhopt_size);
		uh->len = htons(l4_len);
		uh->check = 0; /* UDP checksum will be done after dhcp header*/

		struct dhcpv4_hdr *dhpointer = (struct dhcpv4_hdr *)(dhcp_packet_release + l2_hdr_size + l3_hdr_size + l4_hdr_size);
		dhpointer->dhcp_opcode = DHCP_REQUEST;
		dhpointer->dhcp_htype = ARPHRD_ETHER;
		dhpointer->dhcp_hlen = ETHER_ADDR_LEN;
		dhpointer->dhcp_hopcount = 0;
		dhpointer->dhcp_xid = htonl(dhcp_xid);
		dhpointer->dhcp_secs = 0;
		dhpointer->dhcp_flags = bcast_flag;
		dhpointer->dhcp_cip = option50_ip;
		dhpointer->dhcp_yip = 0;
		dhpointer->dhcp_sip = 0;
		dhpointer->dhcp_gip = inet_addr((const char *) giaddr);
		memcpy(dhpointer->dhcp_chaddr, dhmac, ETHER_ADDR_LEN);
		/*dhpointer->dhcp_sname
		  dhpointer->dhcp_file*/
		dhpointer->dhcp_magic = htonl(DHCP_MAGIC);

		/* DHCP option buffer is copied here to DHCP packet */
		u_char *dhopt_pointer = (u_char *)(dhcp_packet_release + l2_hdr_size + l3_hdr_size + l4_hdr_size + dhcp_hdr_size);
		memcpy(dhopt_pointer, dhopt_buff, dhopt_size);

		/* UDP checksum is done here */
		uh->check = l4_sum((u_int16_t *) (dhcp_packet_release + l2_hdr_size + l3_hdr_size), ((dhcp_hdr_size + dhopt_size + l4_hdr_size) / 2), (u_int16_t *)&iph->saddr, (u_int16_t *)&iph->daddr, htons(l4_proto), htons(l4_len));
	}

	if(pkt_type == DHCP_MSGDECLINE) {
		if(vlan == 0) {
			struct ethernet_hdr *ethhdr = (struct ethernet_hdr *)dhcp_packet_decline;
			memcpy(ethhdr->ether_dhost, dmac, ETHER_ADDR_LEN);
			memcpy(ethhdr->ether_shost, iface_mac, ETHER_ADDR_LEN);
			ethhdr->ether_type = htons(ETHERTYPE_IP);
		} else {
			struct vlan_hdr *vhdr = (struct vlan_hdr *)dhcp_packet_decline;
			memcpy(vhdr->vlan_dhost, dmac, ETHER_ADDR_LEN);
			memcpy(vhdr->vlan_shost, iface_mac, ETHER_ADDR_LEN);
			vhdr->vlan_tpi = htons(ETHERTYPE_VLAN);
			vhdr->vlan_priority_c_vid = htons(vlan);
			vhdr->vlan_len = htons(ETHERTYPE_IP);
		}

		if (padding_flag && dhcp_packet_size < MINIMUM_PACKET_SIZE) {
			memset(dhopt_buff + dhopt_size, 0, MINIMUM_PACKET_SIZE - dhcp_packet_size);
			dhopt_size += MINIMUM_PACKET_SIZE - dhcp_packet_size;
		}

		struct iphdr *iph = (struct iphdr *)(dhcp_packet_decline + l2_hdr_size);
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = l3_tos;
		iph->tot_len = htons(l3_hdr_size +  l4_hdr_size + dhcp_hdr_size + dhopt_size);
		iph->id = 0;
		iph->frag_off = 0;
		iph->ttl = 64;
		iph->protocol = 17;
		iph->check = 0; // Filled later;
		iph->saddr = inet_addr("0.0.0.0");
		iph->daddr = inet_addr("255.255.255.255");
		iph->check = ipchksum((u_int16_t *)(dhcp_packet_decline + l2_hdr_size), iph->ihl << 1);

		struct udphdr *uh = (struct udphdr *) (dhcp_packet_decline + l2_hdr_size + l3_hdr_size);
		uh->source = htons(port + 1);
		uh->dest = htons(port);
		u_int16_t l4_proto = 17;
		u_int16_t l4_len = (l4_hdr_size + dhcp_hdr_size + dhopt_size);
		uh->len = htons(l4_len);
		uh->check = 0; /* UDP checksum will be done after dhcp header*/

		struct dhcpv4_hdr *dhpointer = (struct dhcpv4_hdr *)(dhcp_packet_decline + l2_hdr_size + l3_hdr_size + l4_hdr_size);
		dhpointer->dhcp_opcode = DHCP_REQUEST;
		dhpointer->dhcp_htype = ARPHRD_ETHER;
		dhpointer->dhcp_hlen = ETHER_ADDR_LEN;
		dhpointer->dhcp_hopcount = 0;
		dhpointer->dhcp_xid = htonl(dhcp_xid);
		dhpointer->dhcp_secs = 0;
		dhpointer->dhcp_flags = bcast_flag;
		dhpointer->dhcp_cip = 0;
		dhpointer->dhcp_yip = 0;
		dhpointer->dhcp_sip = 0;
		dhpointer->dhcp_gip = inet_addr((const char *) giaddr);
		memcpy(dhpointer->dhcp_chaddr, dhmac, ETHER_ADDR_LEN);
		/*dhpointer->dhcp_sname
		  dhpointer->dhcp_file*/
		dhpointer->dhcp_magic = htonl(DHCP_MAGIC);

		/* DHCP option buffer is copied here to DHCP packet */
		u_char *dhopt_pointer = (u_char *)(dhcp_packet_decline + l2_hdr_size + l3_hdr_size + l4_hdr_size + dhcp_hdr_size);
		memcpy(dhopt_pointer, dhopt_buff, dhopt_size);

		/* UDP checksum is done here */
		uh->check = l4_sum((u_int16_t *) (dhcp_packet_decline + l2_hdr_size + l3_hdr_size), ((dhcp_hdr_size + dhopt_size + l4_hdr_size) / 2), (u_int16_t *)&iph->saddr, (u_int16_t *)&iph->daddr, htons(l4_proto), htons(l4_len));
	}

        return 0;
}

/*
 * build packet - Builds ARP reply and ICMP reply packets
 */
int build_packet(int pkt_type)
{
	bzero(arp_icmp_reply, sizeof(arp_icmp_reply));
	if(pkt_type == ARP_SEND) {
		map_all_layer_ptr(ARP_MAP);
		if(vlan == 0) {
			struct ethernet_hdr *ethhdr = (struct ethernet_hdr *)arp_icmp_reply;
			memcpy(ethhdr->ether_dhost, eth_hg->ether_shost, ETHER_ADDR_LEN);
			memcpy(ethhdr->ether_shost, iface_mac, ETHER_ADDR_LEN);
			ethhdr->ether_type = htons(ETHERTYPE_ARP);
		} else {
			struct vlan_hdr *vhdr = (struct vlan_hdr *)arp_icmp_reply;
			memcpy(vhdr->vlan_dhost, vlan_hg->vlan_shost, ETHER_ADDR_LEN);
			memcpy(vhdr->vlan_shost, iface_mac, ETHER_ADDR_LEN);
			vhdr->vlan_tpi = htons(ETHERTYPE_VLAN);
			vhdr->vlan_priority_c_vid = htons(vlan);
			vhdr->vlan_len = htons(ETHERTYPE_ARP);
		}
		struct arp_hdr *arph = (struct arp_hdr *)(arp_icmp_reply + l2_hdr_size);
		arph->ar_hrd = htons(ARPHRD_ETHER);
		arph->ar_pro = htons(ETHERTYPE_IP);
		arph->ar_hln = ETHER_ADDR_LEN;
		arph->ar_pln = IP_ADDR_LEN;
		arph->ar_op = htons(ARPOP_REPLY);
		u_int32_t ip_addr_tmp;
		ip_addr_tmp = htonl(ip_address);
		memcpy(arph->sender_mac, iface_mac, ETHER_ADDR_LEN);
		memcpy(arph->sender_ip, (u_char *)&ip_addr_tmp, IP_ADDR_LEN);
		memcpy(arph->target_mac, arp_hg->sender_mac, ETHER_ADDR_LEN);
		memcpy(arph->target_ip, arp_hg->sender_ip, IP_ADDR_LEN);
	} else if(ICMP_SEND) {
		map_all_layer_ptr(ICMP_MAP);
		if(vlan == 0) {
			struct ethernet_hdr *ethhdr = (struct ethernet_hdr *)arp_icmp_reply;
			memcpy(ethhdr->ether_dhost, eth_hg->ether_shost, ETHER_ADDR_LEN);
			memcpy(ethhdr->ether_shost, iface_mac, ETHER_ADDR_LEN);
			ethhdr->ether_type = htons(ETHERTYPE_IP);
		} else {
			struct vlan_hdr *vhdr = (struct vlan_hdr *)arp_icmp_reply;
			memcpy(vhdr->vlan_dhost, vlan_hg->vlan_shost, ETHER_ADDR_LEN);
			memcpy(vhdr->vlan_shost, iface_mac, ETHER_ADDR_LEN);
			vhdr->vlan_tpi = htons(ETHERTYPE_VLAN);
			vhdr->vlan_priority_c_vid = htons(vlan);
			vhdr->vlan_len = htons(ETHERTYPE_IP);
		}
		//print_buff(dhcp_packet_request, sizeof(struct ethernet_hdr));

		struct iphdr *iph = (struct iphdr *)(arp_icmp_reply + l2_hdr_size);
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = l3_tos;
		iph->tot_len = 0; /* Filled later */
		iph->id = 0; /* (iph_g->id + 5000); */
		iph->frag_off = 0;
		iph->ttl = 128;
		iph->protocol = 1;
		iph->check = 0; // Filled later;
		iph->saddr = htonl(ip_address);
		iph->daddr = iph_g->saddr;
		/* iph->daddr = inet_addr("255.255.255.255"); */

		struct icmp_hdr *ich = (struct icmp_hdr *)(arp_icmp_reply + l2_hdr_size + l3_hdr_size);
		ich->icmp_type = ICMP_ECHOREPLY;
		ich->icmp_code = 0;
		ich->icmp_sum = 0;
		ich->id = icmp_hg->id;
		ich->seq = icmp_hg->seq;
		icmp_len = (ntohs(iph_g->tot_len) - (iph_g->ihl << 2) - ICMP_H);
		memcpy((((u_char *)&ich->seq) + 1), (((u_char *)&icmp_hg->seq) +1), (icmp_len + 1));
		iph->tot_len = htons((l3_hdr_size + ICMP_H + icmp_len));
		iph->check = ipchksum((u_int16_t *)(arp_icmp_reply + l2_hdr_size), iph->ihl << 1);
		ich->icmp_sum = icmpchksum((u_int16_t *)(arp_icmp_reply + l2_hdr_size + l3_hdr_size), ((icmp_len + ICMP_H) / 2));
	}
	return 0;
}

/*
 * Checks whether received packet is DHCP offer/ACK/NACK/ARP/ICMP
 * and retunrs the received packet type
 */
int check_packet(int pkt_type)
{

	u_int8_t *dhopt_pointer_tmp;
	if(pkt_type == DHCP_MSGOFFER && vlan != 0) {
		map_all_layer_ptr(DHCP_MSGOFFER);
		if((ntohs(vlan_hg->vlan_priority_c_vid) & VLAN_VIDMASK) == vlan && ntohs(vlan_hg->vlan_tpi) == ETHERTYPE_VLAN && iph_g->protocol == 17 && uh_g->source == htons(port) && (uh_g->dest == htons(port + 1) || uh_g->dest == htons(port))) {
			dhopt_pointer_tmp = dhopt_pointer_g;
			while(*(dhopt_pointer_tmp) != DHCP_END) {
				if( *(dhopt_pointer_tmp) == DHCP_MESSAGETYPE && *(dhopt_pointer_tmp + 2) == DHCP_MSGOFFER && htonl(dhcph_g->dhcp_xid) == dhcp_xid) {
					return DHCP_OFFR_RCVD;
					break;
				}

				if (*(dhopt_pointer_tmp) == DHCP_PAD) {
					/* DHCP_PAD option - increment dhopt_pointer_tmp by one */
					dhopt_pointer_tmp = dhopt_pointer_tmp + 1;
				} else {
					dhopt_pointer_tmp = dhopt_pointer_tmp + *(dhopt_pointer_tmp + 1) + 2;
				}
			}
			return UNKNOWN_PACKET;

		} else {
			return UNKNOWN_PACKET;
		}
	} else if (pkt_type == DHCP_MSGACK && vlan != 0){
		map_all_layer_ptr(DHCP_MSGACK);
		if((ntohs(vlan_hg->vlan_priority_c_vid) & VLAN_VIDMASK)== vlan && ntohs(vlan_hg->vlan_tpi) == ETHERTYPE_VLAN && iph_g->protocol == 17 && uh_g->source == htons(port) && (uh_g->dest == htons(port + 1) || uh_g->dest == htons(port))) {
			dhopt_pointer_tmp = dhopt_pointer_g;
			while(*(dhopt_pointer_tmp) != DHCP_END) {
				if( *(dhopt_pointer_tmp) == DHCP_MESSAGETYPE && *(dhopt_pointer_tmp + 2) == DHCP_MSGACK && htonl(dhcph_g->dhcp_xid) == dhcp_xid) {
					return DHCP_ACK_RCVD;
					break;
				}
				if( *(dhopt_pointer_tmp) == DHCP_MESSAGETYPE && *(dhopt_pointer_tmp + 2) == DHCP_MSGNACK && htonl(dhcph_g->dhcp_xid) == dhcp_xid) {
					return DHCP_NAK_RCVD;
					break;
				}

				if (*(dhopt_pointer_tmp) == DHCP_PAD) {
					/* DHCP_PAD option - increment dhopt_pointer_tmp by one */
					dhopt_pointer_tmp = dhopt_pointer_tmp + 1;
				} else {
					dhopt_pointer_tmp = dhopt_pointer_tmp + *(dhopt_pointer_tmp + 1) + 2;
				}
			}
			return UNKNOWN_PACKET;

		} else {
			return UNKNOWN_PACKET;
		}
	} else if (pkt_type == DHCP_MSGOFFER) {
		map_all_layer_ptr(DHCP_MSGOFFER);
		if(eth_hg->ether_type == htons(ETHERTYPE_IP) && iph_g->protocol == 17 && uh_g->source == htons(port) && (uh_g->dest == htons(port + 1) || uh_g->dest == htons(port))) {
			dhopt_pointer_tmp = dhopt_pointer_g;
			while(*(dhopt_pointer_tmp) != DHCP_END) {
				if( *(dhopt_pointer_tmp) == DHCP_MESSAGETYPE && *(dhopt_pointer_tmp + 2) == DHCP_MSGOFFER && htonl(dhcph_g->dhcp_xid) == dhcp_xid) {
					return DHCP_OFFR_RCVD;
					break;
				}

				if (*(dhopt_pointer_tmp) == DHCP_PAD) {
					/* DHCP_PAD option - increment dhopt_pointer_tmp by one */
					dhopt_pointer_tmp = dhopt_pointer_tmp + 1;
				} else {
					dhopt_pointer_tmp = dhopt_pointer_tmp + *(dhopt_pointer_tmp + 1) + 2;
				}
			}
			return UNKNOWN_PACKET;
		} else {
			return UNKNOWN_PACKET;
		}

	} else if (pkt_type == DHCP_MSGACK) {
		map_all_layer_ptr(DHCP_MSGACK);
		if(eth_hg->ether_type == htons(ETHERTYPE_IP) && iph_g->protocol == 17 && uh_g->source == htons(port) && (uh_g->dest == htons(port + 1) || uh_g->dest == htons(port))) {
			dhopt_pointer_tmp = dhopt_pointer_g;
			while(*(dhopt_pointer_tmp) != DHCP_END) {
				if( *(dhopt_pointer_tmp) == DHCP_MESSAGETYPE && *(dhopt_pointer_tmp + 2) == DHCP_MSGACK && htonl(dhcph_g->dhcp_xid) == dhcp_xid) {
					return DHCP_ACK_RCVD;
					break;
				}
				if( *(dhopt_pointer_tmp) == DHCP_MESSAGETYPE && *(dhopt_pointer_tmp + 2) == DHCP_MSGNACK && htonl(dhcph_g->dhcp_xid) == dhcp_xid) {
					return DHCP_NAK_RCVD;
					break;
				}

				if (*(dhopt_pointer_tmp) == DHCP_PAD) {
					/* DHCP_PAD option - increment dhopt_pointer_tmp by one */
					dhopt_pointer_tmp = dhopt_pointer_tmp + 1;
				} else {
					dhopt_pointer_tmp = dhopt_pointer_tmp + *(dhopt_pointer_tmp + 1) + 2;
				}
			}
			return UNKNOWN_PACKET;
		} else {
			return UNKNOWN_PACKET;
		}
	} else if(pkt_type == ARP_ICMP_RCV) {
		map_all_layer_ptr(ARP_MAP);
		if(!vlan) {

			if((ntohs(arp_hg->ar_op)) == ARPOP_REQUEST && (htonl(ip_address)) == (*((u_int32_t *)(arp_hg->target_ip)))) {
				return ARP_RCVD;
			}
		} else if(vlan && ntohs(vlan) == (vlan_hg->vlan_priority_c_vid & VLAN_VIDMASK)) {
			if((ntohs(arp_hg->ar_op)) == ARPOP_REQUEST && (htonl(ip_address)) == (*((u_int32_t *)(arp_hg->target_ip)))) {
				if(0) {
				} else {
					fprintf(stdout, "Arp request received\n");
				}
				return ARP_RCVD;
			}
		}
		map_all_layer_ptr(ICMP_MAP);
		if(!vlan) {
			if((ntohs(eth_hg->ether_type)) == ETHERTYPE_IP && iph_g->protocol == 1 && ip_address == ntohl(iph_g->daddr) && icmp_hg->icmp_type == ICMP_ECHO) {
				return ICMP_RCVD;
			}
		} else if(vlan && ntohs(vlan) == (vlan_hg->vlan_priority_c_vid & VLAN_VIDMASK)) {
			if((ntohs(vlan_hg->vlan_len)) == ETHERTYPE_IP && iph_g->protocol == 1 && ip_address == ntohl(iph_g->daddr) && icmp_hg->icmp_type == ICMP_ECHO) {
				return ICMP_RCVD;
			}
		}
		return UNKNOWN_PACKET;
	}

    return UNKNOWN_PACKET;
}

/*
 * Sets the server ip and offerered ip on serv_id, option50_ip
 * from the DHCP offer packet
 */
int set_serv_id_opt50()
{
	map_all_layer_ptr(DHCP_MSGOFFER);

	option50_ip = dhcph_g->dhcp_yip;

	while(*(dhopt_pointer_g) != DHCP_END) {
		if(*(dhopt_pointer_g) == DHCP_SERVIDENT) {
			memcpy(&server_id, (u_int32_t *)(dhopt_pointer_g + 2), 4);
		}
		dhopt_pointer_g = dhopt_pointer_g + *(dhopt_pointer_g + 1) + 2;
	}
	return 0;
}

/*
 * Prints the DHCP offer/ack info
 */
int print_dhinfo(int pkt_type)
{
	u_int16_t tmp;
	if(pkt_type == DHCP_MSGOFFER) {
		map_all_layer_ptr(DHCP_MSGOFFER);

		if(0) {
		} else {
			fprintf(stdout, "\nDHCP offer details\n");
			fprintf(stdout, "----------------------------------------------------------\n");
			fprintf(stdout, "DHCP offered IP from server - %s\n", get_ip_str(dhcph_g->dhcp_yip));
			fprintf(stdout, "Next server IP(Probably TFTP server) - %s\n", get_ip_str(dhcph_g->dhcp_sip));
			if(dhcph_g->dhcp_gip) {
				fprintf(stdout, "DHCP Relay agent IP - %s\n", get_ip_str(dhcph_g->dhcp_gip));
			}
		}
	} else if( pkt_type == DHCP_MSGACK) {
		map_all_layer_ptr(DHCP_MSGACK);

		if(0) {
                } else {
			fprintf(stdout, "\nDHCP ack details\n");
			fprintf(stdout, "----------------------------------------------------------\n");
			fprintf(stdout, "DHCP offered IP from server - %s\n", get_ip_str(dhcph_g->dhcp_yip));
			fprintf(stdout, "Next server IP(Probably TFTP server) - %s\n", get_ip_str(dhcph_g->dhcp_sip));
			if(dhcph_g->dhcp_gip) {
				fprintf(stdout, "DHCP Relay agent IP - %s\n", get_ip_str(dhcph_g->dhcp_gip));
			}
		}
	}

	while(*(dhopt_pointer_g) != DHCP_END) {

		switch(*(dhopt_pointer_g)) {
			case DHCP_SERVIDENT:
				if(0) {
				} else {
					fprintf(stdout, "DHCP server  - %s\n", get_ip_str(*(u_int32_t *)(dhopt_pointer_g + 2)));
				}
				break;

			case DHCP_LEASETIME:
				if(0) {
                                } else {
					fprintf(stdout, "Lease time - %d Days %d Hours %d Minutes\n", \
							(ntohl(*(u_int32_t *)(dhopt_pointer_g + 2))) / (3600 * 24), \
							((ntohl(*(u_int32_t *)(dhopt_pointer_g + 2))) % (3600 * 24)) / 3600, \
							(((ntohl(*(u_int32_t *)(dhopt_pointer_g + 2))) % (3600 * 24)) % 3600) / 60);
				}
				break;

			case DHCP_SUBNETMASK:
				if(0) {
                                } else {
					fprintf(stdout, "Subnet mask - %s\n", get_ip_str(*(u_int32_t *)(dhopt_pointer_g + 2)));
				}
				break;

			case DHCP_ROUTER:
				for(tmp = 0; tmp < (*(dhopt_pointer_g + 1) / 4); tmp++) {
					if(0) {
					} else {
						fprintf(stdout, "Router/gateway - %s\n", get_ip_str(*(u_int32_t *)(dhopt_pointer_g + 2 + (tmp * 4))));
					}
				}
				break;

			case DHCP_DNS:
				for(tmp = 0; tmp < ((*(dhopt_pointer_g + 1)) / 4); tmp++) {
					if(0) {
                                        } else {
						fprintf(stdout, "DNS server - %s\n", get_ip_str(*(u_int32_t *)(dhopt_pointer_g + 2 + (tmp * 4))));
					}
				}
				break;

			case DHCP_FQDN:
				{
					/* Minus 3 beacause 3 bytes are used to flags, rcode1 and rcode2 */
					u_int32_t size = (u_int32_t)*(dhopt_pointer_g + 1) - 3;
					/* Plus 2 to add string terminator */
					u_char fqdn_client_name[size + 1];

					/* Plus 5 to reach the beginning of the string */
					memcpy(fqdn_client_name, dhopt_pointer_g + 5, size);
					fqdn_client_name[size] = '\0';

					if(0) {
                                        } else {
						fprintf(stdout, "FQDN Client name - %s\n", fqdn_client_name);
					}
				}
                                break;

                        default:
				if(0) {
				} else {
					fprintf(stdout, "Option no - %d, option length - %d", *dhopt_pointer_g, *(dhopt_pointer_g + 1));
                                	print_dhoption((dhopt_pointer_g + 2),*(dhopt_pointer_g + 1));
				}
		}

                if (*(dhopt_pointer_g) == DHCP_PAD) {
                    /* DHCP_PAD option - increment dhopt_pointer_g by one */
                    dhopt_pointer_g = dhopt_pointer_g + 1;
                } else {
                    dhopt_pointer_g = dhopt_pointer_g + *(dhopt_pointer_g + 1) + 2;
                }
	}

	if(!json_flag) {
		fprintf(stdout, "----------------------------------------------------------\n\n");
	}
	return 0;
}

/*
 * Function maps all pointers on OFFER/ACK/ARP/ICMP packet
 */
int map_all_layer_ptr(int pkt_type)
{
	if(pkt_type == DHCP_MSGOFFER && vlan != 0) {
		vlan_hg = (struct vlan_hdr *)dhcp_packet_offer;
		iph_g = (struct iphdr *)(dhcp_packet_offer + l2_hdr_size);
		uh_g = (struct udphdr *)(dhcp_packet_offer + l2_hdr_size + l3_hdr_size);
		dhcph_g = (struct dhcpv4_hdr *)(dhcp_packet_offer + l2_hdr_size + l3_hdr_size + l4_hdr_size);
		dhopt_pointer_g = (u_int8_t *)(dhcp_packet_offer + l2_hdr_size + l3_hdr_size + l4_hdr_size + sizeof(struct dhcpv4_hdr));
	} else if(pkt_type == DHCP_MSGOFFER && vlan == 0) {
		eth_hg = (struct ethernet_hdr *)dhcp_packet_offer;
		iph_g = (struct iphdr *)(dhcp_packet_offer + l2_hdr_size);
		uh_g = (struct udphdr *)(dhcp_packet_offer + l2_hdr_size + l3_hdr_size);
		dhcph_g = (struct dhcpv4_hdr *)(dhcp_packet_offer + l2_hdr_size + l3_hdr_size + l4_hdr_size);
		dhopt_pointer_g = (u_int8_t *)(dhcp_packet_offer + l2_hdr_size + l3_hdr_size + l4_hdr_size + sizeof(struct dhcpv4_hdr));
	} else if(pkt_type == DHCP_MSGACK && vlan != 0) {
		vlan_hg = (struct vlan_hdr *)dhcp_packet_ack;
		iph_g = (struct iphdr *)(dhcp_packet_ack + l2_hdr_size);
		uh_g = (struct udphdr *)(dhcp_packet_ack + l2_hdr_size + l3_hdr_size);
		dhcph_g = (struct dhcpv4_hdr *)(dhcp_packet_ack + l2_hdr_size + l3_hdr_size + l4_hdr_size);
		dhopt_pointer_g = (u_int8_t *)(dhcp_packet_ack + l2_hdr_size + l3_hdr_size + l4_hdr_size + sizeof(struct dhcpv4_hdr));
	} else if(pkt_type == DHCP_MSGACK && vlan == 0) {
		eth_hg = (struct ethernet_hdr *)dhcp_packet_ack;
		iph_g = (struct iphdr *)(dhcp_packet_ack + l2_hdr_size);
		uh_g = (struct udphdr *)(dhcp_packet_ack + l2_hdr_size + l3_hdr_size);
		dhcph_g = (struct dhcpv4_hdr *)(dhcp_packet_ack + l2_hdr_size + l3_hdr_size + l4_hdr_size);
		dhopt_pointer_g = (u_int8_t *)(dhcp_packet_ack + l2_hdr_size + l3_hdr_size + l4_hdr_size + sizeof(struct dhcpv4_hdr));
	} else if(pkt_type == ARP_MAP && vlan != 0) {
		vlan_hg = (struct vlan_hdr *)arp_icmp_packet;
		arp_hg = (struct arp_hdr *)(arp_icmp_packet + l2_hdr_size);
	} else if(pkt_type == ARP_MAP && vlan == 0) {
		eth_hg = (struct ethernet_hdr *)arp_icmp_packet;
		arp_hg = (struct arp_hdr *)(arp_icmp_packet + l2_hdr_size);
	} else if(pkt_type == ICMP_MAP && vlan != 0) {
		vlan_hg = (struct vlan_hdr *)arp_icmp_packet;
		iph_g = (struct iphdr *)(arp_icmp_packet + l2_hdr_size);
		icmp_hg = (struct icmp_hdr *)(arp_icmp_packet + l2_hdr_size + l3_hdr_size);
	} else if(pkt_type == ICMP_MAP && vlan == 0) {
		eth_hg = (struct ethernet_hdr *)arp_icmp_packet;
		iph_g = (struct iphdr *)(arp_icmp_packet + l2_hdr_size);
		icmp_hg = (struct icmp_hdr *)(arp_icmp_packet + l2_hdr_size + l3_hdr_size);
	}
	return 0;
}
int log_dhinfo()
{
	map_all_layer_ptr(DHCP_MSGACK);
	
	printf("Client_mac: %s\n", dhmac_fname);
		printf("Acquired_ip: %s\n", get_ip_str(dhcph_g->dhcp_yip));
		printf("Server_id: %s\n", get_ip_str(server_id));
		printf("gateway_ip: %s\n", get_ip_str(dhcph_g->dhcp_gip));
}

int get_dhinfo()
{
	FILE *dh_file;
	u_char aux_dmac[ETHER_ADDR_LEN+3];  //[Fix for Seg Fault] @inov8shn - add a few extra chars to this buffer, since fscanf("%2X") below returns a u_int32_t, and was triggering a Segmentation Fault when run for last byte read (&aux_dmac[5]).
	char mac_tmp[20], acq_ip_tmp[20], serv_id_tmp[20], ip_listen_tmp[10];
	pid_t dh_pid;
	int items;
	dh_file = fopen(dhmac_fname, "r");
	if(dh_file == NULL) {
		return ERR_FILE_OPEN;
	}
	items = fscanf(dh_file, "Client_mac: %s\nAcquired_ip: %s\nServer_id: %s\n\
			Host_mac: %2X:%2X:%2X:%2X:%2X:%2X\nIP_listen: %s Pid: %d", mac_tmp, acq_ip_tmp, serv_id_tmp, \
			(u_int32_t *) &aux_dmac[0], (u_int32_t *) &aux_dmac[1], (u_int32_t *) &aux_dmac[2], \
			(u_int32_t *) &aux_dmac[3], (u_int32_t *) &aux_dmac[4], (u_int32_t *) &aux_dmac[5], \
			ip_listen_tmp, &dh_pid);
	if (items == EOF || items < 11) {
		return ERR_FILE_FORMAT;
	}
	memcpy(dmac, aux_dmac, sizeof(dmac));
	option50_ip = inet_addr(acq_ip_tmp);
	server_id = inet_addr(serv_id_tmp);
	if((strncmp(ip_listen_tmp, "True", 4)) == 0) {
		kill(dh_pid, SIGKILL);
	}
	fclose(dh_file);
	unlink(dhmac_fname);
	return 0;
}

/* DHCP option print function - Prints DHCP option on HEX and ASCII format */
int print_dhoption(u_int8_t *buff, int size)
{
	int tmp;
	fprintf(stdout, "\n  OPTION data (HEX)\n    ");
	for(tmp = 0; tmp < size; tmp++) {
		fprintf(stdout, "%02X ", buff[tmp]);
		if((tmp % 16) == 0 && tmp != 0) {
			fprintf(stdout, "\n    ");
		}
	}
        fprintf(stdout, "\n  OPTION data (ASCII)\n    ");
	for(tmp = 0; tmp < size; tmp++) {
		fprintf(stdout, "%c", buff[tmp]);
		if((tmp % 16) == 0 && tmp != 0) {
			fprintf(stdout, "\n    ");
		}
	}
        fprintf(stdout, "\n");
	return 0;
}

char *get_ip_str(u_int32_t ip)
{
	struct in_addr src;
	src.s_addr = ip;
	inet_ntop(AF_INET, ((struct sockaddr_in *) &src),
			ip_str, sizeof(ip_str));
	return ip_str;
}


/*
  Return the mac address of the selected interface
  User must allocate the buffer for store the address
 */
int get_if_mac_address(char *if_name, uint8_t *mac_address)
{
  struct ifreq ifr;
  int sockfd;

  if(!mac_address)
    {
      fprintf(stderr,"Invalid mac address buffer\n");
      return 1;
    }

  if((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0)
    {
      perror("Error opening socket:");
      return SOCKET_ERR;
    }

  // get the mac address ot the interface
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name)-1);
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0)
    {
      perror("Error getting interface's MAC address:");
      close(sockfd);
      return 1;
    }

  memcpy(mac_address, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  close(sockfd);
  return 0;
}


char *mac2str(uint8_t *mac_addr)
{
  static char str[25];

  snprintf(str, 25, "%02x:%02x:%02x:%02x:%02x:%02x",
	   mac_addr[0], mac_addr[1], mac_addr[2],
	   mac_addr[3], mac_addr[4], mac_addr[5]);

  return str;
}


int str2mac(char *str, uint8_t *mac_addr)
{
  char local_mac_str[25];

  // check if both required parameters are ok
  // may be an assert is better ?
  if(!str || !mac_addr)
    return 1;

  strncpy(local_mac_str, str, 24);
  local_mac_str[24] = 0x00;

  // replace semicolons with end of string character
  local_mac_str[2] =  local_mac_str[5] =  local_mac_str[8] =  local_mac_str[11] =  local_mac_str[14] = 0x00;

  mac_addr[0] = (uint8_t)strtol(local_mac_str,NULL,16);
  mac_addr[1] = (uint8_t)strtol(local_mac_str+3,NULL,16);
  mac_addr[2] = (uint8_t)strtol(local_mac_str+6,NULL,16);
  mac_addr[3] = (uint8_t)strtol(local_mac_str+9,NULL,16);
  mac_addr[4] = (uint8_t)strtol(local_mac_str+12,NULL,16);
  mac_addr[5] = (uint8_t)strtol(local_mac_str+15,NULL,16);

  return 0;
}
