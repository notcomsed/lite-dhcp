int build_option53(int msg_type)
{
	if(msg_type == DHCP_MSGDISCOVER ||
	   msg_type == DHCP_MSGREQUEST ||
	   msg_type == DHCP_MSGRELEASE ||
	   msg_type == DHCP_MSGDECLINE) {
		u_int8_t msgtype = DHCP_MESSAGETYPE;
		u_int8_t msglen = 1;
		u_int8_t msg = (u_int8_t) msg_type;

		memcpy(dhopt_buff, &msgtype, 1);
		memcpy(dhopt_buff + 1, &msglen, 1);
		memcpy(dhopt_buff + 2, &msg, 1);
		dhopt_size = dhopt_size + 3;
	}
	return 0;
}

/*
 * Builds DHCP option50 on dhopt_buff
 */
int build_option50()
{
	u_int8_t msgtype = DHCP_REQUESTEDIP;
	u_int8_t msglen = 4;
	u_int32_t msg = option50_ip;

	memcpy((dhopt_buff + dhopt_size), &msgtype, 1);
	memcpy((dhopt_buff + dhopt_size + 1), &msglen, 1);
	memcpy((dhopt_buff + dhopt_size + 2), &msg, 4);
	dhopt_size = dhopt_size + 6;
	return 0;
}

/*
 * Builds DHCP option51 on dhopt_buff - DHCP lease time requested
 */
int build_option51()
{
	u_int8_t msgtype = DHCP_LEASETIME;
	u_int8_t msglen = 4;
	u_int32_t msg = htonl(option51_lease_time);

	memcpy((dhopt_buff + dhopt_size), &msgtype, 1);
	memcpy((dhopt_buff + dhopt_size + 1), &msglen, 1);
	memcpy((dhopt_buff + dhopt_size + 2), &msg, 4);
	dhopt_size = dhopt_size + 6;
	return 0;
}
/*
 * Builds DHCP option54 on dhopt_buff
 */
int build_option54()
{
	u_int8_t msgtype = DHCP_SERVIDENT;
	u_int8_t msglen = 4;
	u_int32_t msg = server_id;

	memcpy((dhopt_buff + dhopt_size), &msgtype, 1);
	memcpy((dhopt_buff + dhopt_size + 1), &msglen, 1);
	memcpy((dhopt_buff + dhopt_size + 2), &msg, 4);
	dhopt_size = dhopt_size + 6;
        return 0;
}

/*
 * Builds DHCP option55 on dhopt_buff
 */
int build_option55()
{
	if (option55_req_flag == 0) {
                u_int32_t msgtype = DHCP_PARAMREQUEST;
                u_int32_t msglen = 5;
                u_int8_t msg[5] = { 0 };
                msg[0] = DHCP_SUBNETMASK;
                msg[1] = DHCP_BROADCASTADDR;
                msg[2] = DHCP_ROUTER;
                msg[3] = DHCP_DOMAINNAME;
                msg[4] = DHCP_DNS;
                /* msg[5] = DHCP_LOGSERV; */

                memcpy((dhopt_buff + dhopt_size), &msgtype, 1);
                memcpy((dhopt_buff + dhopt_size + 1), &msglen, 1);
                memcpy((dhopt_buff + dhopt_size + 2), msg, 5);
                dhopt_size = dhopt_size + 7;
                return 0;
	} else if (option55_req_flag == 1) {
                u_int32_t msgtype = DHCP_PARAMREQUEST;
                u_int32_t msglen = option55_req_len;

                memcpy((dhopt_buff + dhopt_size), &msgtype, 1);
                memcpy((dhopt_buff + dhopt_size + 1), &msglen, 1);
                memcpy((dhopt_buff + dhopt_size + 2), option55_req_list, option55_req_len);
                dhopt_size = dhopt_size + option55_req_len + 2;
	}
}
int build_option12_hostname()
{
	u_int32_t msgtype = DHCP_HOSTNAME;
	u_int32_t msglen = strlen((const char *) hostname_buff);

	memcpy((dhopt_buff + dhopt_size), &msgtype, 1);
	memcpy((dhopt_buff + dhopt_size + 1), &msglen, 1);
	memcpy((dhopt_buff + dhopt_size + 2), hostname_buff, strlen((const char *) hostname_buff));

	dhopt_size = dhopt_size + 2 + strlen((const char *) hostname_buff);
	return 0;
}
