cd /usr/lib/ldhcp
pwd=/usr/lib/ldhcp

echo -n 1 > $pwd/flag.txt


busybox cp -f $pwd/md5info.txt $pwd/md5last.txt
#get ip
cat $pwd/dhcpinfo.txt|grep ipaddress > $pwd/ip.txt
sed -i 's/ipaddress\:/ /g' $pwd/ip.txt
ipaddr=$(cat $pwd/ip.txt)
/sbin/dhcpd $ipaddr > $pwd/indhcp.log
echo >> $pwd/indhcp.log
#get gateway
cat $pwd/dhcpinfo.txt|grep gateway > $pwd/ip.txt
sed -i 's/gateway\:/ /g' $pwd/ip.txt
ipaddr=$(cat $pwd/ip.txt)
/sbin/dhcpd $ipaddr >> $pwd/indhcp.log
echo >> $pwd/indhcp.log
#get subnet
cat $pwd/dhcpinfo.txt|grep subnet > $pwd/ip.txt
sed -i 's/subnet\:/ /g' $pwd/ip.txt
ipaddr=$(cat $pwd/ip.txt)
/sbin/dhcpd $ipaddr >> $pwd/indhcp.log
echo >> $pwd/indhcp.log
echo End >> $pwd/indhcp.log