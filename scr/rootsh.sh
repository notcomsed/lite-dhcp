cd /usr/lib/ldhcpd
flag=$(head -c 1 /usr/lib/ldhcp/flag.txt)
if [ "$flag" -eq "1" ]; then
echo -n 0 > /usr/lib/ldhcp/flag.txt
cat /usr/lib/ldhcpd/outdhcp.log|sh >> /usr/lib/ldhcpd/dhcplog.log
fi