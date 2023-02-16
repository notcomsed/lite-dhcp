cd /usr/lib/ldhcp
sh /usr/lib/ldhcp/getinfo.sh > /usr/lib/ldhcp/dhcp1.txt
head -n 7 /usr/lib/ldhcp/dhcp1.txt > /usr/lib/ldhcp/dhcpinfo.txt
busybox md5sum /usr/lib/ldhcp/dhcpinfo.txt > /usr/lib/ldhcp/md5info.txt
lastdhcp=$(head -c 16 /usr/lib/ldhcp/md5last.txt||echo fail)
newdhcp=$(head -c 16 /usr/lib/ldhcp/md5info.txt)
echo $lastdhcp|grep $newdhcp||sh /usr/lib/ldhcp/sedhcp.sh