cd `pwd`

mkdir /usr/lib/ldhcp
mkdir /usr/lib/ldhcpd

echo ldhcp:x:327:65534:lite dhcp,,,:/usr/lib/ldhcp:/usr/sbin/nologin >> /etc/passwd
echo ldhcp:*:18667:0:99999:7::: >> /etc/shadow

chown ldhcp /usr/lib/ldhcp
chmod 700 /usr/lib/ldhcp
chmod 700 /usr/lib/ldhcpd

cd dhcpd
make
cp dhcpd /sbin/dhcpd
chmod 755 /sbin/dhcpd

cd ../ldhcp
make
cp ldhcp /sbin/ldhcp
chmod 700 /sbin/ldhcp

cd ../scr
cp *.sh /usr/lib/ldhcp
#cp *.txt /usr/lib/ldhcp
cp *.dat /usr/lib/ldhcp
echo 0 > /usr/lib/ldhcpd/outdhcp.log
cp *.sh /usr/lib/ldhcpd