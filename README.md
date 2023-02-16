# lite-dhcp
超小的DHCP客户端,能够以非特权模式运行,不依赖其他组件.

基于unix哲学编程,每一个组件功能单一,能够独立运行.

## ldhcp
##### 组件1 , lite DHCP

DHCP发现器,发送DHCP数据包,获取DHCP地址

ldhcp提供一个api,api会监听127.0.0.1:1026端口, 可以向127.0.0.1:1026发送api请求.

简单请求示例

```bash
nc 127.0.0.1 1026 < ncdata.dat 
```

得到以下结果
```bash
server: 192.168.1.1 #DHCP服务器地址
gateway: 192.168.1.1 #网关地址
subnet: 255.255.255.0 #子网掩码
ipadderss: 192.168.1.100 #IP地址
```

ldhcp启动

```bash
ldhcp -i ens32 -h debian -u nobody
```
`-i`网卡

ens32 网卡名,可改为eth0

`-h`主机名

debian 主机名,可用$HOSTNAME替代

`-u`用户

nobody 以nobody用户运行,可以为任意用户,默认systemd-network

#### 注意ldhcp并不会设置IP地址,仅仅会发送DHCP请求和续租, 并启动api接口.

## dhcpd
##### 组件2 , DHCP daemon

用来监测网卡变化,DHCP信息变化,并自动设置网卡IP地址.

启动
```bash
dhcpd ens32 -u ldhcp -d 
```

ens32 监测的网卡名称

`-u`用户

ldhcp 为使用ldhcp用户启动

`-d` daemon 守护模式

## scr
##### 组件3 , script

一些自动配置DHCP脚本文件

# 快速使用

请确保已经安装如下组件
`busybox`, `gcc`, `g++`, `make`

在root权限下运行以下命令安装

```bash
sh install.sh
```

安装前请清理其他DHCP管理软件,`NetworkManager`, `systemd-networkd`, `udhcpd`, `isc-dhcpd`等

其实不清理也可以安装上去的,如果你想装多个的话.

# 后记
这个DHCP软件仅仅会配置网卡的IP地址, 并不会接管你的DNS和做其他多余的事情. 请手动配置dns.

```bash
vim  /etc/resolv.conf
#
nameserver 1.1.1.1
nameserver 8.8.8.8
```

这个软件开发初衷就是systemd管的太多了,并且systemd-networkd依赖polkit. 试过其他的`isc-dhcp`, `udhcp`,功能太多, 而且都不能以非root权限运行. 遇到漏洞远程执行直接以root权限执行.

这个软件不依赖polkit等其他任何组件,可以独立运行. 也能以非特权用户运行

加上代码大小才72k, 远远小于`udhcp`,`iSC-DHCP`. 轻量,每个组件都可以单独拆开用

### 许可证
General Public License v3
