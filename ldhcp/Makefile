CFLAGS=-DLINUX -g


ldhcp:
	cat include.h>make.o
	cat vard.h>>make.o
	cat func.c>>make.o
	cat ldhcp.c>>make.o
	cat dhcpopt.c>>make.o
	cat server.c>>make.o
	cat main.c>>make.o
	cat make.o>dhcp.c
	gcc dhcp.c -o ldhcp -static -lpthread -O
	