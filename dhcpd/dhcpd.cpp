#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
using namespace std;
char usruid[16]="";
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
			uid=atoi(uidchar);
			break;
		}
		memset(usrline,0,64);
		memcpy(usrline,token,128);
		usrline[127]=0;
		token = strchr(token+1,'\n');

        }
	fclose(pwdf);
    //printf("Info: change uid %d with %s \n",uid,usrName);
	if (uid>0){return uid;} else {return 65534;}
}

void setUidGid(){
	if (getuid() == 0){
	if (usruid[0] != 0){
	setgid((uid_t)65534);setuid(get_uid(usruid));
}}}

int bash(const char *cmdstring)
{
    pid_t pid;
    int status=0;
if(cmdstring == NULL)
{
    return (1);
}


if((pid = fork())<0)
{
    status = -1;
}
else if(pid == 0)
{
	setUidGid();
	if (getuid() !=0){
    execl("/bin/sh", "sh", "-c", cmdstring, (char *)0);
	} else {printf("Error: uid can't change\n");}
    _exit(127);
}
else
{
    while(waitpid(pid, &status, 0) < 0)
    {
        if(errno != EINTR)
        {
            status = -1;
            break;
        }
    }
}

    return status;
}
string get_subnet(string ipstr,string substr){
	//255.255.255.0
	//  1   2  3   4
	int len1=0;
	string tmp1="";
	int interesting=0;
	len1=substr.length();
	int startd=0,endd=0;
	if (len1 >= 15) {return ipstr;} else {
		if (len1 >=13) {interesting=3;} else {
			if (len1 >=11) {interesting=2;} else {
				if (len1 >=9) {interesting=1;} else {
					if (len1 >=7) {interesting=0;} 
				}
			}
		}
	}
	int c=4;
	ipstr=ipstr+".0.0";
	while (interesting){
		endd=ipstr.find('.',startd);
		if (endd > 0 ){
			tmp1=ipstr.substr(0,endd);
			startd=endd+1;
			interesting--;
			c--;
		} else {break;} 
	}
	while(c){
		if (tmp1 == ""){tmp1="0.0.0.0";break;}
		tmp1=tmp1+".0";
		c--;
	}
return tmp1;
	
}

int main(int argc, char *argv[]) 
{
	if (getuid() == 0){
	cout<<"use ./dhcpd ens32 -u nobody -d \nruning with pid "<<getpid()<<endl;
	string buffer="";
	string eth0="";
	if (argc > 4){
	buffer=argv[4];
	eth0=argv[1];
		
	if (*argv[2] == '-' && *(argv[2] + 1) == 'u'){
	if (strlen(argv[3]) < 16){strcpy(usruid,argv[3]);} else {memcpy(usruid,"nobody",7);}
	}
	
	}
	if (buffer == "-d"){
	struct sockaddr_in serveraddr;
	unsigned int ipaddr;
	unsigned int gateway;
	unsigned int subnet;
	string ipstr,gatewaystr,substr;
	sleep(1);
	while(1){
		//printf("starting ...\n");
		buffer="";
		bash("/bin/sh /usr/lib/ldhcp/rootless.sh");
		sleep(10);
	ifstream infile("/usr/lib/ldhcp/indhcp.log", ios::in);
	infile>>ipaddr>>gateway>>subnet>>buffer;
	infile.close();
	
	memcpy(&(serveraddr.sin_addr),&ipaddr,4);
	ipstr = inet_ntoa(serveraddr.sin_addr);
	
	memcpy(&(serveraddr.sin_addr),&gateway,4);
	gatewaystr = inet_ntoa(serveraddr.sin_addr);
	
	memcpy(&(serveraddr.sin_addr),&subnet,4);
	substr = inet_ntoa(serveraddr.sin_addr);
	
	buffer="";
	
	buffer="busybox ifconfig " + eth0 + " " + ipstr + " netmask " + substr + " && busybox route add -net " + get_subnet(ipstr,substr) + " netmask " + substr + " gw "+ ipstr +" metric 1" + " && busybox route add default gw " + gatewaystr + " metric 100 ";
	ofstream offile("/usr/lib/ldhcpd/outdhcp.log", ios::out);
	offile<<buffer;
	offile.close();
	buffer="";
	
	system("sh /usr/lib/ldhcpd/rootsh.sh");
	//printf("sleeping 600s...\n");
	sleep(600);
	}
	}
	} else {
		if (argc >0){
		unsigned int ipaddr=0;
		struct sockaddr_in serveraddr;
		inet_aton(argv[1], &(serveraddr.sin_addr));
		memcpy(&ipaddr,&(serveraddr.sin_addr),4);
		cout << ipaddr;
		}
	}
	return 0;
	}
