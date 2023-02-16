
void *Threadwork(void *arg){
	if (getuid()==0){printf("Thread: can't run as uid 0, exit thread\n");return;} else {printf("Thread: run as uid %d\n",getuid());}
	sleep(4);
struct sockaddr_in serveraddr;
struct sockaddr_in clientaddr;
socklen_t clilen;
int listenfd,cfd;
listenfd = socket(AF_INET, SOCK_STREAM, 0);
memset(&serveraddr,0,sizeof(serveraddr));
serveraddr.sin_family = AF_INET;
inet_aton("127.0.0.1", &(serveraddr.sin_addr));
serveraddr.sin_port = htons(1026);
if (bind(listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {printf("Thread: Error on bind\n");return;}
if (listen(listenfd,5) < 0) {printf("Thread: Error on listen\n");return;}
char httpbuf[1024]="";
unsigned int readlen=0;
while(1){
	 cfd=accept(listenfd, (struct sockaddr *)&clientaddr, &clilen);
	 if(cfd < 0) {
					printf("Thread: Accept new client faliure\n");
					continue;
				}
				memset(httpbuf,0,1020);
				readlen=read(cfd,httpbuf,1020);
				if (readlen<=0){
					printf("Thread: read client faliure\n");
					close(cfd);
					continue;
				}
				if (readlen < 10){memset(httpbuf,0,16);}
				
				if ((httpbuf[0]=='k') && (httpbuf[1]=='e') && (httpbuf[2]==' ') && (httpbuf[3]=='d') && (httpbuf[4]=='h') && (httpbuf[5]=='c') && (httpbuf[6]=='p')){
					char http200[256]="HTTP/1.1 200 OK\r\nversion:DHCP v1.1\nserver:";
					strcat(http200,DHCPINFO.dhcp);
					strcat(http200,"\ngateway:");
					strcat(http200,DHCPINFO.gateway);
					strcat(http200,"\nsubnet:");
					strcat(http200,DHCPINFO.subnet);
					strcat(http200,"\nipaddress:");
					strcat(http200,DHCPINFO.myip);
					strcat(http200,"\nstatus:End\n\r\n\r\n\r\n");
					write(cfd,http200,sizeof(http200));
				} else {
					char http200[]="HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n\r\n";
					write(cfd,http200,sizeof(http200));
				}	
				
				close(cfd);
				sleep(1);
}
close(listenfd);
}