#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/shm.h>
#include "ippp.h"
int main()
{
     struct sockaddr_ippp local_sockaddr,remote_sockaddr;
     int fd = socket(PF_INETPP,SOCK_DGRAM, 0);
     memset(&local_sockaddr,0,sizeof(struct sockaddr_ippp));
     local_sockaddr.sin_family = PF_INETPP;
     local_sockaddr.sin_port = htons(8888);
     local_sockaddr.sin_addr.base = 0;
     local_sockaddr.sin_addr.len = 1;
     local_sockaddr.sin_addr.type = 1;
     local_sockaddr.sin_addr.addr[0] = inet_addr("1.1.1.2");
     local_sockaddr.sin_addr.addr[1] = inet_addr("192.168.1.14");
     bind(fd,(struct sockaddr*)&local_sockaddr,sizeof(local_sockaddr));
     char buff[256];
     int remoteAddrLen;
       do{
          recvfrom(fd, buff,40,0,(struct sockaddr*)&remote_sockaddr,&remoteAddrLen);
          printfHex(buff,40);      //printf("received:%02X\n",buff);
     }while(getchar()=='c');
     close(fd);
     return 0;
}