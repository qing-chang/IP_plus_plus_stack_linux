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
     char rcvBuff[256],sndBuff[256];
     sndBuff[0] = 'H';
     sndBuff[1] = 'E';
     sndBuff[2] = 'L';
     sndBuff[3] = 'L';
     sndBuff[4] = 'O';
     sndBuff[5] = '_';
     sndBuff[6] = 'W';
     sndBuff[7] = 'O';
     sndBuff[8] = 'R';
     sndBuff[9] = 'L';
     sndBuff[10] = 'D';
     sndBuff[11] = '.';
     int remoteAddrLen;
       do{
          recvfrom(fd, rcvBuff, 40, 0, (struct sockaddr*)&remote_sockaddr, &remoteAddrLen);
          printfHex(rcvBuff, 40);
          printf("received:%s\n",rcvBuff);
          sendto(fd, sndBuff, 40, 0, (struct sockaddr*)&remote_sockaddr, remoteAddrLen);
     }while(getchar()=='c');
     close(fd);
     return 0;
}