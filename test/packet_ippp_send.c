#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_ICMP, INET_ADDRSTRLEN/*in_addr结构*/
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)/*iphdr 结构*/
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined/*ioctl 命令*/
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq/*ifreq 结构*/
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD/*ethhdr 结构*/
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <netinet/udp.h>					/*udphdr 结构*/
#include <netinet/tcp.h>					/*tcphdr 结构*/
#include <errno.h>            // errno, perror()

#define DATALEN    12

struct ippphdr{
    __u8   ihl:4,
       version:4;
    __u8   tos;
    __be16 tot_len;
    __u8   ttl;
    __u8   protocol;
    __u8   exthdr_num;
    __u8  flow_label[2];
    __u8    src_type:1,
            dst_type:1,
                   x:6;
    __u8     dst_len:4,
            dst_base:4;
    __u8     src_len:4,
            src_base:4;
    __u32 addr[];
};

int main (int argc, char **argv)
{
    int i, frame_length, sd,fd, bytes;
    char *interface="enp0s3";
    uint8_t src_mac[6];
    uint8_t ether_frame[IP_MAXPACKET];
    struct sockaddr_ll device;
    struct ifreq ifr;

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {//第一次创建socket是为了获取本地网卡信息
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("ioctl() failed to get source MAC address ");
        return (EXIT_FAILURE);
    }
    close (sd);

    // Copy source MAC address.
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);

    // Report source MAC address to stdout.
    printf ("MAC address for interface %s is ", interface);
    for (i=0; i<5; i++) {
        printf ("%02x:", src_mac[i]);
    }
    printf ("%02x\n", src_mac[5]);

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit (EXIT_FAILURE);
    }
    printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

    // Set destination MAC address: you need to fill these out

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6);
    device.sll_halen = htons (6);

    // 发送的data，长度能够随意，可是抓包时看到最小数据长度为46，这是以太网协议规定以太网帧数据域部分最小为46字节，不足的自己主动补零处理
 	//以太网头部
 	struct ethhdr*p_ethhdr;
	p_ethhdr = (struct ethhdr*)ether_frame;
    uint8_t dst_mac[6]={0x08,0x00,0x27,0x51,0xf3,0x03};//设置目的网卡地址;{0xd4,0xbe,0xd9,0xd8,0x32,0x80}{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}{0x00,0x0c,0x29,0xff,0x09,0x9d}{0xe4,0x3a,0x6e,0x07,0xc0,0x62}
	memcpy(p_ethhdr->h_dest,dst_mac,ETH_ALEN);
	memcpy(p_ethhdr->h_source,src_mac,ETH_ALEN);
	p_ethhdr->h_proto=htons(0x0810);

    //IP++头部
	struct ippphdr*p_ippphdr;	
	p_ippphdr = (struct ippphdr*)(ether_frame + ETH_HLEN);
	p_ippphdr->version=0;
	p_ippphdr->ihl=1;
	p_ippphdr->tos=0;
	p_ippphdr->tot_len=htons(12+(8<<p_ippphdr->ihl)+8+DATALEN);
	p_ippphdr->ttl=64;
	p_ippphdr->protocol=17;
	p_ippphdr->exthdr_num=0;
	//p_ippphdr->flow_label=0;
	p_ippphdr->dst_type=0;
	p_ippphdr->dst_base=0;
	p_ippphdr->dst_len=1;
	p_ippphdr->src_type=0;
	p_ippphdr->src_base=0;
	p_ippphdr->src_len=1;
	p_ippphdr->addr[0]=inet_addr("1.1.1.2");
	p_ippphdr->addr[1]=inet_addr("192.168.1.14");
	p_ippphdr->addr[2]=inet_addr("1.1.1.1");
	p_ippphdr->addr[3]=inet_addr("192.168.1.12");
    //UDP头部
	struct udphdr*p_udphdr;	
	p_udphdr = (struct udphdr*)(ether_frame+ETH_HLEN+12+(1<<p_ippphdr->ihl)*8);
	p_udphdr->dest=htons(8888);
	p_udphdr->source=htons(2000);
    p_udphdr->len=htons(20);
	p_udphdr->check=htons(50);
	
    uint8_t data[DATALEN];
    data[0] = 'h';
    data[1] = 'e';
    data[2] = 'l';
    data[3] = 'l';
    data[4] = 'o';
    data[5] = ' ';
    data[6] = 'w';
    data[7] = 'o';
    data[8] = 'r';
    data[9] = 'l';
    data[10] = 'd';
    data[11] = '!';
    memcpy (ether_frame + 14 + 12+(8<<p_ippphdr->ihl) + 8 , data, DATALEN);

    frame_length = ETH_HLEN + 12+(8<<p_ippphdr->ihl) + 8 + DATALEN;
    // Submit request for a raw socket descriptor.
    if ((fd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {//创建正真发送的socket
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }
    // Send ethernet frame to socket.
    if ((bytes = sendto (fd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
    }
    printf ("send num=%d,read num=%d\n",frame_length,bytes);     
    // Close socket descriptor.
    close (sd);

    return (EXIT_SUCCESS);
}
