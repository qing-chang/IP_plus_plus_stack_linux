
#ifndef _IPPP_H
#define _IPPP_H

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

/*由于linux内核源码中没有为新协议族预留协议号，所以原则上需修改内核源码并重新编译，
这样很不方便。因此这里选择借用linux内核中并未真正实现的AF_IPX的协议族号*/
#define AF_INETPP 4
#define PF_INETPP AF_INETPP
#define ETH_P_IPPP 0x0810 /* Internet Protocol Plus Plus packet */

struct ippp_addr {
	__u8    type;
	__u8	base:4,
			 len:4;
	__be32  addr[16];
};

struct ippphdr{
//#if defined(__LITTLE_ENDIAN_BITFIELD)
  __u8   ihl:4,
     version:4;
//#else
//__u8 version:4,
//		 ihl:4;
//#endif
	__u8   tos;
	__be16 tot_len;
	__u8   ttl;
	__u8   protocol;
	__u8   exthdr_num;
	__u8  flow_label[2];
//#if defined(__LITTLE_ENDIAN_BITFIELD)
			 unsigned char x:6,
       source_type:1,
					 dst_type:1;
__u8	 dst_len:4,
		  dst_base:4;
__u8     source_len:4,
		  source_base:4;
//#else
//unsigned char x:6,     
	//	dst_type:1,
//		  source_type:1;
//__u8	 dst_base:4,
//		  dst_len:4;
//__u8  source_base:4,
//	   source_len:4;
//#endif
	__u32 addr[0];
};

struct sockaddr_ippp {
  unsigned short	sin_family;
  __be16		sin_port;	/* Port number			*/
  struct ippp_addr	sin_addr;	/* Internet address		*/
};

// struct ippp_pinfo {
//     struct ippp_addr saddr,
//                      daddr;
// };

// struct udppp_sock {
// 	struct udp_sock	  udp;
	
// 	struct ippp_pinfo inetpp;
// };

// int udppp_init(void);
// void udppp_exit(void);
// int inetpp_add_protocol(const struct net_protocol *prot, unsigned char protocol);
// int inetpp_del_protocol(const struct net_protocol *prot, unsigned char protocol);
// int inetpp_register_protosw(struct inet_protosw *p);
// void inetpp_unregister_protosw(struct inet_protosw *p);
// int ippp_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

// static inline u32 ipv4_portaddr_hash(const struct net *net,
// 				     __be32 saddr,
// 				     unsigned int port);
// // {
// // 	return jhash_1word((__force u32)saddr, net_hash_mix(net)) ^ port;
// // }

// static inline int realLen(struct sockaddr *uaddr)
// {
// 	struct sockaddr_ippp *addr = (struct sockaddr_ippp *)uaddr; 	
// 	return (addr->sin_addr.len+1)*4+2;
// }

// static inline __be32 leafAddr(struct sockaddr_ippp *addr)
// {
// 	return addr->sin_addr.addr[addr->sin_addr.len];
// }

// static inline struct ippphdr *ippp_hdr(const struct sk_buff *skb)
// {
// 	return (struct ippphdr *)skb_network_header(skb);
// }

// static inline struct udppp_sock *udppp_sk(const struct sock *sk)
// {
// 	return (struct udppp_sock *)sk;
// }

// __u32 addr_pp_to_v4(struct ippp_addr addr_pp)
// {
// 	return addr_pp.addr[addr_pp.len];
// }

// struct ippp_addr addr_v4_to_pp(__u32 addr_v4, __u8 absolute, int dst_or_src)
// {
// 	struct ippp_addr addr_pp;
// 	addr_pp.type=absolute;
// 	return addr_pp;
// }
/*十六进制形式打印字符串*/
void printfHex(const unsigned char *buf, const int num)
{
    int i;
    for(i = 0; i < num; i++)
    {
        printf("%02X ", buf[i]);
        if ((i+1)%16 == 0)
            printf("\n");
    }
    printf("\n");
    return;
}
#endif	/* _IPPP_H */