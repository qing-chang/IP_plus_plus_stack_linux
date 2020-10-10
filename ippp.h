
#ifndef _IPPP_H
#define _IPPP_H

#include <net/udp.h>
#include <net/udplite.h>
#include <net/protocol.h>
#include <net/addrconf.h>
#include <net/inet_common.h>
#include <net/transp_v6.h>

#include <linux/ipv6.h>
#include <linux/hardirq.h>
#include <linux/jhash.h>
#include <linux/refcount.h>
#include <linux/jump_label_ratelimit.h>
#include <net/if_inet6.h>
#include <net/ndisc.h>
#include <net/flow.h>
#include <net/flow_dissector.h>
#include <net/snmp.h>
#include <net/netns/hash.h>

/*由于linux内核源码中没有为新协议族预留协议号，所以原则上需修改内核源码并重新编译，
这样很不方便。因此这里选择借用linux内核中并未真正实现的AF_IPX的协议族号*/
#define AF_INETPP 4
#define PF_INETPP AF_INETPP
#define ETH_P_IPPP 0x0810 /* Internet Protocol Plus Plus packet */
#define NFPROTO_IPPP 11

extern struct proto tcppp_prot,udppp_prot;
extern const struct proto_ops inetpp_stream_ops,inetpp_dgram_ops;
extern struct udp_table udp_table;
extern struct net_protocol __rcu *inetpp_protos[MAX_INET_PROTOS];

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
	__u8   ext_hdr_num;
	__u8  flow_label[2];
//#if defined(__LITTLE_ENDIAN_BITFIELD)
	unsigned char x:6,
		   src_type:1,
		   dst_type:1;
	__u8	dst_len:4,
		   dst_base:4;
	__u8 	src_len:4,
		   src_base:4;
//#else
//unsigned char x:6,     
	//	dst_type:1,
//		  src_type:1;
//__u8	 dst_base:4,
//		  dst_len:4;
//__u8  src_base:4,
//	   src_len:4;
//#endif
	__u32 addr[0];
};

struct ext_hdr_addr{
	__u16 addr[0];
};

// //乘方函数
// static inline int power(int x,int n)
// {
// 	int i;
// 	int s=1;
// 	for(i=1; i<=n; i++)    //利用循环进行计算，n次方就是把x乘上n遍
// 	   s*=x;
//    return s;
// }

struct sockaddr_ippp {
  __kernel_sa_family_t	sin_family;
  __be16		sin_port;	/* Port number			*/
  struct ippp_addr	sin_addr;	/* Internet address		*/
};

struct ippp_pinfo {
    struct ippp_addr saddr,
                     daddr;
};

struct udppp_sock {
	struct udp_sock	  udp;
	
	struct ippp_pinfo inetpp;
};

struct tcppp_sock {
	struct tcp_sock	  tcp;
	
	struct ippp_pinfo inetpp;
};

int tcppp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
int tcppp_rcv(struct sk_buff *skb);
int tcppp_init(void);
void tcppp_exit(void);

struct sk_buff *ip_make_skb(struct sock *sk, struct flowi4 *fl4,
			    int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen, struct ipcm_cookie *ipc, struct rtable **rtp,
			    struct inet_cork *cork, unsigned int flags);
int udppp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
struct sk_buff *__skb_recv_udppp(struct sock *sk, unsigned int flags, int noblock, int *off, int *err);
int udppp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,int flags, int *addr_len);
int udppp_rcv(struct sk_buff *skb);
int udppp_init(void);
void udppp_exit(void);
int inetpp_add_protocol(const struct net_protocol *prot, unsigned char protocol);
int inetpp_del_protocol(const struct net_protocol *prot, unsigned char protocol);
int inetpp_register_protosw(struct inet_protosw *p);
void inetpp_unregister_protosw(struct inet_protosw *p);
int ippp_route_input_noref(struct sk_buff *skb, struct net_device *dev);
int ippp_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

static inline u32 ipv4_portaddr_hash(const struct net *net, __be32 saddr, unsigned int port);

static inline int realLen(struct sockaddr *uaddr)
{
	struct sockaddr_ippp *addr = (struct sockaddr_ippp *)uaddr; 	
	return (addr->sin_addr.len+1)*4+2;
}

static inline __be32 leafAddr(struct sockaddr_ippp *addr)
{
	return addr->sin_addr.addr[addr->sin_addr.len];
}

static inline struct ippphdr *ippp_hdr(const struct sk_buff *skb)
{
	return (struct ippphdr *)skb_network_header(skb);
}

static inline struct ext_hdr_addr *ext_hdr_addr(const struct ippphdr *ippph)
{
	if(ippph->ext_hdr_num!=0)
		return (struct ext_hdr_addr *)ippph->addr[2<<ippph->ihl];
	else
		return NULL;
}

static inline u32 hdr_len(const struct ippphdr *ippph)
{
	if(ippph->ext_hdr_num==0)
		return 12 + (8<<ippph->ihl);
	else
	{
		struct ext_hdr_addr *exhrad = ext_hdr_addr(ippph);
		return ntohs(exhrad->addr[ippph->ext_hdr_num-2]);
	}
}

static inline struct udppp_sock *udppp_sk(const struct sock *sk)
{
	return (struct udppp_sock *)sk;
}

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

static inline void u32tostr(__u32 dat,char *str)
{
	char temp[20];
	unsigned char i=0,j=0;
	while(dat)
	{
		temp[j]=dat%10+0x30;
		j++;
		dat/=10;
	}
	for(i=0;i<j;i++)
	{
		str[i]=temp[j-i-1];
	}
	if(i==0)str[i++]='0';
	str[i]=0;
}

static inline void IP4tostr(__u32 ip,char *str)
{
	char temp[5];
	__u8 t,i,j,k,l=0;
	for(i=0;i<4;i++)
	{
		t=ip%256;
		ip/=256;
		j=0;
		while(t)
		{
			temp[j]=t%10+0x30;
			j++;
			t/=10;
		}
		for(k=0;k<j;k++)
		{
			str[l+k]=temp[j-k-1];
		}
		if(k==0)str[l+k++]='0';
		if(i!=3)str[l+k++]='.';
		l+=k;
	}
	str[l]=0;
}

#endif	/* _IPPP_H */