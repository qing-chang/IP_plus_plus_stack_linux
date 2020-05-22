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

extern struct proto udppp_prot;
extern const struct proto_ops inetpp_dgram_ops;
extern struct udp_table udp_table;

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

int udppp_init(void);
void udppp_exit(void);
int inetpp_add_protocol(const struct net_protocol *prot, unsigned char protocol);
int inetpp_del_protocol(const struct net_protocol *prot, unsigned char protocol);
int inetpp_register_protosw(struct inet_protosw *p);
void inetpp_unregister_protosw(struct inet_protosw *p);
int ippp_route_input_noref(struct sk_buff *skb, __be32 daddr, __be32 saddr, u8 tos, struct net_device *dev);
int ippp_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

static inline u32 ipv4_portaddr_hash(const struct net *net,
				     __be32 saddr,
				     unsigned int port)
{
	return jhash_1word((__force u32)saddr, net_hash_mix(net)) ^ port;
}

static inline struct ippphdr *ippp_hdr(const struct sk_buff *skb)
{
	return (struct ippphdr *)skb_network_header(skb);
}