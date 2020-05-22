#include <net/udp.h>
#include <net/udplite.h>
#include <net/protocol.h>
#include <net/addrconf.h>
#include <net/inet_common.h>
#include <net/transp_v6.h>

extern struct proto udppp_prot;
extern const struct proto_ops inetpp_dgram_ops;
extern struct udp_table udp_table;

int udppp_init(void);
void udppp_exit(void);
int inetpp_add_protocol(const struct net_protocol *prot, unsigned char protocol);
int inetpp_del_protocol(const struct net_protocol *prot, unsigned char protocol);
int inetpp_register_protosw(struct inet_protosw *p);
void inetpp_unregister_protosw(struct inet_protosw *p);

int ippp_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)；

static inline u32 ipv4_portaddr_hash(const struct net *net,
				     __be32 saddr,
				     unsigned int port)
{
	return jhash_1word((__force u32)saddr, net_hash_mix(net)) ^ port;
}

struct ippp_addr {
        __u8    type;
		__u8	base:4,
                 len:4;
		__be32  addr[16];

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