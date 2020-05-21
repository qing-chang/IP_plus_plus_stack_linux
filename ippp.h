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

static inline u32 ipv4_portaddr_hash(const struct net *net,
				     __be32 saddr,
				     unsigned int port)
{
	return jhash_1word((__force u32)saddr, net_hash_mix(net)) ^ port;
}
