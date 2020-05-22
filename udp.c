/*
 *	UDP over IPPP
 *	Linux INETPP implementation
 *
 *	Authors:
 *	Pedro Roque		<cq@ippp.net.cn>
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <net/addrconf.h>
#include <net/ndisc.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/raw.h>
#include <net/tcp_states.h>
#include <net/ip6_checksum.h>
#include <net/ip6_tunnel.h>
#include <net/xfrm.h>
#include <net/inet_hashtables.h>
#include <net/inet6_hashtables.h>
#include <net/busy_poll.h>
#include <net/sock_reuseport.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <trace/events/skb.h>
#include "ippp.h"

static struct net_protocol udppp_protocol = {
    //.early_demux =	udp_v4_early_demux,
    //.early_demux_handler =	udp_v4_early_demux,
    //.handler = udppp_rcv,
    //.err_handler = udppp_err,
    .no_policy = 1,
    .netns_ok = 1,
};
int udppp_get_port(struct sock *sk, unsigned short snum)
{
	unsigned int hash2_nulladdr =
		ipv4_portaddr_hash(sock_net(sk), htonl(INADDR_ANY), snum);
	unsigned int hash2_partial =
		ipv4_portaddr_hash(sock_net(sk), inet_sk(sk)->inet_rcv_saddr, 0);

	/* precompute partial secondary hash */
	udp_sk(sk)->udp_portaddr_hash = hash2_partial;
	return udp_lib_get_port(sk, snum, hash2_nulladdr);
}
struct proto udppp_prot = {
	.name			= "UDPPP",
	.owner			= THIS_MODULE,
//	.close			= udp_lib_close,
//	.pre_connect	= udpv6_pre_connect,
//	.connect		= ip6_datagram_connect,
//	.disconnect		= udp_disconnect,
//	.ioctl			= udp_ioctl,
//	.init			= udp_init_sock,
//	.destroy		= udpv6_destroy_sock,
//	.setsockopt		= udpv6_setsockopt,
//	.getsockopt		= udpv6_getsockopt,
//	.sendmsg		= udpv6_sendmsg,
//	.recvmsg		= udpv6_recvmsg,
//	.release_cb		= ip6_datagram_release_cb,
//	.hash			= udp_lib_hash,
//	.unhash			= udp_lib_unhash,
//	.rehash			= udp_v6_rehash,
	.get_port		= udppp_get_port,
//	.memory_allocated	= &udp_memory_allocated,
//	.sysctl_mem		= sysctl_udp_mem,
//	.sysctl_wmem_offset     = offsetof(struct net, ipv4.sysctl_udp_wmem_min),
//	.sysctl_rmem_offset     = offsetof(struct net, ipv4.sysctl_udp_rmem_min),
	.obj_size		= sizeof(struct udppp_sock),
	.h.udp_table		= &udp_table,
#ifdef CONFIG_COMPAT
	//.compat_setsockopt	= compat_udpv6_setsockopt,
	//.compat_getsockopt	= compat_udpv6_getsockopt,
#endif
	//.diag_destroy		= udp_abort,
};

static struct inet_protosw udppp_protosw = {
	.type =      SOCK_DGRAM,
	.protocol =  IPPROTO_UDP,
	.prot =      &udppp_prot,
	.ops =       &inetpp_dgram_ops,
	.flags =     INET_PROTOSW_REUSE,
};

int __init udppp_init(void)
{
	int ret;

	ret = inetpp_add_protocol(&udppp_protocol, IPPROTO_UDP);
	if (ret)
		goto out;

	ret = inetpp_register_protosw(&udppp_protosw);
	if (ret)
		goto out_udppp_protocol;
out:
	return ret;

out_udppp_protocol:
	inetpp_del_protocol(&udppp_protocol, IPPROTO_UDP);
	goto out;
}

void udppp_exit(void)
{
	inetpp_unregister_protosw(&udppp_protosw);
	inetpp_del_protocol(&udppp_protocol, IPPROTO_UDP);
}
