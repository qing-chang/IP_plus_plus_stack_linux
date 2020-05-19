/*
 *	UDP over IPv6
 *	Linux INET6 implementation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *
 *	Based on linux/ipv4/udp.c
 *
 *	Fixes:
 *	Hideaki YOSHIFUJI	:	sin6_scope_id support
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 *      Kazunori MIYAZAWA @USAGI:       change process style to use ip6_append_data
 *      YOSHIFUJI Hideaki @USAGI:	convert /proc/net/udp6 to seq_file.
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
//#include "udp_impl.h"
#include "ippp.h"
/**/
static struct net_protocol udppp_protocol = {
    //.early_demux =	udp_v4_early_demux,
    //.early_demux_handler =	udp_v4_early_demux,
    //.handler = udppp_rcv,
    //.err_handler = udppp_err,
    .no_policy = 1,
    .netns_ok = 1,
};

struct proto udppp_prot = {
	.name			= "UDPPP",
	.owner			= THIS_MODULE,
/*	.close			= udp_lib_close,
	.pre_connect	= udpv6_pre_connect,
	.connect		= ip6_datagram_connect,
	.disconnect		= udp_disconnect,
	.ioctl			= udp_ioctl,
	.init			= udp_init_sock,
	.destroy		= udpv6_destroy_sock,
	.setsockopt		= udpv6_setsockopt,
	.getsockopt		= udpv6_getsockopt,
	.sendmsg		= udpv6_sendmsg,
	.recvmsg		= udpv6_recvmsg,
	.release_cb		= ip6_datagram_release_cb,
	.hash			= udp_lib_hash,
	.unhash			= udp_lib_unhash,
	.rehash			= udp_v6_rehash,
	.get_port		= udp_v6_get_port,
	.memory_allocated	= &udp_memory_allocated,
	.sysctl_mem		= sysctl_udp_mem,*/
//	.sysctl_wmem_offset     = offsetof(struct net, ipv4.sysctl_udp_wmem_min),
//	.sysctl_rmem_offset     = offsetof(struct net, ipv4.sysctl_udp_rmem_min),
	.obj_size		= sizeof(struct udp6_sock),
//	.h.udp_table		= &udp_table,
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
	//.ops =       &inet6_dgram_ops,
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
