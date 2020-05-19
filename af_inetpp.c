/**/
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/icmpv6.h>
#include <linux/netfilter_ipv6.h>

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include <net/udplite.h>
#include <net/tcp.h>
#include <net/ping.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/route.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/ndisc.h>
#ifdef CONFIG_IPV6_TUNNEL
#include <net/ip6_tunnel.h>
#endif
#include <net/calipso.h>
#include <net/seg6.h>

#include <linux/uaccess.h>
#include <linux/mroute6.h>
#include "ippp.h"
/* Internet IP Protocol Plus Plus
由于linux内核源码中没有为新协议族预留协议号，所以原则上应该修改内核源码并重新编译，
这样很不方便。因此这里选择借用linux内核中并未真正实现的AF_IPX的协议族号*/
#define AF_INETPP 4
#define PF_INETPP AF_INETPP
#define ETH_P_IPPP 0x0810 /* Internet Protocol Plus Plus packet */


static struct list_head inetswpp[SOCK_MAX];
static DEFINE_SPINLOCK(inetswpp_lock);
/* 
const struct proto_ops inet6_stream_ops = {
	.family		   = PF_INET6,
	.owner		   = THIS_MODULE,
	.release	   = inet6_release,
	.bind		   = inet6_bind,
	.connect	   = inet_stream_connect,	
	.socketpair	   = sock_no_socketpair,	
	.accept		   = inet_accept,		
	.getname	   = inet6_getname,
	.poll		   = tcp_poll,			
	.ioctl		   = inet6_ioctl,		
	.gettstamp	   = sock_gettstamp,
	.listen		   = inet_listen,		
	.shutdown	   = inet_shutdown,		
	.setsockopt	   = sock_common_setsockopt,	
	.getsockopt	   = sock_common_getsockopt,	
	.sendmsg	   = inet6_sendmsg,		
	.recvmsg	   = inet6_recvmsg,		
#ifdef CONFIG_MMU
	.mmap		   = tcp_mmap,
#endif
	.sendpage	   = inet_sendpage,
	.sendmsg_locked    = tcp_sendmsg_locked,
	.sendpage_locked   = tcp_sendpage_locked,
	.splice_read	   = tcp_splice_read,
	.read_sock	   = tcp_read_sock,
	.peek_len	   = tcp_peek_len,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
	.set_rcvlowat	   = tcp_set_rcvlowat,
}; */

const struct proto_ops inetpp_dgram_ops = {
	.family = PF_INET6,
	.owner = THIS_MODULE,
/*	.release = inet6_release,
	.bind = inet6_bind,
	.connect = inet_dgram_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = inet6_getname,
	.poll = udp_poll,
	.ioctl = inet6_ioctl,
	.gettstamp = sock_gettstamp,
	.listen = sock_no_listen,
	.shutdown = inet_shutdown,
	.setsockopt = sock_common_setsockopt,
	.getsockopt = sock_common_getsockopt,
	.sendmsg = inet6_sendmsg,
	.recvmsg = inet6_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
	.set_peek_off = sk_set_peek_off,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif*/
};

int inetpp_register_protosw(struct inet_protosw *p)
{
	struct list_head *lh;
	struct inet_protosw *answer;
	struct list_head *last_perm;
	int protocol = p->protocol;
	int ret;

	spin_lock_bh(&inetswpp_lock);

	ret = -EINVAL;
	if (p->type >= SOCK_MAX)
		goto out_illegal;

	/* If we are trying to override a permanent protocol, bail. */
	answer = NULL;
	ret = -EPERM;
	last_perm = &inetswpp[p->type];
	list_for_each(lh, &inetswpp[p->type]) {
		answer = list_entry(lh, struct inet_protosw, list);

		/* Check only the non-wild match. */
		if (INET_PROTOSW_PERMANENT & answer->flags) {
			if (protocol == answer->protocol)
				break;
			last_perm = lh;
		}

		answer = NULL;
	}
	if (answer)
		goto out_permanent;

	/* Add the new entry after the last permanent entry if any, so that
	 * the new entry does not override a permanent entry when matched with
	 * a wild-card protocol. But it is allowed to override any existing
	 * non-permanent entry.  This means that when we remove this entry, the
	 * system automatically returns to the old behavior.
	 */
	list_add_rcu(&p->list, last_perm);
	ret = 0;
out:
	spin_unlock_bh(&inetswpp_lock);
	return ret;

out_permanent:
	pr_err("Attempt to override permanent protocol %d\n", protocol);
	goto out;

out_illegal:
	pr_err("Ignoring attempt to register invalid socket type %d\n",
	       p->type);
	goto out;
}
EXPORT_SYMBOL(inetpp_register_protosw);

void inetpp_unregister_protosw(struct inet_protosw *p)
{
	if (INET_PROTOSW_PERMANENT & p->flags) {
		pr_err("Attempt to unregister permanent protocol %d\n",
		       p->protocol);
	} else {
		spin_lock_bh(&inetswpp_lock);
		list_del_rcu(&p->list);
		spin_unlock_bh(&inetswpp_lock);

		synchronize_net();
	}
}
EXPORT_SYMBOL(inetpp_unregister_protosw);

static int inetpp_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
{
	struct sock *sk;
	struct inet_protosw *answer;
	struct inet_sock *inet;
	struct proto *answer_prot;
	unsigned char answer_flags;
	int try_loading_module = 0;
	int err;

	if (protocol < 0 || protocol >= IPPROTO_MAX)
		return -EINVAL;

	sock->state = SS_UNCONNECTED;

	/* Look for the requested type/protocol pair. */
lookup_protocol:
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();

out:
	return err;
out_rcu_unlock:
	rcu_read_unlock();
	goto out;
}

static const struct net_proto_family inetpp_family_ops = {
	.family = PF_INETPP,
	.create = inetpp_create,
	.owner = THIS_MODULE,
};

static struct packet_type ippp_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_IPPP),
//	.func = ippp_rcv,
};

static int __init inetpp_init(void)
{
	struct list_head *r;
	int err = 0;

	for (r = &inetswpp[0]; r < &inetswpp[SOCK_MAX]; ++r)
		INIT_LIST_HEAD(r);

	err = proto_register(&udppp_prot, 1);
	if (err)
		goto out;

	err = sock_register(&inetpp_family_ops);

	err = udppp_init();
	if (err)
		goto udppp_fail;

	dev_add_pack(&ippp_packet_type);
out:
	return err;
udppp_fail:
	return err;
}

static void __exit inetpp_exit(void)
{
	dev_remove_pack(&ippp_packet_type);
	udppp_exit();
	sock_unregister(PF_INETPP);
	proto_unregister(&udppp_prot);
	printk(KERN_INFO "ippp exit\n");
}

module_init(inetpp_init);
module_exit(inetpp_exit);

MODULE_AUTHOR("Qing Chang");
MODULE_DESCRIPTION("IP plus plus protocol stack for Linux");
MODULE_LICENSE("GPL");