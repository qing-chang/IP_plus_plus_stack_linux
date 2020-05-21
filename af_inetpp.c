/* Internet IP Protocol Plus Plus */
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
/*由于linux内核源码中没有为新协议族预留协议号，所以原则上需修改内核源码并重新编译，
这样很不方便。因此这里选择借用linux内核中并未真正实现的AF_IPX的协议族号*/
#define AF_INETPP 4
#define PF_INETPP AF_INETPP
#define ETH_P_IPPP 0x0810 /* Internet Protocol Plus Plus packet */


static struct list_head inetswpp[SOCK_MAX];
static DEFINE_SPINLOCK(inetswpp_lock);

int __inetpp_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len,
		bool force_bind_address_no_port, bool with_lock)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	unsigned short snum;
	int chk_addr_ret;
	u32 tb_id = RT_TABLE_LOCAL;
	int err;

	if (addr->sin_family != AF_INET) {
		/* Compatibility games : accept AF_UNSPEC (mapped to AF_INET)
		 * only if s_addr is INADDR_ANY.
		 */
		err = -EAFNOSUPPORT;
		if (addr->sin_family != AF_UNSPEC ||
		    addr->sin_addr.s_addr != htonl(INADDR_ANY))
			goto out;
	}

	tb_id = l3mdev_fib_table_by_index(net, sk->sk_bound_dev_if) ? : tb_id;
	chk_addr_ret = inet_addr_type_table(net, addr->sin_addr.s_addr, tb_id);

	/* Not specified by any standard per-se, however it breaks too
	 * many applications when removed.  It is unfortunate since
	 * allowing applications to make a non-local bind solves
	 * several problems with systems using dynamic addressing.
	 * (ie. your servers still start up even if your ISDN link
	 *  is temporarily down)
	 */
	err = -EADDRNOTAVAIL;
	if (//!inet_can_nonlocal_bind(net, inet) &&
	    addr->sin_addr.s_addr != htonl(INADDR_ANY) &&
	    chk_addr_ret != RTN_LOCAL &&
	    chk_addr_ret != RTN_MULTICAST &&
	    chk_addr_ret != RTN_BROADCAST)
		goto out;

	snum = ntohs(addr->sin_port);
	err = -EACCES;
	if (snum && //inet_port_requires_bind_service(net, snum) &&
	    !ns_capable(net->user_ns, CAP_NET_BIND_SERVICE))
		goto out;

	/*      We keep a pair of addresses. rcv_saddr is the one
	 *      used by hash lookups, and saddr is used for transmit.
	 *
	 *      In the BSD API these are the same except where it
	 *      would be illegal to use them (multicast/broadcast) in
	 *      which case the sending device address is used.
	 */
	if (with_lock)
		lock_sock(sk);

	/* Check these errors (active socket, double bind). */
	err = -EINVAL;
	if (sk->sk_state != TCP_CLOSE || inet->inet_num)
		goto out_release_sock;

	inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;
	if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
		inet->inet_saddr = 0;  /* Use device */

	/* Make sure we are allowed to bind here. */
	if (snum || !(inet->bind_address_no_port ||
		      force_bind_address_no_port)) {
		if (sk->sk_prot->get_port(sk, snum)) {
			inet->inet_saddr = inet->inet_rcv_saddr = 0;
			err = -EADDRINUSE;
			goto out_release_sock;
		}
	//	err = BPF_CGROUP_RUN_PROG_INET4_POST_BIND(sk);
		if (err) {
			inet->inet_saddr = inet->inet_rcv_saddr = 0;
			goto out_release_sock;
		}
	}

	if (inet->inet_rcv_saddr)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
	if (snum)
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	inet->inet_sport = htons(inet->inet_num);
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sk_dst_reset(sk);
	err = 0;
out_release_sock:
	if (with_lock)
		release_sock(sk);
out:
	return err;
}

int inetpp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sock *sk = sock->sk;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	if (sk->sk_prot->bind) {
		return sk->sk_prot->bind(sk, uaddr, addr_len);
	}
	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	/* BPF prog is run before any checks are done so that if the prog
	 * changes context in a wrong way it will be caught.
	 */
	//err = BPF_CGROUP_RUN_PROG_INET4_BIND(sk, uaddr);
	if (err)
		return err;

	return __inetpp_bind(sk, uaddr, addr_len, false, true);
}
EXPORT_SYMBOL(inetpp_bind);

 
const struct proto_ops inetpp_stream_ops = {
	.family		   = PF_INETPP,
	.owner		   = THIS_MODULE,
//	.release	   = inet6_release,
//	.bind		   = inet6_bind,
//	.connect	   = inet_stream_connect,	
//	.socketpair	   = sock_no_socketpair,	
//	.accept		   = inet_accept,		
//	.getname	   = inet6_getname,
//	.poll		   = tcp_poll,			
//	.ioctl		   = inet6_ioctl,		
//	.gettstamp	   = sock_gettstamp,
//	.listen		   = inet_listen,		
//	.shutdown	   = inet_shutdown,		
//	.setsockopt	   = sock_common_setsockopt,	
//	.getsockopt	   = sock_common_getsockopt,	
//	.sendmsg	   = inet6_sendmsg,		
//	.recvmsg	   = inet6_recvmsg,		
#ifdef CONFIG_MMU
//	.mmap		   = tcp_mmap,
#endif
//	.sendpage	   = inet_sendpage,
//	.sendmsg_locked    = tcp_sendmsg_locked,
//	.sendpage_locked   = tcp_sendpage_locked,
//	.splice_read	   = tcp_splice_read,
//	.read_sock	   = tcp_read_sock,
//	.peek_len	   = tcp_peek_len,
#ifdef CONFIG_COMPAT
//	.compat_setsockopt = compat_sock_common_setsockopt,
//	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
//	.set_rcvlowat	   = tcp_set_rcvlowat,
}; 

const struct proto_ops inetpp_dgram_ops = {
	.family = PF_INET6,
	.owner = THIS_MODULE,
//	.release = inet6_release,
	.bind = inetpp_bind,
/*	.connect = inet_dgram_connect,
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
	list_for_each_entry_rcu(answer, &inetswpp[sock->type], list) {

		err = 0;
		/* Check the non-wild match. */
		if (protocol == answer->protocol) {
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		err = -EPROTONOSUPPORT;
	}

	if (unlikely(err)) {
		if (try_loading_module < 2) {
			rcu_read_unlock();
			/*
			 * Be more specific, e.g. net-pf-2-proto-132-type-1
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP-type-SOCK_STREAM)
			 */
			if (++try_loading_module == 1)
				request_module("net-pf-%d-proto-%d-type-%d",
					       PF_INETPP, protocol, sock->type);
			/*
			 * Fall back to generic, e.g. net-pf-2-proto-132
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP)
			 */
			else
				request_module("net-pf-%d-proto-%d",
					       PF_INETPP, protocol);
			goto lookup_protocol;
		} else
			goto out_rcu_unlock;
	}



	err = -EPERM;
	if (sock->type == SOCK_RAW && !kern &&
	    !ns_capable(net->user_ns, CAP_NET_RAW))
		goto out_rcu_unlock;

	sock->ops = answer->ops;
	answer_prot = answer->prot;
	answer_flags = answer->flags;
	rcu_read_unlock();

	WARN_ON(!answer_prot->slab);

	err = -ENOBUFS;
	sk = sk_alloc(net, PF_INETPP, GFP_KERNEL, answer_prot, kern);
	if (!sk)
		goto out;

	err = 0;
	if (INET_PROTOSW_REUSE & answer_flags)
		sk->sk_reuse = SK_CAN_REUSE;

	inet = inet_sk(sk);
	inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;

	inet->nodefrag = 0;

	if (SOCK_RAW == sock->type) {
		inet->inet_num = protocol;
		if (IPPROTO_RAW == protocol)
			inet->hdrincl = 1;
	}

	if (net->ipv4.sysctl_ip_no_pmtu_disc)
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	inet->inet_id = 0;

	sock_init_data(sock, sk);

	sk->sk_destruct	   = inet_sock_destruct;
	sk->sk_protocol	   = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	inet->uc_ttl	= -1;
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_all	= 1;
	inet->mc_index	= 0;
	inet->mc_list	= NULL;
	inet->rcv_tos	= 0;

	sk_refcnt_debug_inc(sk);

	if (inet->inet_num) {
		/* It assumes that any protocol which allows
		 * the user to assign a number at socket
		 * creation time automatically
		 * shares.
		 */
		inet->inet_sport = htons(inet->inet_num);
		/* Add to protocol hash chains. */
		err = sk->sk_prot->hash(sk);
		if (err) {
			sk_common_release(sk);
			goto out;
		}
	}

	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err) {
			sk_common_release(sk);
			goto out;
		}
	}

	if (!kern) {
		err = BPF_CGROUP_RUN_PROG_INET_SOCK(sk);
		if (err) {
			sk_common_release(sk);
			goto out;
		}
	}
/**/
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
	printk(KERN_INFO "ippp inserted\n");
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