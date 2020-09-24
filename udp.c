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
DEFINE_STATIC_KEY_FALSE(udppp_encap_needed_key);
static struct net_protocol udppp_protocol = {
    //.early_demux =	udp_v4_early_demux,
    //.early_demux_handler =	udp_v4_early_demux,
    .handler = udppp_rcv,
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

int udppp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
	struct flowi4 fl4_stack;
	struct flowi4 *fl4;
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err, is_udplite = IS_UDPLITE(sk);
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct sk_buff *skb;
	struct ip_options_data opt_copy;

	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
	 *	Check the flags.
	 */

	if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

// 	getfrag = is_udplite ? udplite_getfrag : ip_generic_getfrag;

	fl4 = &inet->cork.fl.u.ip4;
	if (up->pending) {
		/*
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INET)) {
				release_sock(sk);
				return -EINVAL;
			}
			goto do_append_data;
		}
		release_sock(sk);
	}
	ulen += sizeof(struct udphdr);

	/*
	 *	Get and verify the address.
	 */
	if (usin) {
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		if (usin->sin_family != AF_INETPP) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}
		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		if (dport == 0)
			return -EINVAL;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
// 		daddr = inet->inet_daddr;
// 		dport = inet->inet_dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		connected = 1;
	}

// 	ipcm_init_sk(&ipc, inet);
// 	ipc.gso_size = up->gso_size;

	if (msg->msg_controllen) {
// 		err = udp_cmsg_send(sk, msg, &ipc.gso_size);
// 		if (err > 0)
// 			err = ip_cmsg_send(sk, msg, &ipc,
// 					   sk->sk_family == AF_INET6);
// 		if (unlikely(err < 0)) {
// 			kfree(ipc.opt);
// 			return err;
// 		}
// 		if (ipc.opt)
// 			free = 1;
// 		connected = 0;
	}
// 	if (!ipc.opt) {
// 		struct ip_options_rcu *inet_opt;

// 		rcu_read_lock();
// 		inet_opt = rcu_dereference(inet->inet_opt);
// 		if (inet_opt) {
// 			memcpy(&opt_copy, inet_opt,
// 			       sizeof(*inet_opt) + inet_opt->opt.optlen);
// 			ipc.opt = &opt_copy.opt;
// 		}
// 		rcu_read_unlock();
// 	}

// 	if (cgroup_bpf_enabled && !connected) {
// 		err = BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk,
// 					    (struct sockaddr *)usin, &ipc.addr);
// 		if (err)
// 			goto out_free;
// 		if (usin) {
// 			if (usin->sin_port == 0) {
// 				/* BPF program set invalid port. Reject it. */
// 				err = -EINVAL;
// 				goto out_free;
// 			}
// 			daddr = usin->sin_addr.s_addr;
// 			dport = usin->sin_port;
// 		}
// 	}

// 	saddr = ipc.addr;
// 	ipc.addr = faddr = daddr;

// 	if (ipc.opt && ipc.opt->opt.srr) {
// 		if (!daddr) {
// 			err = -EINVAL;
// 			goto out_free;
// 		}
// 		faddr = ipc.opt->opt.faddr;
// 		connected = 0;
// 	}
// 	tos = get_rttos(&ipc, inet);
// 	if (sock_flag(sk, SOCK_LOCALROUTE) ||
// 	    (msg->msg_flags & MSG_DONTROUTE) ||
// 	    (ipc.opt && ipc.opt->opt.is_strictroute)) {
// 		tos |= RTO_ONLINK;
// 		connected = 0;
// 	}

// 	if (ipv4_is_multicast(daddr)) {
// 		if (!ipc.oif || netif_index_is_l3_master(sock_net(sk), ipc.oif))
// 			ipc.oif = inet->mc_index;
// 		if (!saddr)
// 			saddr = inet->mc_addr;
// 		connected = 0;
// 	} else if (!ipc.oif) {
// 		ipc.oif = inet->uc_index;
// 	} else if (ipv4_is_lbcast(daddr) && inet->uc_index) {
		/* oif is set, packet is to local broadcast and
		 * and uc_index is set. oif is most likely set
		 * by sk_bound_dev_if. If uc_index != oif check if the
		 * oif is an L3 master and uc_index is an L3 slave.
		 * If so, we want to allow the send using the uc_index.
		 */
// 		if (ipc.oif != inet->uc_index &&
// 		    ipc.oif == l3mdev_master_ifindex_by_index(sock_net(sk),
// 							      inet->uc_index)) {
// 			ipc.oif = inet->uc_index;
// 		}
// 	}

// 	if (connected)
// 		rt = (struct rtable *)sk_dst_check(sk, 0);

// 	if (!rt) {
// 		struct net *net = sock_net(sk);
// 		__u8 flow_flags = inet_sk_flowi_flags(sk);

// 		fl4 = &fl4_stack;

// 		flowi4_init_output(fl4, ipc.oif, ipc.sockc.mark, tos,
// 				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
// 				   flow_flags,
// 				   faddr, saddr, dport, inet->inet_sport,
// 				   sk->sk_uid);

// 		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
// 		rt = ip_route_output_flow(net, fl4, sk);
// 		if (IS_ERR(rt)) {
// 			err = PTR_ERR(rt);
// 			rt = NULL;
// 			if (err == -ENETUNREACH)
// 				IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
// 			goto out;
// 		}

// 		err = -EACCES;
// 		if ((rt->rt_flags & RTCF_BROADCAST) &&
// 		    !sock_flag(sk, SOCK_BROADCAST))
// 			goto out;
// 		if (connected)
// 			sk_dst_set(sk, dst_clone(&rt->dst));
// 	}

// 	if (msg->msg_flags&MSG_CONFIRM)
// 		goto do_confirm;
back_from_confirm:

// 	saddr = fl4->saddr;
// 	if (!ipc.addr)
// 		daddr = ipc.addr = fl4->daddr;

	/* Lockless fast path for the non-corking case. */
	if (!corkreq) {
		struct inet_cork cork;

// 		skb = ip_make_skb(sk, fl4, getfrag, msg, ulen, sizeof(struct udphdr), &ipc, &rt, &cork, msg->msg_flags);
		err = PTR_ERR(skb);
// 		if (!IS_ERR_OR_NULL(skb))
// 			err = udp_send_skb(skb, fl4, &cork);
		goto out;
	}

	lock_sock(sk);
// 	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
// 		release_sock(sk);

// 		net_dbg_ratelimited("socket already corked\n");
// 		err = -EINVAL;
// 		goto out;
// 	}
	/*
	 *	Now cork the socket to pend data.
	 */
// 	fl4 = &inet->cork.fl.u.ip4;
// 	fl4->daddr = daddr;
// 	fl4->saddr = saddr;
// 	fl4->fl4_dport = dport;
// 	fl4->fl4_sport = inet->inet_sport;
// 	up->pending = AF_INET;

do_append_data:
	up->len += ulen;
// 	err = ip_append_data(sk, fl4, getfrag, msg, ulen,
// 			     sizeof(struct udphdr), &ipc, &rt,
// 			     corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
// 	if (err)
// 		udp_flush_pending_frames(sk);
// 	else if (!corkreq)
// 		err = udp_push_pending_frames(sk);
// 	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
// 		up->pending = 0;
// 	release_sock(sk);

out:
// 	ip_rt_put(rt);
out_free:
// 	if (free)
// 		kfree(ipc.opt);
// 	if (!err)
// 		return len;
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
// 	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
// 		UDP_INC_STATS(sock_net(sk), UDP_MIB_SNDBUFERRORS, is_udplite);
// 	}
// 	return err;

do_confirm:
// 	if (msg->msg_flags & MSG_PROBE)
// 		dst_confirm_neigh(&rt->dst, &fl4->daddr);
// 	if (!(msg->msg_flags&MSG_PROBE) || len)
// 		goto back_from_confirm;
	err = 0;
	goto out;
}
EXPORT_SYMBOL(udppp_sendmsg);

static struct sk_buff *skb_set_peeked(struct sk_buff *skb)
{
	struct sk_buff *nskb;

	if (skb->peeked)
		return skb;

	/* We have to unshare an skb before modifying it. */
	if (!skb_shared(skb))
		goto done;

	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb)
		return ERR_PTR(-ENOMEM);

	skb->prev->next = nskb;
	skb->next->prev = nskb;
	nskb->prev = skb->prev;
	nskb->next = skb->next;

	consume_skb(skb);
	skb = nskb;

done:
	skb->peeked = 1;

	return skb;
}

struct sk_buff *__skb_try_recv_from_queue(struct sock *sk, struct sk_buff_head *queue,
					  unsigned int flags, int *off, int *err, struct sk_buff **last)
{
	bool peek_at_off = false;
	struct sk_buff *skb;
	int _off = 0;

	if (unlikely(flags & MSG_PEEK && *off >= 0)) {
		peek_at_off = true;
		_off = *off;
	}

	*last = queue->prev;
	skb_queue_walk(queue, skb) {
		if (flags & MSG_PEEK) {
			if (peek_at_off && _off >= skb->len &&
			    (_off || skb->peeked)) {
				_off -= skb->len;
				continue;
			}
			if (!skb->len) {
				skb = skb_set_peeked(skb);
				if (IS_ERR(skb)) {
					*err = PTR_ERR(skb);
					return NULL;
				}
			}
			refcount_inc(&skb->users);
		} else {
			__skb_unlink(skb, queue);
		}
		*off = _off;
		return skb;
	}
	return NULL;
}

static void udp_rmem_release(struct sock *sk, int size, int partial, bool rx_queue_lock_held)
{
	struct udp_sock *up = udp_sk(sk);
	struct sk_buff_head *sk_queue;
	int amt;

	if (likely(partial)) {
		up->forward_deficit += size;
		size = up->forward_deficit;
		if (size < (sk->sk_rcvbuf >> 2) &&
		    !skb_queue_empty(&up->reader_queue))
			return;
	} else {
		size += up->forward_deficit;
	}
	up->forward_deficit = 0;

	/* acquire the sk_receive_queue for fwd allocated memory scheduling,
	 * if the called don't held it already
	 */
	sk_queue = &sk->sk_receive_queue;
	if (!rx_queue_lock_held)
		spin_lock(&sk_queue->lock);


	sk->sk_forward_alloc += size;
	amt = (sk->sk_forward_alloc - partial) & ~(SK_MEM_QUANTUM - 1);
	sk->sk_forward_alloc -= amt;

	if (amt)
		__sk_mem_reduce_allocated(sk, amt >> SK_MEM_QUANTUM_SHIFT);

	atomic_sub(size, &sk->sk_rmem_alloc);

	/* this can save us from acquiring the rx queue lock on next receive */
	skb_queue_splice_tail_init(sk_queue, &up->reader_queue);

	if (!rx_queue_lock_held)
		spin_unlock(&sk_queue->lock);
}

#define UDP_SKB_IS_STATELESS 0x80000000

static int udp_skb_truesize(struct sk_buff *skb)
{
	return udp_skb_scratch(skb)->_tsize_state & ~UDP_SKB_IS_STATELESS;
}

static void udp_skb_dtor_locked(struct sock *sk, struct sk_buff *skb)
{
	prefetch(&skb->data);
	udp_rmem_release(sk, udp_skb_truesize(skb), 1, true);
}

static inline int connection_based(struct sock *sk)
{
	return sk->sk_type == SOCK_SEQPACKET || sk->sk_type == SOCK_STREAM;
}

static int receiver_wake_function_pp(wait_queue_entry_t *wait, unsigned int mode, int sync, void *key)
{
	/*
	 * Avoid a wakeup if event not interesting for us
	 */
	if (key && !(key_to_poll(key) & (EPOLLIN | EPOLLERR)))
		return 0;
	return autoremove_wake_function(wait, mode, sync, key);
}

int __skb_wait_for_more_packets_pp(struct sock *sk, struct sk_buff_head *queue, int *err, long *timeo_p, const struct sk_buff *skb)
{
	int error;
	DEFINE_WAIT_FUNC(wait, receiver_wake_function_pp);

	prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);

	/* Socket errors? */
	error = sock_error(sk);
	if (error)
		goto out_err;

	if (READ_ONCE(queue->prev) != skb)
		goto out;

	/* Socket shut down? */
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		goto out_noerr;

	/* Sequenced packets can come disconnected.
	 * If so we report the problem
	 */
	error = -ENOTCONN;
	if (connection_based(sk) && !(sk->sk_state == TCP_ESTABLISHED || sk->sk_state == TCP_LISTEN))
		goto out_err;

	/* handle signals */
	if (signal_pending(current))
		goto interrupted;

	error = 0;
	*timeo_p = schedule_timeout(*timeo_p);
out:
	finish_wait(sk_sleep(sk), &wait);
	return error;
interrupted:
	error = sock_intr_errno(*timeo_p);
out_err:
	*err = error;
	goto out;
out_noerr:
	*err = 0;
	error = 1;
	goto out;
}

struct sk_buff *__skb_recv_udppp(struct sock *sk, unsigned int flags, int noblock, int *off, int *err)
{
	struct sk_buff_head *sk_queue = &sk->sk_receive_queue;
	struct sk_buff_head *queue;
	struct sk_buff *last;
	long timeo;
	int error;

	queue = &udp_sk(sk)->reader_queue;
	flags |= noblock ? MSG_DONTWAIT : 0;
	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	do {
		struct sk_buff *skb;

		error = sock_error(sk);
		if (error)
			break;

		error = -EAGAIN;
		do {
			spin_lock_bh(&queue->lock);
			skb = __skb_try_recv_from_queue(sk, queue, flags, off,err, &last);
			if (skb) {
				if (!(flags & MSG_PEEK))
					udp_skb_destructor(sk, skb);
				spin_unlock_bh(&queue->lock);
				return skb;
			}

			if (skb_queue_empty_lockless(sk_queue)) {
				spin_unlock_bh(&queue->lock);
				goto busy_check;
			}

			/* refill the reader queue and walk it again
			 * keep both queues locked to avoid re-acquiring
			 * the sk_receive_queue lock if fwd memory scheduling
			 * is needed.
			 */
			spin_lock(&sk_queue->lock);
			skb_queue_splice_tail_init(sk_queue, queue);

			skb = __skb_try_recv_from_queue(sk, queue, flags, off, err, &last);
			if (skb && !(flags & MSG_PEEK))
				udp_skb_dtor_locked(sk, skb);
			spin_unlock(&sk_queue->lock);
			spin_unlock_bh(&queue->lock);
			if (skb)
				return skb;

busy_check:
			if (!sk_can_busy_loop(sk))
				break;

			sk_busy_loop(sk, flags & MSG_DONTWAIT);
		} while (!skb_queue_empty_lockless(sk_queue));

		/* sk_queue is empty, reader_queue may contain peeked packets */
	} while (timeo && !__skb_wait_for_more_packets_pp(sk, &sk->sk_receive_queue, &error, &timeo, (struct sk_buff *)sk_queue));

	*err = error;
	return NULL;
}

/*
 * 	This should be easy, if there is something there we
 * 	return it, otherwise we block.
 */

int udppp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_ippp *, sin, msg->msg_name);
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int off, err, peeking = flags & MSG_PEEK;
	int is_udplite = IS_UDPLITE(sk);
	bool checksum_valid = false;

// 	if (flags & MSG_ERRQUEUE)
// 		return ip_recv_error(sk, msg, len, addr_len);

try_again:
	off = sk_peek_offset(sk, flags);
	skb = __skb_recv_udp(sk, flags, noblock, &off, &err);
	if (!skb)
		return err;

	ulen = udp_skb_len(skb);
	copied = len;
	if (copied > ulen - off)
		copied = ulen - off;
	else if (copied < ulen)
		msg->msg_flags |= MSG_TRUNC;

	/*
	 * If checksum is needed at all, try to do it while copying the
	 * data.  If the data is truncated, or if we only want a partial
	 * coverage checksum (UDP-Lite), do it before the copy.
	 */

// 	if (copied < ulen || peeking || (is_udplite && UDP_SKB_CB(skb)->partial_cov)) {
// 		checksum_valid = udp_skb_csum_unnecessary(skb) || !__udp_lib_checksum_complete(skb);
// 		if (!checksum_valid)
// 			goto csum_copy_err;
// 	}

// 	if (checksum_valid || udp_skb_csum_unnecessary(skb)) {
// 		if (udp_skb_is_linear(skb))
			err = copy_linear_skb(skb, copied, off, &msg->msg_iter);
// 		else
			// err = skb_copy_datagram_msg(skb, off, msg, copied);
// 	} else {
// 		err = skb_copy_and_csum_datagram_msg(skb, off, msg);

// 		if (err == -EINVAL)
// 			goto csum_copy_err;
// 	}

// 	if (unlikely(err)) {
// 		if (!peeking) {
// 			atomic_inc(&sk->sk_drops);
// 			UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
// 		}
// 		kfree_skb(skb);
// 		return err;
// 	}

// 	if (!peeking)
// 		UDP_INC_STATS(sock_net(sk), UDP_MIB_INDATAGRAMS, is_udplite);

// 	sock_recv_ts_and_drops(msg, sk, skb);

	/* Copy the address. */
	if (sin) {
		sin->sin_family = AF_INETPP;
		sin->sin_port = udp_hdr(skb)->source;
// 		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
// 		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
		*addr_len = sizeof(*sin);

// 		if (cgroup_bpf_enabled)
// 			BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk, (struct sockaddr *)sin);
	}

// 	if (udp_sk(sk)->gro_enabled)
// 		udp_cmsg_recv(msg, sk, skb);

// 	if (inet->cmsg_flags)
// 		ip_cmsg_recv_offset(msg, sk, skb, sizeof(struct udphdr), off);

	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;

	skb_consume_udp(sk, skb, peeking ? -err : err);
	return err;

csum_copy_err:
// 	if (!__sk_queue_drop_skb(sk, &udp_sk(sk)->reader_queue, skb, flags, udp_skb_destructor)) {
// 		UDP_INC_STATS(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
// 		UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
// 	}
// 	kfree_skb(skb);

	/* starting over for a new packet, but check if we need to yield */
// 	cond_resched();
	msg->msg_flags &= ~MSG_TRUNC;
	goto try_again;
}
static int compute_score(struct sock *sk, struct net *net, __be32 saddr, __be16 sport, __be32 daddr, unsigned short hnum, int dif, int sdif)
{
	int score;
	struct inet_sock *inet;
	bool dev_match;
//  if (!net_eq(sock_net(sk), net))printk("net_eq(sock_net(sk), net");
//  if (udp_sk(sk)->udp_port_hash != hnum )printk("udp_sk(sk)->udp_port_hash != hnum ");
//  if (ipv6_only_sock(sk))printk("ipv6_only_sock(sk)");
// 	if (!net_eq(sock_net(sk), net) || udp_sk(sk)->udp_port_hash != hnum || ipv6_only_sock(sk))
// 		{printk("-1....");return -1;}
	// char str[20];
	// IP4tostr(sk->sk_rcv_saddr,str);
	// printk("sk->sk_rcv_saddr=%s",str);
	// IP4tostr(daddr,str);
	// printk("daddr=%s",str);
	// if (sk->sk_rcv_saddr != daddr)
	// 	return -1;

	score = (sk->sk_family == PF_INETPP) ? 2 : 1;

	inet = inet_sk(sk);
	if (inet->inet_daddr) {
		if (inet->inet_daddr != saddr)
			return -1;
		score += 4;
	}

	if (inet->inet_dport) {
		if (inet->inet_dport != sport)
			return -1;
		score += 4;
	}

	dev_match = udp_sk_bound_dev_eq(net, sk->sk_bound_dev_if, dif, sdif);
	// if (!dev_match)
	// 	return -1;
	score += 4;

	if (READ_ONCE(sk->sk_incoming_cpu) == raw_smp_processor_id())
		score++;
	return score;
}

static u32 udp_ehashfn(const struct net *net, const __be32 laddr, const __u16 lport, const __be32 faddr, const __be16 fport)
{
	static u32 udp_ehash_secret __read_mostly;

	net_get_random_once(&udp_ehash_secret, sizeof(udp_ehash_secret));

	return __inet_ehashfn(laddr, lport, faddr, fport, udp_ehash_secret + net_hash_mix(net));
}
static struct sock *udp4_lib_lookup2(struct net *net, __be32 saddr, __be16 sport, __be32 daddr, unsigned int hnum,
				     int dif, int sdif, struct udp_hslot *hslot2, struct sk_buff *skb)
{
	struct sock *sk, *result;
	int score, badness;
	u32 hash = 0;

	result = NULL;
	badness = 0;
	udp_portaddr_for_each_entry_rcu(sk, &hslot2->head) {
		score = compute_score(sk, net, saddr, sport, daddr, hnum, dif, sdif);
	// char str[20];
	// u32tostr(score,str);
	// printk("score=%s",str);
		if (score > badness) {
			if (sk->sk_reuseport &&
			    sk->sk_state != TCP_ESTABLISHED) {
				hash = udp_ehashfn(net, daddr, hnum,
						   saddr, sport);
				result = reuseport_select_sock(sk, hash, skb, sizeof(struct udphdr));
				if (result && !reuseport_has_conns(sk, false))
					return result;
			}
			badness = score;
			result = sk;
		}
	}
	return result;
}
struct sock *__udp4_lib_lookup_(struct net *net, __be32 saddr, __be16 sport, __be32 daddr, __be16 dport, int dif,
		int sdif, struct udp_table *udptable, struct sk_buff *skb)
{
	struct sock *result;
	unsigned short hnum = ntohs(dport);
	unsigned int hash2, slot2;
	struct udp_hslot *hslot2;

	hash2 = ipv4_portaddr_hash(net, daddr, hnum);
	slot2 = hash2 & udptable->mask;
	hslot2 = &udptable->hash2[slot2];

	result = udp4_lib_lookup2(net, saddr, sport, daddr, hnum, dif, sdif, hslot2, skb);
	if (!result) {
		hash2 = ipv4_portaddr_hash(net, htonl(INADDR_ANY), hnum);
		slot2 = hash2 & udptable->mask;
		hslot2 = &udptable->hash2[slot2];

		result = udp4_lib_lookup2(net, saddr, sport, htonl(INADDR_ANY), hnum, dif, sdif, hslot2, skb);
	}
	if (IS_ERR(result))
		return NULL;
	return result;
}
static inline struct sock *__udppp_lib_lookup_skb(struct sk_buff *skb, __be16 sport, __be16 dport, struct udp_table *udptable)
{
	const struct ippphdr *ippph = ippp_hdr(skb);

	return __udp4_lib_lookup_(dev_net(skb->dev), ippph->addr[ippph->dst_len + ippph->src_len + 1],
			sport, ippph->addr[ippph->dst_len], dport, inet_iif(skb), inet_sdif(skb), udptable, skb);
}
/**
 * skb_condense - try to get rid of fragments/frag_list if possible
 * @skb: buffer
 *
 * Can be used to save memory before skb is added to a busy queue.
 * If packet has bytes in frags and enough tail room in skb->head,
 * pull all of them, so that we can free the frags right now and adjust
 * truesize.
 * Notes:
 *	We do not reallocate skb->head thus can not fail.
 *	Caller must re-evaluate skb->truesize if needed.
 */
void skb_condense(struct sk_buff *skb)
{
	if (skb->data_len) {
		if (skb->data_len > skb->end - skb->tail || skb_cloned(skb))
			return;

		/* Nice, we can free page frag(s) right now */
		__pskb_pull_tail(skb, skb->data_len);
	}
	/* At this point, skb->truesize might be over estimated,
	 * because skb had a fragment, and fragments do not tell
	 * their truesize.
	 * When we pulled its content into skb->head, fragment
	 * was freed, but __pskb_pull_tail() could not possibly
	 * adjust skb->truesize, not knowing the frag truesize.
	 */
	skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));
}
static int udp_busylocks_log __read_mostly;
static spinlock_t *udp_busylocks __read_mostly;
static spinlock_t *busylock_acquire(void *ptr)
{
	spinlock_t *busy;

	busy = udp_busylocks + hash_ptr(ptr, udp_busylocks_log);
	spin_lock(busy);
	return busy;
}
static bool udp_try_make_stateless(struct sk_buff *skb)
{
	if (!skb_has_extensions(skb))
		return true;

	if (!secpath_exists(skb)) {
		skb_ext_reset(skb);
		return true;
	}

	return false;
}
#define UDP_SKB_IS_STATELESS 0x80000000
static void udp_set_dev_scratch(struct sk_buff *skb)
{
	struct udp_dev_scratch *scratch = udp_skb_scratch(skb);

	BUILD_BUG_ON(sizeof(struct udp_dev_scratch) > sizeof(long));
	scratch->_tsize_state = skb->truesize;
#if BITS_PER_LONG == 64
	scratch->len = skb->len;
	scratch->csum_unnecessary = !!skb_csum_unnecessary(skb);
	scratch->is_linear = !skb_is_nonlinear(skb);
#endif
	if (udp_try_make_stateless(skb))
		scratch->_tsize_state |= UDP_SKB_IS_STATELESS;
}
static void busylock_release(spinlock_t *busy)
{
	if (busy)
		spin_unlock(busy);
}

int __udp_enqueue_schedule_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff_head *list = &sk->sk_receive_queue;
	int rmem, delta, amt, err = -ENOMEM;
	spinlock_t *busy = NULL;
	int size;

	/* try to avoid the costly atomic add/sub pair when the receive
	 * queue is full; always allow at least a packet
	 */
	rmem = atomic_read(&sk->sk_rmem_alloc);
	if (rmem > sk->sk_rcvbuf)
		goto drop;

	/* Under mem pressure, it might be helpful to help udp_recvmsg()
	 * having linear skbs :
	 * - Reduce memory overhead and thus increase receive queue capacity
	 * - Less cache line misses at copyout() time
	 * - Less work at consume_skb() (less alien page frag freeing)
	 */
	if (rmem > (sk->sk_rcvbuf >> 1)) {
		skb_condense(skb);

		busy = busylock_acquire(sk);
	}
	size = skb->truesize;
	udp_set_dev_scratch(skb);

	/* we drop only if the receive buf is full and the receive
	 * queue contains some other skb
	 */
	rmem = atomic_add_return(size, &sk->sk_rmem_alloc);
	if (rmem > (size + (unsigned int)sk->sk_rcvbuf))
		goto uncharge_drop;

	spin_lock(&list->lock);
	if (size >= sk->sk_forward_alloc) {
		amt = sk_mem_pages(size);
		delta = amt << SK_MEM_QUANTUM_SHIFT;
		if (!__sk_mem_raise_allocated(sk, delta, amt, SK_MEM_RECV)) {
			err = -ENOBUFS;
			spin_unlock(&list->lock);
			goto uncharge_drop;
		}

		sk->sk_forward_alloc += delta;
	}

	sk->sk_forward_alloc -= size;

	/* no need to setup a destructor, we will explicitly release the
	 * forward allocated memory on dequeue
	 */
	sock_skb_set_dropcount(sk, skb);

	__skb_queue_tail(list, skb);
	spin_unlock(&list->lock);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk);

	busylock_release(busy);
	return 0;

uncharge_drop:
	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);

drop:
	atomic_inc(&sk->sk_drops);
	busylock_release(busy);
	return err;
}
static int __udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int rc;

	if (inet_sk(sk)->inet_daddr) {
		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
		sk_incoming_cpu_update(sk);
	} else {
		sk_mark_napi_id_once(sk, skb);
	}

	rc = __udp_enqueue_schedule_skb(sk, skb);
	// if (rc < 0) {
	// 	int is_udplite = IS_UDPLITE(sk);

		/* Note that an ENOMEM error is charged twice */
	// 	if (rc == -ENOMEM)
	// 		UDP_INC_STATS(sock_net(sk), UDP_MIB_RCVBUFERRORS,
	// 				is_udplite);
	// 	UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
	// 	kfree_skb(skb);
	// 	trace_udp_fail_queue_rcv_skb(rc, sk);
	// 	return -1;
	// }

	return 0;
}

/* returns:
 *  -1: error
 *   0: success
 *  >0: "udp encap" protocol resubmission
 *
 * Note that in the success and error cases, the skb is assumed to
 * have either been requeued or freed.
 */
static int udp_queue_rcv_one_skb(struct sock *sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	int is_udplite = IS_UDPLITE(sk);

	/*
	 *	Charge it to the socket, dropping if the queue is full.
	 */
// 	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
// 		goto drop;
// 	nf_reset_ct(skb);

// 	if (static_branch_unlikely(&udp_encap_needed_key) && up->encap_type) {
// 		int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);

		/*
		 * This is an encapsulation socket so pass the skb to
		 * the socket's udp_encap_rcv() hook. Otherwise, just
		 * fall through and pass this up the UDP socket.
		 * up->encap_rcv() returns the following value:
		 * =0 if skb was successfully passed to the encap
		 *    handler or was discarded by it.
		 * >0 if skb should be passed on to UDP.
		 * <0 if skb should be resubmitted as proto -N
		 */

		/* if we're overly short, let UDP handle it */
// 		encap_rcv = READ_ONCE(up->encap_rcv);
// 		if (encap_rcv) {
// 			int ret;

			/* Verify checksum before giving to encap */
// 			if (udp_lib_checksum_complete(skb))
// 				goto csum_error;

// 			ret = encap_rcv(sk, skb);
// 			if (ret <= 0) {
// 				__UDP_INC_STATS(sock_net(sk),
// 						UDP_MIB_INDATAGRAMS,
// 						is_udplite);
// 				return -ret;
// 			}
// 		}

		/* FALLTHROUGH -- it's a UDP Packet */
// 	}

	/*
	 * 	UDP-Lite specific tests, ignored on UDP sockets
	 */
// 	if ((is_udplite & UDPLITE_RECV_CC)  &&  UDP_SKB_CB(skb)->partial_cov) {

		/*
		 * MIB statistics other than incrementing the error count are
		 * disabled for the following two types of errors: these depend
		 * on the application settings, not on the functioning of the
		 * protocol stack as such.
		 *
		 * RFC 3828 here recommends (sec 3.3): "There should also be a
		 * way ... to ... at least let the receiving application block
		 * delivery of packets with coverage values less than a value
		 * provided by the application."
		 */
// 		if (up->pcrlen == 0) {          /* full coverage was set  */
// 			net_dbg_ratelimited("UDPLite: partial coverage %d while full coverage %d requested\n",
// 					    UDP_SKB_CB(skb)->cscov, skb->len);
// 			goto drop;
// 		}
		/* The next case involves violating the min. coverage requested
		 * by the receiver. This is subtle: if receiver wants x and x is
		 * greater than the buffersize/MTU then receiver will complain
		 * that it wants x while sender emits packets of smaller size y.
		 * Therefore the above ...()->partial_cov statement is essential.
		 */
// 		if (UDP_SKB_CB(skb)->cscov  <  up->pcrlen) {
// 			net_dbg_ratelimited("UDPLite: coverage %d too small, need min %d\n",
// 					    UDP_SKB_CB(skb)->cscov, up->pcrlen);
// 			goto drop;
// 		}
// 	}

// 	prefetch(&sk->sk_rmem_alloc);
// 	if (rcu_access_pointer(sk->sk_filter) &&
// 	    udp_lib_checksum_complete(skb))
// 			goto csum_error;

// 	if (sk_filter_trim_cap(sk, skb, sizeof(struct udphdr)))
// 		goto drop;

	udp_csum_pull_header(skb);

// 	ipv4_pktinfo_prepare(sk, skb);
	return __udp_queue_rcv_skb(sk, skb);

// csum_error:
// 	__UDP_INC_STATS(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
// drop:
// 	__UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
// 	atomic_inc(&sk->sk_drops);
// 	kfree_skb(skb);
// 	return -1;
}

static int udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff *next, *segs;
	int ret;

	if (likely(!udp_unexpected_gso(sk, skb)))
		return udp_queue_rcv_one_skb(sk, skb);

	BUILD_BUG_ON(sizeof(struct udp_skb_cb) > SKB_GSO_CB_OFFSET);
	__skb_push(skb, -skb_mac_offset(skb));
	// segs = udp_rcv_segment(sk, skb, true);
	// skb_list_walk_safe(segs, skb, next) {
	// 	__skb_pull(skb, skb_transport_offset(skb));
	// 	ret = udp_queue_rcv_one_skb(sk, skb);
	// 	if (ret > 0)
	// 		ip_protocol_deliver_rcu(dev_net(skb->dev), skb, -ret);
	// }
	return 0;
}

/* wrapper for udp_queue_rcv_skb tacking care of csum conversion and
 * return code conversion for ip layer consumption
 */
static int udppp_unicast_rcv_skb(struct sock *sk, struct sk_buff *skb, struct udphdr *uh)
{
	int ret;

	// if (inet_get_convert_csum(sk) && uh->check && !IS_UDPLITE(sk))
	// 	skb_checksum_try_convert(skb, IPPROTO_UDP, inet_compute_pseudo);

	ret = udp_queue_rcv_skb(sk, skb);

	/* a return value > 0 means to resubmit the input, but
	 * it wants the return to be -protocol, or 0
	 */
	if (ret > 0)
		return -ret;
	return 0;
}

int __udppp_lib_rcv(struct sk_buff *skb, struct udp_table *udptable, int proto)
{
	struct sock *sk;
	struct udphdr *uh;
	unsigned short ulen;
	struct rtable *rt = skb_rtable(skb);
	__be32 saddr, daddr;
	struct net *net = dev_net(skb->dev);
	bool refcounted;

	/*
	 *  Validate the packet.
	 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto drop;		/* No space for header. */

	uh   = udp_hdr(skb);
	ulen = ntohs(uh->len);
	// saddr = ip_hdr(skb)->saddr;
	// daddr = ip_hdr(skb)->daddr;
	if (ulen > skb->len)
		goto short_packet;

	if (proto == IPPROTO_UDP) {
		/* UDP validates ulen. */
		if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
			goto short_packet;
		uh = udp_hdr(skb);
	}

	// if (udp4_csum_init(skb, uh, proto))
	// 	goto csum_error;

	// sk = skb_steal_sock(skb, &refcounted);
	// if (sk) {
	// 	struct dst_entry *dst = skb_dst(skb);
	// 	int ret;

	// 	if (unlikely(sk->sk_rx_dst != dst))
	// 		udp_sk_rx_dst_set(sk, dst);

	// 	ret = udp_unicast_rcv_skb(sk, skb, uh);
	// 	if (refcounted)
	// 		sock_put(sk);
	// 	return ret;
	// }

	// if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
	// 	return __udp4_lib_mcast_deliver(net, skb, uh, saddr, daddr, udptable, proto);

	sk = __udppp_lib_lookup_skb(skb, uh->source, uh->dest, udptable);
	if (sk){
		return udppp_unicast_rcv_skb(sk, skb, uh);
	}

	// if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
	// 	goto drop;
	// nf_reset_ct(skb);

	/* No socket. Drop packet silently, if checksum is wrong */
	// if (udp_lib_checksum_complete(skb))
	// 	goto csum_error;

	__UDP_INC_STATS(net, UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
	// icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	/*
	 * Hmm.  We got an UDP packet to a port to which we
	 * don't wanna listen.  Ignore it.
	 */
	kfree_skb(skb);
	return 0;

short_packet:
// 	net_dbg_ratelimited("UDP%s: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
// 			    proto == IPPROTO_UDPLITE ? "Lite" : "", &saddr, ntohs(uh->source), ulen, skb->len, &daddr, ntohs(uh->dest));
	goto drop;

csum_error:
	/*
	 * RFC1122: OK.  Discards the bad packet silently (as far as
	 * the network is concerned, anyway) as per 4.1.3.4 (MUST).
	 */
// 	net_dbg_ratelimited("UDP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
// 			    proto == IPPROTO_UDPLITE ? "Lite" : "", &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest), ulen);
	__UDP_INC_STATS(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_UDPLITE);
drop:
	__UDP_INC_STATS(net, UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
	kfree_skb(skb);
	return 0;
}

int udppp_rcv(struct sk_buff *skb)
{
	return __udppp_lib_rcv(skb, &udp_table, IPPROTO_UDP);
}

void udp_destroy_sock(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);
	bool slow = lock_sock_fast(sk);
	udp_flush_pending_frames(sk);
	unlock_sock_fast(sk, slow);
	if (static_branch_unlikely(&udppp_encap_needed_key)) {
		if (up->encap_type) {
			void (*encap_destroy)(struct sock *sk);
			encap_destroy = READ_ONCE(up->encap_destroy);
			if (encap_destroy)
				encap_destroy(sk);
		}
		if (up->encap_enabled)
			static_branch_dec(&udppp_encap_needed_key);
	}
}

struct proto udppp_prot = {
	.name			= "UDPPP",
	.owner			= THIS_MODULE,
	.close			= udp_lib_close,
//	.pre_connect	= udpv6_pre_connect,
//	.connect		= ip6_datagram_connect,
//	.disconnect		= udp_disconnect,
//	.ioctl			= udp_ioctl,
	.init			= udp_init_sock,
	.destroy		= udp_destroy_sock,
//	.setsockopt		= udpv6_setsockopt,
//	.getsockopt		= udpv6_getsockopt,
	.sendmsg		= udppp_sendmsg,
	.recvmsg		= udppp_recvmsg,
//	.release_cb		= ip6_datagram_release_cb,
	.hash			= udp_lib_hash,
	.unhash			= udp_lib_unhash,
//	.rehash			= udp_v6_rehash,
	.get_port		= udppp_get_port,
	.memory_allocated	= &udp_memory_allocated,
	.sysctl_mem		= sysctl_udp_mem,
	.sysctl_wmem_offset     = offsetof(struct net, ipv4.sysctl_udp_wmem_min),
	.sysctl_rmem_offset     = offsetof(struct net, ipv4.sysctl_udp_rmem_min),
	.obj_size		= sizeof(struct udppp_sock),
	.h.udp_table		= &udp_table,
#ifdef CONFIG_COMPAT
	//.compat_setsockopt	= compat_udppp_setsockopt,
	//.compat_getsockopt	= compat_udppp_getsockopt,
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
