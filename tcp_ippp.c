
#include <linux/bottom_half.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/cache.h>
#include <linux/jhash.h>
#include <linux/init.h>
#include <linux/times.h>
#include <linux/slab.h>

#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/ipv6.h>
#include <net/inet_common.h>
#include <net/timewait_sock.h>
#include <net/xfrm.h>
#include <net/secure_seq.h>
#include <net/busy_poll.h>

#include <linux/inet.h>
#include <linux/ipv6.h>
#include <linux/stddef.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/inetdevice.h>

#include <crypto/hash.h>
#include <linux/scatterlist.h>

#include <trace/events/tcp.h>
#include "ippp.h"

static struct net_protocol tcppp_protocol = {
	// .early_demux	=	tcp_v6_early_demux,
	// .early_demux_handler =  tcp_v6_early_demux,
	.handler	=	tcppp_rcv,
	// .err_handler	=	tcppp_err,
	.no_policy	=	1,
	.netns_ok	=	1,
};

int tcppp_rcv(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	struct sk_buff *skb_to_free;
	int sdif = inet_sdif(skb);
	int dif = inet_iif(skb);
	const struct ippphdr *ippph;
	const struct tcphdr *th;
	bool refcounted;
	struct sock *sk;
	int ret;

	if (skb->pkt_type != PACKET_HOST)
		goto discard_it;

	/* Count it even if it's bad */
	__TCP_INC_STATS(net, TCP_MIB_INSEGS);

	if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
		goto discard_it;

	th = (const struct tcphdr *)skb->data;

	if (unlikely(th->doff < sizeof(struct tcphdr) / 4))
		goto bad_packet;
	if (!pskb_may_pull(skb, th->doff * 4))
		goto discard_it;

	/* An explanation is required here, I think.
	 * Packet length and doff are validated by header prediction,
	 * provided case of th->doff==0 is eliminated.
	 * So, we defer the checks. */

	if (skb_checksum_init(skb, IPPROTO_TCP, inet_compute_pseudo))
		goto csum_error;

	th = (const struct tcphdr *)skb->data;
	ippph = ippp_hdr(skb);
lookup:
	sk = __inet_lookup_skb(&tcp_hashinfo, skb, __tcp_hdrlen(th), th->source, th->dest, sdif, &refcounted);
	if (!sk)
		goto no_tcp_socket;

process:
	if (sk->sk_state == TCP_TIME_WAIT)
		goto do_time_wait;



	return 0;
put_and_return:
	if (refcounted)
		sock_put(sk);

	return ret;

no_tcp_socket:
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto discard_it;

	// tcp_v4_fill_cb(skb, ippph, th);

	if (tcp_checksum_complete(skb)) {
csum_error:
		__TCP_INC_STATS(net, TCP_MIB_CSUMERRORS);
bad_packet:
		__TCP_INC_STATS(net, TCP_MIB_INERRS);
	} else {
		// tcp_v4_send_reset(NULL, skb);
	}

discard_it:
	/* Discard frame. */
	kfree_skb(skb);
	return 0;

discard_and_relse:
	sk_drops_add(sk, skb);
	if (refcounted)
		sock_put(sk);
	goto discard_it;

do_time_wait:
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
		inet_twsk_put(inet_twsk(sk));
		goto discard_it;
	}

	// tcp_v4_fill_cb(skb, iph, th);

	if (tcp_checksum_complete(skb)) {
		inet_twsk_put(inet_twsk(sk));
		goto csum_error;
	}
	switch (tcp_timewait_state_process(inet_twsk(sk), skb, th)) {
	case TCP_TW_SYN: {
		 struct sock *sk2 ;//= inet_lookup_listener(dev_net(skb->dev),
		// 					&tcp_hashinfo, skb,
		// 					__tcp_hdrlen(th),
		// 					ippph->saddr, th->source,
		// 					ippph->daddr, th->dest,
		// 					inet_iif(skb),
		// 					sdif);
		if (sk2) {
			inet_twsk_deschedule_put(inet_twsk(sk));
			sk = sk2;
			// tcp_v4_restore_cb(skb);
			refcounted = false;
			goto process;
		}
	}
		/* to ACK */
		fallthrough;
	case TCP_TW_ACK:
		// tcp_v4_timewait_ack(sk, skb);
		break;
	case TCP_TW_RST:
		// tcp_v4_send_reset(sk, skb);
		inet_twsk_deschedule_put(inet_twsk(sk));
		goto discard_it;
	case TCP_TW_SUCCESS:;
	}
	goto discard_it;
}

const struct inet_connection_sock_af_ops ippp_specific = {
	// .queue_xmit	   = inet6_csk_xmit,
// 	.send_check	   = tcp_v6_send_check,
// 	.rebuild_header	   = inet6_sk_rebuild_header,
// 	.sk_rx_dst_set	   = inet6_sk_rx_dst_set,
// 	.conn_request	   = tcp_v6_conn_request,
// 	.syn_recv_sock	   = tcp_v6_syn_recv_sock,
// 	.net_header_len	   = sizeof(struct ipv6hdr),
// 	.net_frag_header_len = sizeof(struct frag_hdr),
// 	.setsockopt	   = ipv6_setsockopt,
// 	.getsockopt	   = ipv6_getsockopt,
// 	.addr2sockaddr	   = inet6_csk_addr2sockaddr,
// 	.sockaddr_len	   = sizeof(struct sockaddr_in6),
// #ifdef CONFIG_COMPAT
// 	.compat_setsockopt = compat_ipv6_setsockopt,
// 	.compat_getsockopt = compat_ipv6_getsockopt,
// #endif
// 	.mtu_reduced	   = tcp_v6_mtu_reduced,
};

static int tcppp_init_sock(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	tcp_init_sock(sk);

	icsk->icsk_af_ops = &ippp_specific;

// #ifdef CONFIG_TCP_MD5SIG
// 	tcp_sk(sk)->af_specific = &tcp_sock_ipv6_specific;
// #endif

	return 0;
}

struct proto tcppp_prot = {
	.name			= "TCPPP",
	.owner			= THIS_MODULE,
	// .close			= tcp_close,
	// .pre_connect		= tcp_v4_pre_connect,
	// .connect		= tcp_v4_connect,
	// .disconnect		= tcp_disconnect,
	.accept			= inet_csk_accept,
	// .ioctl			= tcp_ioctl,
	.init			= tcppp_init_sock,
	// .destroy		= tcp_v4_destroy_sock,
	// .shutdown		= tcp_shutdown,
	// .setsockopt		= tcp_setsockopt,
	// .getsockopt		= tcp_getsockopt,
	// .keepalive		= tcp_set_keepalive,
	.recvmsg		= tcp_recvmsg,
	.sendmsg		= tcp_sendmsg,
	// .sendpage		= tcp_sendpage,
	// .backlog_rcv		= tcp_v4_do_rcv,
// 	.release_cb		= tcp_release_cb,
// 	.hash			= inet_hash,
// 	.unhash			= inet_unhash,
	.get_port		= inet_csk_get_port,
// 	.enter_memory_pressure	= tcp_enter_memory_pressure,
// 	.leave_memory_pressure	= tcp_leave_memory_pressure,
// 	.stream_memory_free	= tcp_stream_memory_free,
// 	.sockets_allocated	= &tcp_sockets_allocated,
// 	.orphan_count		= &tcp_orphan_count,
// 	.memory_allocated	= &tcp_memory_allocated,
// 	.memory_pressure	= &tcp_memory_pressure,
// 	.sysctl_mem		= sysctl_tcp_mem,
// 	.sysctl_wmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_wmem),
// 	.sysctl_rmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_rmem),
// 	.max_header		= MAX_TCP_HEADER,
	.obj_size		= sizeof(struct tcppp_sock),
// 	.slab_flags		= SLAB_TYPESAFE_BY_RCU,
// 	.twsk_prot		= &tcp_timewait_sock_ops,
// 	.rsk_prot		= &tcp_request_sock_ops,
	.h.hashinfo		= &tcp_hashinfo,
// 	.no_autobind		= true,
// #ifdef CONFIG_COMPAT
// 	.compat_setsockopt	= compat_tcp_setsockopt,
// 	.compat_getsockopt	= compat_tcp_getsockopt,
// #endif
// 	.diag_destroy		= tcp_abort,
};
EXPORT_SYMBOL(tcppp_prot);

static struct inet_protosw tcppp_protosw = {
	.type =      SOCK_STREAM,
	.protocol =  IPPROTO_TCP,
	.prot =      &tcppp_prot,
	.ops =       &inetpp_stream_ops,
	.flags =     INET_PROTOSW_REUSE,
};

int __init tcppp_init(void)
{
	int ret;

	ret = inetpp_add_protocol(&tcppp_protocol, IPPROTO_TCP);
	if (ret)
		goto out;

	ret = inetpp_register_protosw(&tcppp_protosw);
	if (ret)
		goto out_tcppp_protocol;
	goto out;

out_tcppp_protocol:
	inetpp_del_protocol(&tcppp_protocol, IPPROTO_TCP);
out:
	return ret;
}

void tcppp_exit(void)
{
	inetpp_unregister_protosw(&tcppp_protosw);
	inetpp_del_protocol(&tcppp_protocol, IPPROTO_TCP);
}