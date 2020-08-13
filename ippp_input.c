#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "indirect_call_wrapper.h"

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inet_ecn.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <net/dst_metadata.h>
//#include <linux/math.h>
#include "ippp.h"

void ippp_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol)
{
	const struct net_protocol *ipprot;
	int raw, ret;

resubmit:
	//raw = raw_local_deliver(skb, protocol);

	ipprot = rcu_dereference(inetpp_protos[protocol]);
	if (ipprot) {
		if (!ipprot->no_policy) {
	// 		if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
	// 			kfree_skb(skb);
	// 			return;
	// 		}
	// 		//nf_reset_ct(skb);
		}
		ret = INDIRECT_CALL_2(ipprot->handler, udppp_rcv, udppp_rcv, skb);
		if (ret < 0) {
			protocol = -ret;
			goto resubmit;
		}
		__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
	} else {
		if (!raw) {
	// 		if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
	// 			__IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
	// 			icmp_send(skb, ICMP_DEST_UNREACH,
	// 				  ICMP_PROT_UNREACH, 0);
	// 		}
	// 		kfree_skb(skb);
		} else {
	// 		__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
	// 		consume_skb(skb);
		}
	}
}
static int ippp_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	ippp_protocol_deliver_rcu(net, skb, ippp_hdr(skb)->protocol);
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
int ippp_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);

	// if (ip_is_fragment(ip_hdr(skb))) {
	// 	if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
	// 		return 0;
	// }

	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN, net, NULL, skb, skb->dev, NULL, ippp_local_deliver_finish);
}

static int ip_rcv_finish_core(struct net *net, struct sock *sk,
			      struct sk_buff *skb, struct net_device *dev,
			      const struct sk_buff *hint)
{
	const struct ippphdr *ippph = ippp_hdr(skb);
	//const struct iphdr *iph = ip_hdr(skb);
	int (*edemux)(struct sk_buff *skb);
	struct rtable *rt;
	int err;

// 	if (ip_can_use_hint(skb, iph, hint)) {
// 		err = ip_route_use_hint(skb, iph->daddr, iph->saddr, iph->tos,
// 					dev, hint);
// 		if (unlikely(err))
// 			goto drop_error;
// 	}

// 	if (net->ipv4.sysctl_ip_early_demux &&
// 	    !skb_dst(skb) &&
// 	    !skb->sk &&
// 	    !ip_is_fragment(iph)) {
// 		const struct net_protocol *ipprot;
// 		int protocol = iph->protocol;

// 		ipprot = rcu_dereference(inetpp_protos[protocol]);
// 		if (ipprot && (edemux = READ_ONCE(ipprot->early_demux))) {
// 			err = INDIRECT_CALL_2(edemux, tcp_v4_early_demux, udp_v4_early_demux, skb);
// 			if (unlikely(err))
// 				goto drop_error;
// 			/* must reload iph, skb->head might have changed */
// 			iph = ip_hdr(skb);
// 		}
// 	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	if (!skb_valid_dst(skb)) {
		err = ippp_route_input_noref(skb, dev);
		if (unlikely(err))
			goto drop_error;
	}

// #ifdef CONFIG_IP_ROUTE_CLASSID
// 	if (unlikely(skb_dst(skb)->tclassid)) {
// 		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
// 		u32 idx = skb_dst(skb)->tclassid;
// 		st[idx&0xFF].o_packets++;
// 		st[idx&0xFF].o_bytes += skb->len;
// 		st[(idx>>16)&0xFF].i_packets++;
// 		st[(idx>>16)&0xFF].i_bytes += skb->len;
// 	}
// #endif

// 	if (ip_rcv_options(skb, dev))
// 		goto drop;

// 	rt = skb_rtable(skb);
// 	if (rt->rt_type == RTN_MULTICAST) {
// 		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INMCAST, skb->len);
// 	} else if (rt->rt_type == RTN_BROADCAST) {
// 		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INBCAST, skb->len);
// 	} else if (skb->pkt_type == PACKET_BROADCAST ||
// 		   skb->pkt_type == PACKET_MULTICAST) {
// 		struct in_device *in_dev = __in_dev_get_rcu(dev);

		/* RFC 1122 3.3.6:
		 *
		 *   When a host sends a datagram to a link-layer broadcast
		 *   address, the IP destination address MUST be a legal IP
		 *   broadcast or IP multicast address.
		 *
		 *   A host SHOULD silently discard a datagram that is received
		 *   via a link-layer broadcast (see Section 2.4) but does not
		 *   specify an IP multicast or broadcast destination address.
		 *
		 * This doesn't explicitly say L2 *broadcast*, but broadcast is
		 * in a way a form of multicast and the most common use case for
		 * this is 802.11 protecting against cross-station spoofing (the
		 * so-called "hole-196" attack) so do it for both.
		 */
	// 	if (in_dev && IN_DEV_ORCONF(in_dev, DROP_UNICAST_IN_L2_MULTICAST))
	// 		goto drop;
	// }

	return NET_RX_SUCCESS;

drop:
	kfree_skb(skb);
	return NET_RX_DROP;

drop_error:
	if (err == -EXDEV)
		__NET_INC_STATS(net, LINUX_MIB_IPRPFILTER);
	goto drop;
}

static int ippp_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	int ret;

	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;

	ret = ip_rcv_finish_core(net, sk, skb, dev, NULL);
	if (ret != NET_RX_DROP)
		ret = ippp_local_deliver(skb);//dst_input(skb);
	return ret;
}

/*
 * 	Main IPPP Receive routine.
 */
static struct sk_buff *ippp_rcv_core(struct sk_buff *skb, struct net *net)
{
	const struct ippphdr *ippph;
	u32 len,hdrLen;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	__IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	if (!pskb_may_pull(skb, 20))
		goto inhdr_error;

	ippph = ippp_hdr(skb);
	hdrLen = hdr_len(ippph);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	if (ippph->version != 0)
		goto inhdr_error;

//	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
// 	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
// 	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
// 	__IP_ADD_STATS(net,
// 		       IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
// 		       max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

	if (!pskb_may_pull(skb, hdrLen))
		goto inhdr_error;

	ippph = ippp_hdr(skb);
	hdrLen = hdr_len(ippph);

	len = ntohs(ippph->tot_len);
	if (skb->len < len) {
		__IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < hdrLen)
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	if (pskb_trim_rcsum(skb, len)) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	ippph = ippp_hdr(skb);
	hdrLen = hdr_len(ippph);
	skb->transport_header = skb->network_header + hdrLen;

	/* Remove any debris in the socket control block */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	IPCB(skb)->iif = skb->skb_iif;

	/* Must drop socket now because of tproxy. */
	skb_orphan(skb);

	return skb;

inhdr_error:
	__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NULL;
}

/*
 * IPPP receive entry point
 */
int ippp_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct net *net = dev_net(dev);

	skb = ippp_rcv_core(skb, net);
	if (skb == NULL)
		return NET_RX_DROP;

	return NF_HOOK(NFPROTO_IPPP, NF_INET_PRE_ROUTING,net, NULL, skb, dev, NULL,ippp_rcv_finish);
}