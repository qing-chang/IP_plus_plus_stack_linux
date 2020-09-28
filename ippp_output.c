#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/lwtunnel.h>
#include <linux/bpf-cgroup.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/netlink.h>
#include <linux/tcp.h>
#include "ippp.h"

struct sk_buff *ip_make_skb(struct sock *sk, struct flowi4 *fl4,
			    int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen, struct ipcm_cookie *ipc, struct rtable **rtp,
			    struct inet_cork *cork, unsigned int flags)
{
	struct sk_buff_head queue;
	int err;

	if (flags & MSG_PROBE)
		return NULL;

	__skb_queue_head_init(&queue);

	cork->flags = 0;
	cork->addr = 0;
	cork->opt = NULL;printk(KERN_INFO "ip_make_skb...");
	// err = ip_setup_cork(sk, cork, ipc, rtp);
	// if (err)
		return ERR_PTR(err);

	// err = __ip_append_data(sk, fl4, &queue, cork, &current->task_frag, getfrag, from, length, transhdrlen, flags);
	// if (err) {
	// 	__ip_flush_pending_frames(sk, &queue, cork);
	// 	return ERR_PTR(err);
	// }

	// return __ip_make_skb(sk, fl4, &queue, cork);
}