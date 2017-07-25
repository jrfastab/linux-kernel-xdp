#include <linux/module.h>
#include <linux/sock_diag.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/kproxy_diag.h>
#include <linux/percpu.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/kproxy.h>

static int kproxy_inet(struct sk_buff *skb, struct sock *sk)
{
	struct kproxy_diag_psock_inet6 kproxy_inet6;
	struct kproxy_diag_psock_inet kproxy_inet;
	struct inet_sock *inet = inet_sk(sk);
	int err = -EOPNOTSUPP;

	switch (sk->sk_family) {
	case AF_INET:
		kproxy_inet.saddr = inet->inet_saddr;
		kproxy_inet.daddr = inet->inet_daddr;
		kproxy_inet.sport = ntohs(inet->inet_sport);
		kproxy_inet.dport = ntohs(inet->inet_dport);

		err = nla_put(skb, KPROXY_DIAG_PSOCK_AF_INET,
			      sizeof(kproxy_inet), &kproxy_inet);
		break;
	case AF_INET6:
		//kproxy_inet.saddr = inet->inet_saddr;
		//kproxy_inet.daddr = inet->inet_daddr;
		kproxy_inet6.sport = ntohs(inet->inet_sport);
		kproxy_inet6.dport = ntohs(inet->inet_dport);

		err = nla_put(skb, KPROXY_DIAG_PSOCK_AF_INET6,
			      sizeof(kproxy_inet6), &kproxy_inet6);
		break;
	default:
		break;
	}

	return err;
}

static int kproxy_sock_fill(struct sock *sk, struct sk_buff *skb)
{
	struct kproxy_sock *ksock = kproxy_sk(sk);
	struct nlattr *psock_list, *psock_attr;
	struct kproxy_psock *psock;
	int err = 0;

	psock_list = nla_nest_start(skb, KPROXY_DIAG_PSOCK_LIST);
	if (!psock_list)
		return -EMSGSIZE;

	list_for_each_entry(psock, &ksock->server_sock, list) {
		struct kproxy_diag_psock_stats stats;

		psock_attr = nla_nest_start(skb, KPROXY_DIAG_PSOCK_ATTR_LIST);
		if (!psock_attr) {
			nla_nest_cancel(skb, psock_list);
			return -EMSGSIZE;
		}

		stats.tx_bytes = psock->stats.tx_bytes;
		stats.rx_bytes = psock->stats.rx_bytes;
		err = nla_put(skb, KPROXY_DIAG_PSOCK_STATS, sizeof(stats), &stats);
		if (err)
			goto out;

		err = kproxy_inet(skb, psock->sock);
		if (err)
			goto out;

		nla_nest_end(skb, psock_attr);
	}

	nla_nest_end(skb, psock_list);
	return 0;
out:
	nla_nest_cancel(skb, psock_attr);
	nla_nest_cancel(skb, psock_list);
	return err;
}

static int kproxy_diag_fill(struct sk_buff *skb,
			    struct kproxy_diag_req *req,
			    bool may_report_filterinfo,
			    u32 portid, u32 seq, u32 flags)
{
	struct net *net = sock_net(skb->sk);
	struct kproxy_diag_msg *rp;
	struct nlattr *proxy_list;
	struct hlist_head *head;
	struct nlmsghdr *nlh;
	int err = -EMSGSIZE;
	struct sock *sk;
	int num = 0;

	nlh = nlmsg_put(skb, portid, seq, SOCK_DIAG_BY_FAMILY, sizeof(*rp), flags);
	if (!nlh)
		return -EMSGSIZE;

	rp = nlmsg_data(nlh);
	rp->kdiag_family = AF_KPROXY;
	sock_diag_save_cookie(skb->sk, rp->kdiag_cookie);

	read_lock(&kproxy_proto.h.kproxy_hash->lock);
	head = &kproxy_proto.h.kproxy_hash->ht;
	if (hlist_empty(head))
		goto done;

	proxy_list = nla_nest_start(skb, KPROXY_DIAG_PROXY_LIST);
	if (!proxy_list)
		goto done;

	sk_for_each(sk, head) {
		if (!net_eq(sock_net(sk), net))
			continue;

		err = kproxy_sock_fill(sk, skb);
		if (err	< 0)
			goto done_list;
		num++;
	}
done_list:
	nla_nest_end(skb, proxy_list);
done:
	rp->kdiag_num = num;
	read_unlock(&kproxy_proto.h.kproxy_hash->lock);
	nlmsg_end(skb, nlh);
	return err < 0 ? err : num;
}

static int kproxy_diag_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	int num = 0, s_num = cb->args[0];
	struct kproxy_diag_req *req;
	bool may_report_filterinfo;
	int err;

	req = nlmsg_data(cb->nlh);
	may_report_filterinfo = netlink_net_capable(cb->skb, CAP_NET_ADMIN);
	err = kproxy_diag_fill(skb, req, may_report_filterinfo,
			       NETLINK_CB(cb->skb).portid,
			       cb->nlh->nlmsg_seq, NLM_F_MULTI);
	cb->args[0] = err;

	return skb->len;
}

static int kproxy_diag_handler_dump(struct sk_buff *skb, struct nlmsghdr *h)
{
	int hdrlen = sizeof(struct kproxy_diag_req);
	struct net *net = sock_net(skb->sk);
	struct kproxy_diag_req *req;

	if (nlmsg_len(h) < hdrlen)
		return -EINVAL;

	req = nlmsg_data(h);
	if (h->nlmsg_flags & NLM_F_DUMP) {
		struct netlink_dump_control c = {
			.dump = kproxy_diag_dump,
		};
		return netlink_dump_start(net->diag_nlsk, skb, h, &c);
	}

	return -EOPNOTSUPP;
}

static const struct sock_diag_handler kproxy_diag_handler = {
	.family = AF_KPROXY,
	.dump = kproxy_diag_handler_dump,
};

static int __init kproxy_diag_init(void)
{
	return sock_diag_register(&kproxy_diag_handler);
}

static void __exit kproxy_diag_exit(void)
{
	sock_diag_unregister(&kproxy_diag_handler);
}

module_init(kproxy_diag_init);
module_exit(kproxy_diag_exit);
MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 44 /* AF_KPROXY */);
