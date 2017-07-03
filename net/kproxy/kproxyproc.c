#include <linux/in.h>
#include <linux/inet.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/rculist.h>
#include <linux/seq_file.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <net/kproxy.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#ifdef CONFIG_PROC_FS
struct kproxy_seq_proxyinfo {
	char				*name;
	const struct file_operations	*seq_fops;
	const struct seq_operations	seq_ops;
};

static struct kproxy_sock *kproxy_get_first(struct seq_file *seq)
{
	struct net *net = seq_file_net(seq);
	struct kproxy_net *knet = net_generic(net, kproxy_net_id);

	return list_first_or_null_rcu(&knet->kproxy_list,
				      struct kproxy_sock, kproxy_list);
}

static struct kproxy_sock *kproxy_get_next(struct kproxy_sock *kproxy)
{
	struct kproxy_net *knet = net_generic(sock_net(&kproxy->sk),
					      kproxy_net_id);

	return list_next_or_null_rcu(&knet->kproxy_list,
				     &kproxy->kproxy_list,
				     struct kproxy_sock, kproxy_list);
}

static struct kproxy_sock *kproxy_get_idx(struct seq_file *seq, loff_t pos)
{
	struct net *net = seq_file_net(seq);
	struct kproxy_net *knet = net_generic(net, kproxy_net_id);
	struct kproxy_sock *ksock;

	list_for_each_entry_rcu(ksock, &knet->kproxy_list, kproxy_list) {
		if (!pos)
			return ksock;
		--pos;
	}
	return NULL;
}

static void *kproxy_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	void *p;

	if (v == SEQ_START_TOKEN)
		p = kproxy_get_first(seq);
	else
		p = kproxy_get_next(v);
	++*pos;
	return p;
}

static void *kproxy_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(rcu)
{
	rcu_read_lock();

	if (!*pos)
		return SEQ_START_TOKEN;
	else
		return kproxy_get_idx(seq, *pos - 1);
}

static void kproxy_seq_stop(struct seq_file *seq, void *v)
	__releases(rcu)
{
	rcu_read_unlock();
}

struct kproxy_proc_proxy_state {
	struct seq_net_private p;
	int idx;
};

static int kproxy_seq_open(struct inode *inode, struct file *file)
{
	struct kproxy_seq_proxyinfo *proxyinfo = PDE_DATA(inode);

	return seq_open_net(inode, file, &proxyinfo->seq_ops,
			   sizeof(struct kproxy_proc_proxy_state));
}

static void kproxy_format_proxy_header(struct seq_file *seq)
{
	struct net *net = seq_file_net(seq);
	struct kproxy_net *knet = net_generic(net, kproxy_net_id);

	seq_printf(seq, "*** kProxy **** (%d proxies)\n",
		   knet->count);

	seq_printf(seq,
		   "%-16s %-16s %-10s %-16s %-16s %-10s %s\n",
		   "Client-RX-bytes",
		   "ClientQ",
		   "Server-TX-bytes",
		   "Server-RX-bytes",
		   "Client-TX-bytes",
		   "ServerQ",
		   "Addresses"
	);
}

static void kproxy_format_addresses(struct seq_file *seq,
				    struct sock *sk)
{
	switch (sk->sk_family) {
	case AF_INET: {
		struct inet_sock *inet = inet_sk(sk);

		seq_printf(seq, "%pI4:%u->%pI4:%u",
			   &inet->inet_saddr, ntohs(inet->inet_sport),
			   &inet->inet_daddr, ntohs(inet->inet_dport));
		break;
	}
	case AF_INET6: {
		struct inet_sock *inet = (struct inet_sock *)sk;

		seq_printf(seq, "%pI6:%u->%pI6:%u",
			   &sk->sk_v6_rcv_saddr, ntohs(inet->inet_sport),
			   &sk->sk_v6_daddr, ntohs(inet->inet_dport));
		break;
	}
	default:
		seq_puts(seq, "Unknown-family");
	}
}

static void kproxy_format_proxy(struct kproxy_sock *ksock,
				struct seq_file *seq)
{
	seq_printf(seq, "%-16llu %-16llu %-10u %-16llu %-16llu %-10u",
		   ksock->client_sock.stats.rx_bytes,
		   ksock->server_sock.stats.tx_bytes,
		   kproxy_enqueued(&ksock->client_sock),
		   ksock->server_sock.stats.rx_bytes,
		   ksock->client_sock.stats.tx_bytes,
		   kproxy_enqueued(&ksock->server_sock));

	kproxy_format_addresses(seq, ksock->client_sock.sock->sk);
	seq_puts(seq, " ");
	kproxy_format_addresses(seq, ksock->server_sock.sock->sk);

	seq_puts(seq, "\n");
}

static int kproxy_seq_show(struct seq_file *seq, void *v)
{
	struct kproxy_proc_proxy_state *proxy_state;

	proxy_state = seq->private;
	if (v == SEQ_START_TOKEN) {
		proxy_state->idx = 0;
		kproxy_format_proxy_header(seq);
	} else {
		kproxy_format_proxy(v, seq);
		proxy_state->idx++;
	}
	return 0;
}

static const struct file_operations kproxy_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= kproxy_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_net,
};

static struct kproxy_seq_proxyinfo kproxy_seq_proxyinfo = {
	.name		= "kproxy",
	.seq_fops	= &kproxy_seq_fops,
	.seq_ops	= {
		.show	= kproxy_seq_show,
		.start	= kproxy_seq_start,
		.next	= kproxy_seq_next,
		.stop	= kproxy_seq_stop,
	}
};

static int kproxy_proc_register(struct net *net,
				struct kproxy_seq_proxyinfo *proxyinfo)
{
	struct proc_dir_entry *p;
	int rc = 0;

	p = proc_create_data(proxyinfo->name, 0444, net->proc_net,
			     proxyinfo->seq_fops, proxyinfo);
	if (!p)
		rc = -ENOMEM;
	return rc;
}
EXPORT_SYMBOL(kproxy_proc_register);

static void kproxy_proc_unregister(struct net *net,
				   struct kproxy_seq_proxyinfo *proxyinfo)
{
	remove_proc_entry(proxyinfo->name, net->proc_net);
}
EXPORT_SYMBOL(kproxy_proc_unregister);

static int kproxy_proc_init_net(struct net *net)
{
	int err;

	err = kproxy_proc_register(net, &kproxy_seq_proxyinfo);
	if (err)
		return err;

	return 0;
}

static void kproxy_proc_exit_net(struct net *net)
{
	kproxy_proc_unregister(net, &kproxy_seq_proxyinfo);
}

static struct pernet_operations kproxy_net_ops = {
	.init = kproxy_proc_init_net,
	.exit = kproxy_proc_exit_net,
};

int __init kproxy_proc_init(void)
{
	return register_pernet_subsys(&kproxy_net_ops);
}

void __exit kproxy_proc_exit(void)
{
	unregister_pernet_subsys(&kproxy_net_ops);
}

#endif /* CONFIG_PROC_FS */
