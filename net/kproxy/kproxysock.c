/*
 * Kernel Proxy
 *
 * Copyright (c) 2017 Tom Herbert <tom@quantonium.net>
 * Copyright (c) 2017 John Fastabend <john.fastabend@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/errno.h>
#include <linux/file.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/bpf.h>
#include <net/strparser.h>
#include <net/kproxy.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <uapi/linux/kproxy.h>

unsigned int kproxy_net_id;

static struct kproxy_peers *kproxy_peers_alloc(unsigned int max_peers)
{
	unsigned int size = sizeof(struct kproxy_peers) +
				sizeof(struct kproxy_psock *) * max_peers;
	struct kproxy_peers *peers = kzalloc(size, GFP_ATOMIC);

	if (!peers)
		return NULL;

	peers->socks_index = kcalloc(max_peers, sizeof(int), GFP_ATOMIC);
	if (!peers->socks_index) {
		kfree(peers);
		return NULL;
	}

	peers->max_peers = max_peers;
	return peers;
}

static int kproxy_peers_max(struct kproxy_psock *psock)
{
	return psock->peers->max_peers;
}

static int kproxy_mux_func(struct kproxy_psock *psock, struct sk_buff *skb)
{
	struct bpf_prog *prog = psock->bpf_mux;
	int index;

	if (!prog) {
		index = 0;
	} else {
		/* Attach socket reference for BPF program inspection if
		 * needed.
		 */
		WARN_ON(skb->sk);
		skb->sk = psock->sock;
		index = (*prog->bpf_func)(skb, prog->insnsi);
		skb->sk = NULL;
	}

	return index;
}

static struct kproxy_psock *kproxy_peers_get(struct kproxy_psock *psock,
					     struct sk_buff *skb)
{
	struct kproxy_peers *peers = psock->peers;
	unsigned int index;

	index = kproxy_mux_func(psock, skb);
	if (unlikely(index < 0 || index >= peers->max_peers))
		return NULL;

	return rcu_dereference(peers->socks[index]);
}

static struct kproxy_psock *__kproxy_peers_get(struct kproxy_psock *psock,
					       unsigned int index)
{
	struct kproxy_peers *peers = psock->peers;

	if (unlikely(index < 0 || index >= peers->max_peers))
		return NULL;

	return rcu_dereference(peers->socks[index]);
}

static void kproxy_report_sk_error(struct kproxy_psock *psock, int err,
				   bool hard_report)
{
	struct sock *sk = psock->sock;

	/* Check if we still have stuff in receive queue that we might be
	 * able to finish sending on the peer socket. Hold off on reporting
	 * the error if there is data queued and not a hard error.
	 */
	if (hard_report || !kproxy_enqueued(psock)) {
		sk->sk_err = err;
		sk->sk_error_report(sk);
	} else {
		psock->deferred_err = err;
	}
}

static void kproxy_report_deferred_error(struct kproxy_psock *psock)
{
	struct sock *sk = psock->sock;

	sk->sk_err = psock->deferred_err;
	sk->sk_error_report(sk);
}

static int kproxy_unjoin_sock(struct sock *sock);

static void kproxy_state_change(struct sock *sk)
{
	/* Allowing transitions into established an syn_recv states allows
	 * for early binding sockets to a kproxy object before the connection
	 * is established. All other transitions indicate the connection is
	 * being torn down so tear down the kproxy socket.
	 */
	switch (sk->sk_state) {
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		break;
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	case TCP_LISTEN:
		break;
	case TCP_CLOSE:
		kproxy_unjoin_sock(sk);
		break;
	default:
		kproxy_report_sk_error(kproxy_psock_sk(sk), EPIPE, false);
		break;
	}
}

static void kproxy_tx_work(struct work_struct *w);

void schedule_writer(struct kproxy_psock *psock)
{
	schedule_work(&psock->tx_work);
}

/* Post skb to peers proxy queue */
static int kproxy_recv(struct kproxy_psock *psock, struct sk_buff *skb,
		       unsigned int offset, size_t len)
{
	WARN_ON(len != skb->len - offset);

	/* Always clone since we're consuming whole skbuf */
	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb) {
		kfree_skb(skb);
		return -ENOMEM;
	}

	if (unlikely(offset)) {
		/* Don't expect offsets to be present */
		if (!pskb_pull(skb, offset)) {
			kfree_skb(skb);
			return 0;
		}
	}

	psock->produced += skb->len;
	psock->stats.rx_bytes += skb->len;

	skb_queue_tail(&psock->rxqueue, skb);

	/* Check limit of queued data */
	if (kproxy_enqueued(psock) > psock->queue_hiwat)
		return -ENOMEM;

	return 0;
}

static int kproxy_tx_writer(struct kproxy_psock *peer)
{
	schedule_writer(peer);
	return 0;
}

static void kproxy_read_sock_strparser(struct strparser *strp,
				       struct sk_buff *skb)
{
	struct kproxy_psock *psock = container_of(strp,
						  struct kproxy_psock, strp);
	struct kproxy_psock *peer;
	int err;

	rcu_read_lock();
	peer = kproxy_peers_get(psock, skb);
	if (unlikely(!peer)) {
		kfree_skb(skb);
		goto out;
	}

	if (peer == psock) { /* catch this case we can't take lock on send so need a work queue */
		WARN_ON(1);
		kfree_skb(skb);
		goto out;
	}

	/* Push a message to peers queue and pause the parser if the peer
	 * exceedes the high water mark. Note because we must consume
	 * the skb here even if the water mark is exceeded we push the
	 * skb on the queue. So it is not a hard water mark in that
	 * sense.
	 */
	err = kproxy_recv(peer, skb, 0, skb->len);
	if (err) {
		strp_pause(&psock->strp);
		goto out;
	}

	/* Probably got some data, kick writer side */
	if (likely(!skb_queue_empty(&peer->rxqueue)))
		kproxy_tx_writer(peer);

out:
	rcu_read_unlock();
}

/* Called with lock held on socket */
static void kproxy_data_ready(struct sock *sk)
{
	struct kproxy_psock *psock;

	read_lock_bh(&sk->sk_callback_lock);

	psock = kproxy_psock_sk(sk);
	if (likely(psock))
		strp_data_ready(&psock->strp);

	read_unlock_bh(&sk->sk_callback_lock);
}

static void check_for_rx_wakeup(struct kproxy_psock *psock,
				int orig_consumed)
{
	int started_with = psock->produced - orig_consumed;

	/* Check if we fell below low watermark with new data that
	 * was consumed and if we have any paused peers unpause them.
	 */
	if (started_with > psock->queue_lowat &&
	    kproxy_enqueued(psock) <= psock->queue_lowat) {
		int max_peers = kproxy_peers_max(psock);
		int i;

		for (i = 0; i < max_peers; i++) {
			struct kproxy_psock *p = __kproxy_peers_get(psock, i);

			if (!p)
				continue;
			if (p->strp.rx_paused)
				strp_unpause(&p->strp);
		}
	}
}

static void kproxy_tx_work(struct work_struct *w)
{
	struct kproxy_psock *psock;
	struct sk_buff *skb;
	int orig_consumed;
	int sent, n;

 	psock = container_of(w, struct kproxy_psock, tx_work);
	if (unlikely(psock->tx_stopped))
		return;

	if (unlikely(!psock->sock->sk_socket))
		return;

	orig_consumed = psock->consumed;

	if (psock->save_skb) {
		skb = psock->save_skb;
		sent = psock->save_sent;
		psock->save_skb = NULL;
		goto start;
	}

	while ((skb = skb_dequeue(&psock->rxqueue))) {
		sent = 0;
start:
		do {
			n = skb_send_sock(skb, psock->sock->sk_socket, sent);
			if (n <= 0) {
				if (n == -EAGAIN) {
					/* Save state to try again when
					 * there's write space on the
					 * socket.
					 */
					psock->save_skb = skb;
					psock->save_sent = sent;
					goto out;
				}

				/* Got a hard error or socket had
				 * been closed somehow. Report this
				 * on the transport socket.
				 */
				kproxy_report_sk_error(psock,
						       n ? -n : EPIPE, true);
				psock->tx_stopped = 1;
				goto out;
			}
			sent += n;
			psock->consumed += n;
			psock->stats.tx_bytes += n;
		} while (sent < skb->len);
	}

	if (unlikely(psock->deferred_err)) {
		int max_peers = kproxy_peers_max(psock);
		int i;

		/* An error had been reported and not the queue has been
		 * drained, go ahead and report the errout.
		 */
		for (i = 0; i < max_peers; i++) {
			struct kproxy_psock *p = __kproxy_peers_get(psock, i);

			if (!p)
				continue;
			kproxy_report_deferred_error(p);
		}
	}
out:
	check_for_rx_wakeup(psock, orig_consumed);
}

static void kproxy_write_space(struct sock *sk)
{
	struct kproxy_psock *psock = kproxy_psock_sk(sk);

	schedule_writer(psock);
}

static void kproxy_stop_sock(struct kproxy_psock *psock)
{
	struct sock *sk = psock->sock;

	/* Set up callbacks */
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_data_ready = psock->save_data_ready;
	sk->sk_write_space = psock->save_write_space;
	sk->sk_state_change = psock->save_state_change;
	sk->sk_user_data = NULL;
	strp_stop(&psock->strp);
	write_unlock_bh(&sk->sk_callback_lock);

	/* Make sure tx_stopped is committed */
	smp_mb();

	cancel_work_sync(&psock->tx_work);
}

static void kproxy_destroy_psock(struct rcu_head *rcu)
{
	struct kproxy_psock *psock = container_of(rcu,
						  struct kproxy_psock, rcu);

	kproxy_stop_sock(psock);
	__skb_queue_purge(&psock->rxqueue); /* tbd something better */
	strp_done(&psock->strp);
	sock_put(psock->sock);
	//fput(psock->sock->file);
	kfree(psock);
}

struct kproxy_psock *kproxy_lookup_psock(struct kproxy_sock *ksock, int fd)
{
	struct kproxy_psock *psock;

	list_for_each_entry(psock, &ksock->server_sock, list) {
		if (psock->fd == fd)
			return psock;
	}

	return NULL;
}

struct kproxy_psock *kproxy_lookup_psock_by_sock(struct kproxy_sock *ksock,
						 struct sock *sock)
{
	struct kproxy_psock *psock;

	list_for_each_entry(psock, &ksock->server_sock, list) {
		if (psock->sock == sock)
			return psock;
	}

	return NULL;
}

static int kproxy_release_proxy(struct kproxy_psock *psock)
{
	struct kproxy_psock *old_psock;
	int index = psock->index;

	old_psock = rcu_dereference(psock->peers->socks[index]);

	/* should have already been checked can remove .... */
	if (old_psock != psock) {
		WARN_ON(1);
		return -EINVAL;
	}

	rcu_assign_pointer(psock->peers->socks[index], NULL);

	old_psock->refcnt--;
	if (!old_psock->refcnt) {
		list_del_rcu(&old_psock->list);
		call_rcu(&old_psock->rcu, kproxy_destroy_psock);
	}
	return 0;
}

static int kproxy_unjoin_sock(struct sock *sk)
{
	struct kproxy_psock *psock = kproxy_psock_sk(sk);
	struct kproxy_sock *ksock = psock->ksock;
	int err;

	lock_sock(&ksock->sk);
	err = kproxy_release_proxy(psock);
	WARN_ON(err); /* testing: warning indicates we missed a check above */
	release_sock(&ksock->sk);
	return err;
}

static int kproxy_unjoin(struct socket *kproxy, struct kproxy_unjoin *info)
{
	struct kproxy_sock *ksock = kproxy_sk(kproxy->sk);
	struct kproxy_psock *psock;
	int err = -EINVAL;

	lock_sock(kproxy->sk);

	/* Each endpoint must exist in ksock */
	psock = kproxy_lookup_psock(ksock, info->sock_fd);
	if (!psock)
		goto out;

	err = kproxy_release_proxy(psock);
	WARN_ON(err); /* testing: warning indicates we missed a check above */
out:
	release_sock(kproxy->sk);
	return err;
}

static int kproxy_release(struct socket *sock)
{
	struct kproxy_net *knet = net_generic(sock_net(sock->sk),
					      kproxy_net_id);
	struct kproxy_sock *ksock = kproxy_sk(sock->sk);
	struct kproxy_psock *psock, *tmp;
	struct sock *sk = sock->sk;
	int err;

	if (!sk)
		goto out;

	sock_orphan(sk);
	list_for_each_entry_safe(psock, tmp, &ksock->server_sock, list) {
		err = kproxy_release_proxy(psock);
		WARN_ON(err);
	}

	if (ksock->peers) {
		kfree(ksock->peers->socks_index);
		kfree(ksock->peers);
	}

	bpf_prog_put(ksock->bpf_parse);
	if (ksock->bpf_mux)
		bpf_prog_put(ksock->bpf_mux);

	mutex_lock(&knet->mutex);
	list_del_rcu(&ksock->list);
	knet->count--;
	mutex_unlock(&knet->mutex);

	sk->sk_prot->unhash(sk);

	sock->sk = NULL;
	sock_put(sk);
out:
	return 0;
}

static int kproxy_parse_func_strparser(struct strparser *strp,
				       struct sk_buff *skb)
{
	struct kproxy_psock *psock = container_of(strp,
						  struct kproxy_psock, strp);
	struct bpf_prog *prog = psock->bpf_parse;

	return (*prog->bpf_func)(skb, prog->insnsi);
}

static int kproxy_read_sock_done(struct strparser *strp, int err)
{
	return err;
}

static int kproxy_init_sock(struct kproxy_psock *psock,
			    struct sock *sock)
{
	struct strp_callbacks cb;
	int err;

	cb.rcv_msg = kproxy_read_sock_strparser;
	cb.abort_parser = NULL;
	cb.parse_msg = kproxy_parse_func_strparser;
	cb.read_sock_done = kproxy_read_sock_done;

	skb_queue_head_init(&psock->rxqueue);
	INIT_WORK(&psock->tx_work, kproxy_tx_work);

	psock->sock = sock;
	psock->queue_hiwat = 1000000;
	psock->queue_lowat = 1000000;

	err = strp_init(&psock->strp, sock, &cb);
	if (err) {
		WARN_ON(1);
		return -EINVAL;
	}
	sock_hold(sock);
	return 0;
}

static void kproxy_start_sock(struct kproxy_psock *psock)
{
	struct sock *sk = psock->sock;

	/* Set up callbacks */
	write_lock_bh(&sk->sk_callback_lock);
	psock->save_data_ready = sk->sk_data_ready;
	psock->save_write_space = sk->sk_write_space;
	psock->save_state_change = sk->sk_state_change;
	sk->sk_user_data = psock;
	sk->sk_data_ready = kproxy_data_ready;
	sk->sk_write_space = kproxy_write_space;
	sk->sk_state_change = kproxy_state_change;
	write_unlock_bh(&sk->sk_callback_lock);
}

static struct kproxy_psock *kproxy_init_psock(struct sock *sock,
					      struct kproxy_sock *ksock)
{
	struct kproxy_psock *psock;
	int err;

	if (!ksock || !ksock->peers) {
		WARN_ON(1);
		return ERR_PTR(-EINVAL);
	}

	psock = kmalloc(sizeof(*psock), GFP_KERNEL);
	if (!psock)
		return ERR_PTR(-ENOMEM);

	memset(psock, 0, sizeof(*psock));
	psock->refcnt = 0;
	psock->bpf_mux = ksock->bpf_mux;
	psock->bpf_parse = ksock->bpf_parse;
	psock->peers = ksock->peers;
	psock->index = ksock->peers->max_peers;
	psock->ksock = ksock;

	err = kproxy_init_sock(psock, sock);
	if (err) {
		kfree(psock);
		return ERR_PTR(err);
	}

	return psock;
}

static int kproxy_join_psock(struct kproxy_psock *psock, int index)
{
	struct kproxy_psock *old_sock;
	struct kproxy_peers *peers = psock->peers;

	if (unlikely(index >= peers->max_peers))
		return -ENOMEM;

	old_sock = rcu_dereference(peers->socks[index]);

	psock->refcnt++;
	psock->index = index;
	rcu_assign_pointer(peers->socks[index], psock);

	if (old_sock) {
		old_sock->refcnt--;
		if (!old_sock->refcnt) {
			list_del_rcu(&old_sock->list);
			call_rcu(&old_sock->rcu, kproxy_destroy_psock);
		}
	}

	return 0;
}

static int kproxy_join_sockets(struct socket *kproxy,
			       struct sock *sock, int index)
{
	struct kproxy_sock *ksock = kproxy_sk(kproxy->sk);
	struct kproxy_psock *psock;
	int err;

	psock = kproxy_lookup_psock_by_sock(ksock, sock);
	if (psock)
		return -EINVAL;

	if (!ksock->attached)
		return -EINVAL;

	if (!sock) {// || !sock->ops->read_sock) {
		WARN_ON(1); // some invalid kernel hook
		return -EINVAL;
	}

	psock = kproxy_init_psock(sock, ksock);
	if (IS_ERR(psock))
		return PTR_ERR(psock);

	lock_sock(kproxy->sk);
	err = kproxy_join_psock(psock, index);
	if (err)
		goto out;

	/* Start the proxy */
	list_add_rcu(&psock->list, &ksock->server_sock);
	kproxy_start_sock(psock);
out:
	release_sock(kproxy->sk);
	return err;
}

static int kproxy_join(struct socket *kproxy, struct kproxy_join *info)
{
	struct kproxy_sock *ksock = kproxy_sk(kproxy->sk);
	struct kproxy_psock *psock;
	struct socket *sock;
	int err;

	if (!ksock->attached)
		return -EINVAL;

	sock = sockfd_lookup(info->sock_fd, &err);
	if (!sock)
		return -EINVAL;

	psock = kproxy_lookup_psock_by_sock(ksock, sock->sk);
	if (psock)
		goto out;

	psock = kproxy_init_psock(sock->sk, ksock);
	if (IS_ERR(psock))
		goto out;

	lock_sock(sock->sk);
	err = kproxy_join_psock(psock, info->index);
	if (err)
		goto out_release;

	list_add_rcu(&psock->list, &ksock->server_sock);
	kproxy_start_sock(psock);
out_release:
	release_sock(sock->sk);
out:
	fput(sock->file);
	return err;
}

int kproxy_bind_bpf(struct socket *kproxy, struct sock *s, int i, u64 flags)
{
	return  kproxy_join_sockets(kproxy, s, i);
}
EXPORT_SYMBOL(kproxy_bind_bpf);

static int kproxy_attach(struct socket *sock, struct kproxy_attach *info)
{
	struct kproxy_sock *ksock = kproxy_sk(sock->sk);
	struct bpf_prog *parse, *mux = NULL;

	ksock->bpf_fd_parse = info->bpf_fd_parse;
	ksock->bpf_fd_mux = info->bpf_fd_mux; 

	parse = bpf_prog_get_type(ksock->bpf_fd_parse,
				  BPF_PROG_TYPE_SOCKET_FILTER);
	if (IS_ERR(parse))
		return PTR_ERR(parse);

	if (ksock->bpf_fd_mux) {
		mux = bpf_prog_get_type(ksock->bpf_fd_mux,
					BPF_PROG_TYPE_SOCKET_FILTER);
		if (IS_ERR(mux)) {
			bpf_prog_put(parse);
			return PTR_ERR(mux);;
		}
	}

	ksock->bpf_parse = parse;
	ksock->bpf_mux = mux;

	ksock->max_peers = info->max_peers;
	ksock->peers = kproxy_peers_alloc(info->max_peers);
	if (!ksock->peers) {
		bpf_prog_put(mux);
		bpf_prog_put(parse);
		return -ENOMEM;
	}

	ksock->attached = true;
	return 0;
}

static int kproxy_ioctl(struct socket *sock, unsigned int cmd,
			unsigned long arg)
{
	int err;

	switch (cmd) {
	case SIOCKPROXYATTACH: {
		struct kproxy_attach info;

		if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
			return -EFAULT;

		err = kproxy_attach(sock, &info);

		break;
	}

	case SIOCKPROXYJOIN: {
		struct kproxy_join info;

		if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
			return -EFAULT;

		err = kproxy_join(sock, &info);

		break;
	}

	case SIOCKPROXYUNJOIN: {
		struct kproxy_unjoin info;

		if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
			return -EFAULT;

		err = kproxy_unjoin(sock, &info);

		break;
	}

	default:
		err = -ENOIOCTLCMD;
		break;
	}

	return err;
}

static const struct proto_ops kproxy_dgram_ops = {
	.family =	PF_KPROXY,
	.owner =	THIS_MODULE,
	.release =	kproxy_release,
	.bind =		sock_no_bind,
	.connect =	sock_no_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	sock_no_getname,
	.poll =		sock_no_poll,
	.ioctl =	kproxy_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt =	sock_no_setsockopt,
	.getsockopt =	sock_no_getsockopt,
	.sendmsg =	sock_no_sendmsg,
	.recvmsg =	sock_no_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
};

int kproxy_hash_sk(struct sock *sk)
{
	struct kproxy_hashinfo *h = sk->sk_prot->h.kproxy_hash;
	struct hlist_head *head;

	head = &h->ht;

	write_lock_bh(&h->lock);
	sk_add_node(sk, head);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	write_unlock_bh(&h->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(kproxy_hash_sk);

void kproxy_unhash_sk(struct sock *sk)
{
	struct kproxy_hashinfo *h = sk->sk_prot->h.kproxy_hash;

	write_lock_bh(&h->lock);
	if (sk_del_node_init(sk))
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	write_unlock_bh(&h->lock);
}

static struct kproxy_hashinfo kproxy_hashinfo = {
	.lock = __RW_LOCK_UNLOCKED(kproxy_hashinfo.lock),
};

struct proto kproxy_proto = {
	.name   = "KPROXY",
	.owner  = THIS_MODULE,
	.hash   = kproxy_hash_sk,
	.unhash = kproxy_unhash_sk,
	.obj_size = sizeof(struct kproxy_sock),
	.h.kproxy_hash = &kproxy_hashinfo,
};
EXPORT_SYMBOL_GPL(kproxy_proto);

/* Create proto operation for kcm sockets */
static int kproxy_create(struct net *net, struct socket *sock,
			 int protocol, int kern)
{
	struct kproxy_net *knet = net_generic(net, kproxy_net_id);
	struct sock *sk;
	struct kproxy_sock *ksock;

	switch (sock->type) {
	case SOCK_DGRAM:
		sock->ops = &kproxy_dgram_ops;
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	sk = sk_alloc(net, PF_KPROXY, GFP_KERNEL, &kproxy_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	sk->sk_prot->hash(sk);

	ksock = kproxy_sk(sk);
	INIT_LIST_HEAD_RCU(&ksock->server_sock);

	mutex_lock(&knet->mutex);
	list_add_rcu(&ksock->list, &knet->kproxy_list);
	ksock->attached = false;
	knet->count++;
	mutex_unlock(&knet->mutex);

	return 0;
}

static struct net_proto_family kproxy_family_ops = {
	.family = PF_KPROXY,
	.create = kproxy_create,
	.owner  = THIS_MODULE,
};

static __net_init int kproxy_init_net(struct net *net)
{
	struct kproxy_net *knet = net_generic(net, kproxy_net_id);

	INIT_LIST_HEAD_RCU(&knet->kproxy_list);
	mutex_init(&knet->mutex);

	return 0;
}

static __net_exit void kproxy_exit_net(struct net *net)
{
	struct kproxy_net *knet = net_generic(net, kproxy_net_id);

	/* All kProxy sockets should be closed at this point */
	WARN_ON(!list_empty(&knet->kproxy_list));
}

static struct pernet_operations kproxy_net_ops = {
	.init = kproxy_init_net,
	.exit = kproxy_exit_net,
	.id   = &kproxy_net_id,
	.size = sizeof(struct kproxy_net),
};

static int __init kproxy_init(void)
{
	int err = -ENOMEM;

	err = proto_register(&kproxy_proto, 1);
	if (err)
		goto fail;

	err = sock_register(&kproxy_family_ops);
	if (err)
		goto sock_register_fail;

	err = register_pernet_device(&kproxy_net_ops);
	if (err)
		goto net_ops_fail;

	err = kproxy_proc_init();
	if (err)
		goto proc_init_fail;

	return 0;

proc_init_fail:
	unregister_pernet_device(&kproxy_net_ops);
net_ops_fail:
	sock_unregister(PF_KPROXY);
sock_register_fail:
	proto_unregister(&kproxy_proto);

fail:

	return err;
}

static void __exit kproxy_exit(void)
{
	kproxy_proc_exit();
	unregister_pernet_device(&kproxy_net_ops);
	sock_unregister(PF_KPROXY);
	proto_unregister(&kproxy_proto);
}

module_init(kproxy_init);
module_exit(kproxy_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_KPROXY);
