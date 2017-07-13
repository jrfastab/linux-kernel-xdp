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

	peers->socks_index = kzalloc(sizeof(int) * max_peers, GFP_ATOMIC);
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
		index = (*prog->bpf_func)(skb, prog->insnsi);
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

static inline struct kproxy_sock *kproxy_sk(const struct sock *sk)
{
	return (struct kproxy_sock *)sk;
}

static inline struct kproxy_psock *kproxy_psock_sk(const struct sock *sk)
{
	return (struct kproxy_psock *)sk->sk_user_data;
}

static void kproxy_report_sk_error(struct kproxy_psock *psock, int err,
				   bool hard_report)
{
	struct sock *sk = psock->sock->sk;

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
	struct sock *sk = psock->sock->sk;

	sk->sk_err = psock->deferred_err;
	sk->sk_error_report(sk);
}

static void kproxy_state_change(struct sock *sk)
{
	kproxy_report_sk_error(kproxy_psock_sk(sk), EPIPE, false);
}

static void kproxy_tx_work(struct kproxy_psock *psock);

void schedule_writer(struct kproxy_psock *psock)
{
	kproxy_tx_work(psock);
}

/* Post skb to peers proxy queue */
static int kproxy_recv(struct kproxy_psock *psock, struct sk_buff *skb, unsigned int offset, size_t len)
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
	struct kproxy_psock *psock = container_of(strp, struct kproxy_psock, strp);
	struct kproxy_psock *peer;
	int err;

	rcu_read_lock();
	peer = kproxy_peers_get(psock, skb);
	if (unlikely(!peer)) {
		kfree_skb(skb);
		return;
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
	return;
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

static void kproxy_tx_work(struct kproxy_psock *psock)
{
	int sent, n;
	struct sk_buff *skb;
	int orig_consumed;

	if (unlikely(psock->tx_stopped))
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
			n = skb_send_sock(skb, psock->sock, sent);
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
	struct sock *sk = psock->sock->sk;

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
}

static void kproxy_destroy_psock(struct rcu_head *rcu)
{
	struct kproxy_psock *psock = container_of(rcu, struct kproxy_psock, rcu);

	printk("%s: fd:%i: stop strp destroy psock rcu\n", __func__, psock->fd);
	kproxy_stop_sock(psock);
	__skb_queue_purge(&psock->rxqueue); /* tbd something better */
	strp_done(&psock->strp);
	sock_put(psock->sock->sk);
	fput(psock->sock->file);

	bpf_prog_put(psock->bpf_prog);
	if (psock->bpf_mux)
		bpf_prog_put(psock->bpf_mux);

	kfree(psock->peers->socks_index);
	kfree(psock->peers);
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

static int kproxy_release_proxy(struct kproxy_psock *client, int c_i,
				 struct kproxy_psock *server, int s_i)
{
	struct kproxy_psock *old_client, *old_server;

	/* Now to unbind them remove the peer links and decrement
	 * the refcnt. If refcnt hits zero we can free the resource.
	 *
	 * For this we will accept hints in the info struct on where
	 * to look but if no hint is provided we search the peers list.
	 */
	old_client = rcu_dereference(client->peers->socks[c_i]);
	old_server = rcu_dereference(server->peers->socks[s_i]);

	/* should have already been checked can remove .... */
	if (old_server != client) {
		WARN_ON(1);
		return -EINVAL;
	}

	if (old_client != server) {
		WARN_ON(1);
		return -EINVAL;
	}

	rcu_assign_pointer(client->peers->socks[c_i], NULL);
	rcu_assign_pointer(server->peers->socks[s_i], NULL);

	old_client->refcnt--;
	if (!old_client->refcnt) {
		printk("old_client %i destroyed\n", old_client->fd);
		list_del_rcu(&old_client->list);
		call_rcu(&old_client->rcu, kproxy_destroy_psock);
	}

	old_server->refcnt--;
	if (!old_server->refcnt) {
		printk("old_server %i destroyed\n", old_server->fd);
		list_del_rcu(&old_server->list);
		call_rcu(&old_server->rcu, kproxy_destroy_psock);
	}
	return 0;
}

static int kproxy_unjoin(struct socket *sock, struct kproxy_unjoin *info)
{
	struct kproxy_sock *ksock = kproxy_sk(sock->sk);
	struct kproxy_psock *client, *server;
	int err = -EINVAL, c_i = 0, s_i = 0;
	struct kproxy_peers *cpeers;

	lock_sock(sock->sk);

	/* Each endpoint must exist in ksock */
	client = kproxy_lookup_psock(ksock, info->client_fd);
	if (!client)
		goto out;

	server = kproxy_lookup_psock(ksock, info->server_fd);
	if (!server)
		goto out;

	cpeers = client->peers;
	for (c_i = 0; c_i < cpeers->max_peers; c_i++) {
		if (cpeers->socks[c_i] == server) {
			s_i = cpeers->socks_index[c_i];
			break;
		}
	}

	if (c_i == cpeers->max_peers) {
		WARN_ON(1);
		goto out;
	}

	printk("%s: client %i c_i %i server %i s_i %i\n",
		__func__, client->fd, c_i, server->fd, s_i);

	err = kproxy_release_proxy(client, c_i, server, s_i);
	WARN_ON(err); /* testing: warning indicates we missed a check above */

out:
	release_sock(sock->sk);
	return err;
}

static int kproxy_release(struct socket *sock)
{
	struct kproxy_net *knet = net_generic(sock_net(sock->sk),
					      kproxy_net_id);
	struct kproxy_sock *ksock = kproxy_sk(sock->sk);
	struct kproxy_psock *psock, *tmp;
	struct sock *sk = sock->sk;

	if (!sk)
		goto out;

	sock_orphan(sk);
	list_for_each_entry_safe(psock, tmp, &ksock->server_sock, list) {
		struct kproxy_peers *peers = psock->peers; 
		struct kproxy_psock *peer;
		int i, err, peer_i;

		for (i = 0; i < peers->max_peers; i++) {
			peer = peers->socks[i];

			if (!peer)
				continue;

			peer_i = peers->socks_index[i];
			printk("%s: psock %i i %i peer %i peer_i %i\n", __func__, psock->fd, i, peer->fd, peer_i);
			err = kproxy_release_proxy(psock, i, peer, peer_i);
			WARN_ON(err);
		}
	}

	mutex_lock(&knet->mutex);
	list_del_rcu(&ksock->list);
	knet->count--;
	mutex_unlock(&knet->mutex);

	sock->sk = NULL;
	sock_put(sk);

out:
	return 0;
}

static int kproxy_parse_func_strparser(struct strparser *strp, struct sk_buff *skb)
{
	struct kproxy_psock *psock = container_of(strp, struct kproxy_psock, strp);
	struct bpf_prog *prog = psock->bpf_prog;

	return (*prog->bpf_func)(skb, prog->insnsi);
}

static int kproxy_read_sock_done(struct strparser *strp, int err)
{
	return err;
}

static void kproxy_init_sock(struct kproxy_psock *psock,
			     struct socket *sock)
{
	struct strp_callbacks cb;
	int err;

	cb.rcv_msg = kproxy_read_sock_strparser;
	cb.abort_parser = NULL;
	cb.parse_msg = kproxy_parse_func_strparser;
	cb.read_sock_done = kproxy_read_sock_done;

	skb_queue_head_init(&psock->rxqueue);

	psock->sock = sock;
	psock->queue_hiwat = 1000000;
	psock->queue_lowat = 1000000;

	err = strp_init(&psock->strp, psock->sock->sk, &cb);
	if (err) {
		WARN_ON(1);
		return;
	}
	sock_hold(sock->sk);
}

static void kproxy_start_sock(struct kproxy_psock *psock)
{
	struct sock *sk = psock->sock->sk;

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

static struct kproxy_psock *kproxy_init_psock(int fd,
					      int bpf_parse, int bpf_mux,
					      int max_peers)
{
	struct bpf_prog *prog, *mux_prog;
	struct kproxy_psock *psock;
	struct socket *sock;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return ERR_PTR(err);

	if (!sock->ops->read_sock)
		return ERR_PTR(-EINVAL);

	prog = bpf_prog_get_type(bpf_parse, BPF_PROG_TYPE_SOCKET_FILTER);
	if (IS_ERR(prog)) {
		err = PTR_ERR(prog);
		return ERR_PTR(err);
	}

	if (bpf_mux) {
		mux_prog = bpf_prog_get_type(bpf_mux, BPF_PROG_TYPE_SOCKET_FILTER);
		if (IS_ERR(mux_prog)) {
			err = PTR_ERR(mux_prog);
			bpf_prog_put(prog);
			return ERR_PTR(err);
		}
	}

	err = -ENOMEM;
	psock = kmalloc(sizeof(*psock), GFP_KERNEL);
	if (!psock)
		goto alloc_err;

	memset(psock, 0, sizeof(*psock));
	psock->fd = fd;
	psock->refcnt = 0;
	psock->bpf_mux = mux_prog;
	psock->bpf_prog = prog;

	psock->peers = kproxy_peers_alloc(max_peers);
	if (!psock->peers)
		goto peers_err;

	kproxy_init_sock(psock, sock);
	return psock;

peers_err:
	kfree(psock);
alloc_err:
	fput(sock->file);
	if (mux_prog)
		bpf_prog_put(mux_prog);
	bpf_prog_put(prog);
	return ERR_PTR(err);
}

static int kproxy_join_psock(struct kproxy_psock *client, int c_i,
			     struct kproxy_psock *server, int s_i)
{
	struct kproxy_psock *old_sock_c, *old_sock_s;
	struct kproxy_peers *c = client->peers;
	struct kproxy_peers *s = server->peers;

	if (unlikely(c_i >= c->max_peers))
		return -ENOMEM;

	if (unlikely(s_i >= s->max_peers))
		return -ENOMEM;

	old_sock_c = rcu_dereference(c->socks[c_i]);
	old_sock_s = rcu_dereference(s->socks[s_i]);

	server->refcnt++;
	client->refcnt++;

	rcu_assign_pointer(c->socks[c_i], server);
	rcu_assign_pointer(s->socks[s_i], client);
	c->socks_index[c_i] = s_i;
	s->socks_index[s_i] = c_i;

#ifdef DEBUG
	printk("%s: sock %i c->socks_index[%i] = %i:%i\n", __func__, client->fd, c_i, server->fd, s_i);
	printk("%s: sock %i s->socks_index[%i] = %i:%i\n", __func__, server->fd, s_i, client->fd, c_i);
#endif

	if (old_sock_c) {
		old_sock_c->refcnt--;
		if (!old_sock_c->refcnt) {
			list_del_rcu(&old_sock_c->list);
			call_rcu(&old_sock_c->rcu, kproxy_destroy_psock);
		}
	}
	if (old_sock_s) {
		old_sock_s->refcnt--;
		if (!old_sock_s->refcnt) {
			list_del_rcu(&old_sock_s->list);
			call_rcu(&old_sock_s->rcu, kproxy_destroy_psock);
		}
	}

	return 0;
}

static int kproxy_join(struct socket *sock, struct kproxy_join *info)
{
	struct kproxy_sock *ksock = kproxy_sk(sock->sk);
	struct kproxy_psock *client_sock, *server_sock;
	bool new_client = false, new_server = false;
	int err;

	client_sock = kproxy_lookup_psock(ksock, info->client_fd);
	if (!client_sock) {
		new_client = true;
		client_sock = kproxy_init_psock(info->client_fd,
						info->bpf_fd_parse_client,
						info->bpf_fd_mux,
						info->max_peers);
	}

	server_sock = kproxy_lookup_psock(ksock, info->server_fd);
	if (!server_sock) {
		new_server = true;
		server_sock = kproxy_init_psock(info->server_fd,
						info->bpf_fd_parse_server,
						info->bpf_fd_mux,
						info->max_peers);
	}

	if (!client_sock || !server_sock)
		return -EINVAL;

	lock_sock(sock->sk);
	err = kproxy_join_psock(client_sock, info->client_index,
				server_sock, info->server_index);
	if (err)
		goto out;

	/* Start the proxy */
	if (new_client) {
		list_add_rcu(&client_sock->list, &ksock->server_sock);
		kproxy_start_sock(client_sock);
	}

	if (new_server) {
		list_add_rcu(&server_sock->list, &ksock->server_sock);
		kproxy_start_sock(server_sock);
	}

out:
	release_sock(sock->sk);
	return err;
}

static int kproxy_ioctl(struct socket *sock, unsigned int cmd,
			unsigned long arg)
{
	int err;

	switch (cmd) {
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

static struct proto kproxy_proto = {
	.name   = "KPROXY",
	.owner  = THIS_MODULE,
	.obj_size = sizeof(struct kproxy_sock),
};

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

	ksock = kproxy_sk(sk);
	INIT_LIST_HEAD_RCU(&ksock->server_sock);

	mutex_lock(&knet->mutex);
	list_add_rcu(&ksock->list, &knet->kproxy_list);
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
