/*
 * Kernel Proxy
 *
 * Copyright (c) 2017 Tom Herbert <tom@quantonium.net>
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
#include <net/kproxy.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <uapi/linux/kproxy.h>

unsigned int kproxy_net_id;

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
	//schedule_work(&psock->tx_work);
}

static int kproxy_recv(read_descriptor_t *desc, struct sk_buff *skb,
		       unsigned int offset, size_t len)
{
	struct kproxy_psock *psock = (struct kproxy_psock *)desc->arg.data;

	printk("%s: kproxy_recv: skb->len %i offset %i len %zu\n", __func__, skb->len, offset, len);
	WARN_ON(len != skb->len - offset);

	/* Check limit of queued data */
	if (kproxy_enqueued(psock) > psock->queue_hiwat) {
		printk("%s: limit eached\n", __func__);
		return 0;
	}

	/* Dequeue from lower socket and put skbufs on an internal queue
	 * queue.
	 */

	/* Always clone since we're consuming whole skbuf */
	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb) {
		printk("%s: clone failed\n", __func__);
		desc->error = -ENOMEM;
		return 0;
	}

	if (unlikely(offset)) {
		/* Don't expect offsets to be present */

		printk("%s: offset what\n", __func__);

		if (!pskb_pull(skb, offset)) {
			kfree_skb(skb);
			desc->error = -ENOMEM;
			return 0;
		}
	}

	psock->produced += skb->len;
	psock->stats.rx_bytes += skb->len;

	printk("%s: psock queue tail: %i\n", __func__, skb->len);
	skb_queue_tail(&psock->rxqueue, skb);

	return skb->len;
}

static int kproxy_tx_writer(struct kproxy_psock *psock)
{
	struct kproxy_psock *peer;
	//struct bpf_prog *prog = psock->bpf_mux;

	// (*prog->bpf_func)(skb, prog->insnsi);

	peer = list_first_entry(&psock->peer, struct kproxy_psock, list);
	schedule_writer(peer);

	return 0;
}

/* Called with lock held on lower socket */
static int kproxy_read_sock(struct kproxy_psock *psock)
{
	struct socket *sock = psock->sock;
	read_descriptor_t desc;

	printk("%s: read sock\n", __func__);

	if (!psock) {
		WARN_ON(1);
		return 0;
	}

#if 0
	if (!psock->peer) {
		WARN_ON(1);
		return 0;
	}
#endif

	/* Check limit of queued data. If we're over then just
	 * return. We'll be called again when the write has
	 * consumed data to below queue_lowat.
	 */
	if (kproxy_enqueued(psock) > psock->queue_hiwat)
		return 0;

	printk("kproxy enqueue\n");

	desc.arg.data = psock;
	desc.error = 0;
	desc.count = 1; /* give more than one skb per call */

	if (!sock) {
		WARN_ON(1);
		return 0;
	}
	printk("desc accounting done %p:%p:%p\n",
		sock, sock->ops, sock->ops->read_sock);

	if (!sock->ops->read_sock) {
		WARN_ON(1);
		return 0;
	}

	/* sk should be locked here, so okay to do read_sock */
	sock->ops->read_sock(sock->sk, &desc, kproxy_recv);
	printk("%s: read_sock kproxy_recv\n", __func__);

	/* Probably got some data, kick writer side */
	if (likely(!skb_queue_empty(&psock->rxqueue))) {
		printk("scheduled writers\n");
		kproxy_tx_writer(psock);
	} else {
		printk("queue empty no writers needed\n");
	}

	return desc.error;
}

/* Called with lock held on socket */
static void kproxy_data_ready(struct sock *sk)
{
	struct kproxy_psock *psock = kproxy_psock_sk(sk);

	printk("%s: data ready\n", __func__);

	if (unlikely(!psock))
		return;

	read_lock_bh(&sk->sk_callback_lock);

	if (kproxy_read_sock(psock) == -ENOMEM)
		schedule_work(&psock->rx_work);

	read_unlock_bh(&sk->sk_callback_lock);
}

static void check_for_rx_wakeup(struct kproxy_psock *psock,
				int orig_consumed)
{
	int started_with = psock->produced - orig_consumed;

	printk("%s: wakeup\n", __func__);

	/* Check if we fell below low watermark with new data that
	 * was consumed and if so schedule receiver.
	 */
	if (started_with > psock->queue_lowat &&
	    kproxy_enqueued(psock) <= psock->queue_lowat)
		kproxy_tx_writer(psock);
}

static void kproxy_rx_work(struct work_struct *w)
{
	struct kproxy_psock *psock = container_of(w, struct kproxy_psock,
						  rx_work);
	struct sock *sk = psock->sock->sk;

	printk("%s: work\n", __func__);

	lock_sock(sk);
	if (kproxy_read_sock(psock) == -ENOMEM)
		kproxy_tx_writer(psock);
	release_sock(sk);
}

/* Perform TX side. This is only called from the workqueue so we
 * assume mutual exclusion.
 */
#if 0
static void kproxy_tx_work(struct work_struct *w)
{
	struct kproxy_psock *psock = container_of(w, struct kproxy_psock,
						  tx_work);
#endif
static void kproxy_tx_work(struct kproxy_psock *psock)
{
	int sent, n;
	struct sk_buff *skb;
	int orig_consumed = psock->consumed;
	struct kproxy_psock *peer;

	printk("%s: TX work\n", __func__);
	if (unlikely(psock->tx_stopped))
		return;

	peer = list_first_entry(&psock->peer, struct kproxy_psock, list);

	if (psock->save_skb) {
		skb = psock->save_skb;
		sent = psock->save_sent;
		psock->save_skb = NULL;
		goto start;
	}

	while ((skb = skb_dequeue(&peer->rxqueue))) {
		sent = 0;
		printk("%s: skb dequeue len %i\n", __func__, skb->len);
start:
		do {
			n = skb_send_sock(skb, psock->sock, sent);
			printk("%s: skb send client socket %i:%i\n", __func__, n, sent);
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
//				kproxy_report_sk_error(psock,
//						       n ? -n : EPIPE, true);
				psock->tx_stopped = 1;
				goto out;
			}
			sent += n;
			psock->consumed += n;
			psock->stats.tx_bytes += n;
		} while (sent < skb->len);
	}

	if (unlikely(peer->deferred_err)) {
		/* An error had been report on the peer and
		 * now the queue has been drained, go ahead
		 * and report the errot.
		 */
		kproxy_report_deferred_error(peer);
	}
out:
	printk("%s: done rx wakeup\n", __func__);
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
	struct kproxy_psock *peer;

	/* Set up callbacks */
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_data_ready = psock->save_data_ready;
	sk->sk_write_space = psock->save_write_space;
	sk->sk_state_change = psock->save_state_change;
	sk->sk_user_data = NULL;
	write_unlock_bh(&sk->sk_callback_lock);

	/* Shut down the workers. Sequence is important because
	 * RX and TX can schedule on another.
	 */

	psock->tx_stopped = 1;

	/* Make sure tx_stopped is committed */
	smp_mb();

	//cancel_work_sync(&psock->tx_work);
	/* At this point tx_work will just return if schedule, it will
	 * not schedule rx_work.
	 */

	peer = list_first_entry(&psock->peer, struct kproxy_psock, list);
	cancel_work_sync(&peer->rx_work);
	/* rx_work is done */

	//cancel_work_sync(&psock->tx_work);
	/* Just in case rx_work managed to schedule a tx_work after we
	 * set tx_stopped .
	 */
}

static void kproxy_done_psock(struct kproxy_psock *psock)
{
	__skb_queue_purge(&psock->rxqueue);
	sock_put(psock->sock->sk);
	fput(psock->sock->file);
	psock->sock = NULL;
}

static int kproxy_unjoin(struct socket *sock, struct kproxy_unjoin *info)
{
	struct kproxy_sock *ksock = kproxy_sk(sock->sk);
	struct kproxy_psock *server_sock, *tmp;
	int err = 0;

	printk("%s: unjoin!\n", __func__);
	lock_sock(sock->sk);

	if (ksock->running) {
		printk("%s: error\n", __func__);
		err = -EALREADY;
		goto out;
	}

	/* Stop proxy activity */
	kproxy_stop_sock(ksock->client_sock);

	list_for_each_entry_safe(server_sock, tmp, &ksock->server_sock, list)
		kproxy_stop_sock(server_sock);

	/* Done with sockets */
	kproxy_done_psock(ksock->client_sock);
	list_for_each_entry_safe(server_sock, tmp, &ksock->server_sock, list)
		kproxy_done_psock(server_sock);

	/* TBD return memory */

	/* Stop ksock */
	ksock->running = false;

	/* Releae BPF program if it exists */
	if (ksock->bpf_mux)
		bpf_prog_put(ksock->bpf_mux);

	printk("%s: running false\n", __func__);
out:
	release_sock(sock->sk);

	return err;
}

static int kproxy_release(struct socket *sock)
{
	struct kproxy_net *knet = net_generic(sock_net(sock->sk),
					      kproxy_net_id);
	struct sock *sk = sock->sk;
	struct kproxy_sock *ksock = kproxy_sk(sock->sk);

	printk("%s: release kproxy\n", __func__);
	if (!sk)
		goto out;

	sock_orphan(sk);

	if (ksock->running) {
		struct kproxy_unjoin info;

		memset(&info, 0, sizeof(info));
		kproxy_unjoin(sock, &info);
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

static void kproxy_init_sock(struct kproxy_psock *psock,
			     struct socket *sock,
			     struct kproxy_psock *peer)
{
	skb_queue_head_init(&psock->rxqueue);
	psock->sock = sock;
	list_add_rcu(&peer->list, &psock->peer);
	psock->queue_hiwat = 1000000;
	psock->queue_lowat = 1000000;
	//INIT_WORK(&psock->tx_work, kproxy_tx_work);
	INIT_WORK(&psock->rx_work, kproxy_rx_work);
	sock_hold(sock->sk);
}

static void kproxy_start_sock(struct kproxy_psock *psock)
{
	struct sock *sk = psock->sock->sk;

	printk("%s callbacks\n", __func__);
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

	schedule_work(&psock->rx_work);
}

static int kproxy_join(struct socket *sock, struct kproxy_join *info)
{
	struct kproxy_sock *ksock = kproxy_sk(sock->sk);
	struct socket *csock, *ssock;
	struct kproxy_psock *client_sock, *server_sock;
	int err;

	printk("%s %i %i\n", __func__, info->client_fd, info->server_fd);
	if (info->bpf_fd_mux) {
		struct bpf_prog *prog;

		prog = bpf_prog_get_type(info->bpf_fd_mux, BPF_PROG_TYPE_SOCKET_FILTER);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
		ksock->bpf_mux = prog;
	}

	csock = sockfd_lookup(info->client_fd, &err);
	if (!csock)
		return err;

	ssock = sockfd_lookup(info->server_fd, &err);
	if (!ssock) {
		fput(csock->file);
		if (ksock->bpf_mux)
			bpf_prog_put(ksock->bpf_mux);
		return err;
	}

	err = -EINVAL;

	if (!csock->ops->read_sock || !ssock->ops->read_sock)
		goto outerr_early;

	err = -ENOMEM;
	client_sock = kmalloc(sizeof(*client_sock), GFP_KERNEL);
	if (!client_sock)
		goto outerr_early;

	server_sock = kmalloc(sizeof(*server_sock), GFP_KERNEL);
	if (!server_sock) {
		kfree(client_sock);
		goto outerr_early;
	}

	INIT_LIST_HEAD_RCU(&server_sock->peer);
	INIT_LIST_HEAD_RCU(&client_sock->peer);

	lock_sock(sock->sk);

	if (ksock->running) {
		err = -EALREADY;
		goto outerr;
	}

	/* Insert initial client */
	kproxy_init_sock(client_sock, csock, server_sock);
	ksock->client_sock = client_sock;

	/* Insert initial peer */
	kproxy_init_sock(server_sock, ssock, client_sock);
	list_add_rcu(&server_sock->list, &ksock->server_sock);

	/* Start a 1:1 proxy server_sock <-> client_proxy */
	kproxy_start_sock(client_sock);
	kproxy_start_sock(server_sock);
	ksock->running = true;

	release_sock(sock->sk);
	return 0;

outerr:
	release_sock(sock->sk);
	kfree(client_sock);
	kfree(server_sock);
outerr_early:
	if (ksock->bpf_mux)
		bpf_prog_put(ksock->bpf_mux);
	fput(csock->file);
	fput(ssock->file);

	return err;
}

/* kproxy_add will add another peer to the list of possible endpoints
 * that a client may choose. Useful for load balncing amongst sockets.
 */
static int kproxy_add(struct socket *sock, struct kproxy_add *info)
{
	struct kproxy_sock *ksock = kproxy_sk(sock->sk);
	struct kproxy_psock *server_sock;
	struct socket *ssock;
	int err;

	printk("%s add fd %i\n", __func__, info->server_fd);

	ssock = sockfd_lookup(info->server_fd, &err);
	if (!ssock)
		return err;

	err = 0;

	if (!ssock->ops->read_sock) {
		fput(ssock->file);
		return -EINVAL;
	}

	server_sock = kmalloc(sizeof(*server_sock), GFP_KERNEL);
	if (!server_sock) {
		fput(ssock->file);
		return -ENOMEM;
	}

	INIT_LIST_HEAD_RCU(&server_sock->peer);

	lock_sock(sock->sk);

	if (!ksock->running) {
		err = -EALREADY;
		goto outerr;
	}

	kproxy_init_sock(server_sock, ssock, ksock->client_sock);
	kproxy_start_sock(server_sock);
	list_add_tail_rcu(&server_sock->list, &ksock->client_sock->peer);

	release_sock(sock->sk);

	return 0;
outerr:
	release_sock(sock->sk);
	fput(ssock->file);
	kfree(server_sock);
	return err;
}

static int kproxy_ioctl(struct socket *sock, unsigned int cmd,
			unsigned long arg)
{
	int err;

	printk("%s cmd %i\n", __func__, cmd);
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

	case SIOCKPROXYADD: {
		struct kproxy_add info;

		if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
			return -EFAULT;

		err = kproxy_add(sock, &info);

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

	printk("%s\n", __func__);
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

	/* All kProxy sockets should be closed at this point, which should mean
	 * that all multiplexors and psocks have been destroyed.
	 */
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
