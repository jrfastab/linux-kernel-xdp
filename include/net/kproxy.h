/*
 * Kernel Proxy
 *
 * Copyright (c) 2017 Tom Herbert <tom@quantonium.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef __NET_KPROXY_H_
#define __NET_KPROXY_H_

#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/strparser.h>
#include <uapi/linux/kproxy.h>

extern unsigned int kproxy_net_id;
extern struct proto kproxy_proto;

struct kproxy_hashinfo {
	rwlock_t lock;
	struct hlist_head ht;
};

struct kproxy_stats {
	unsigned long long tx_bytes;
	unsigned long long rx_bytes;
};

struct kproxy_peers {
	struct rcu_head	rcu;
	/* max peers used to build arrays at join time. Note in the 1:1
	 * case all the control paths list walks are in the first entry
	 * causing minimal extra overhead.
	 */
	u16		max_peers;
	/* socks_index is the index of the related kproxy_psock needed
	 * to unregister socks. Only used under kproxy_net lock.
	 */
	int		*socks_index;
	/* array holding peers used in datapath with writes protected
	 * by kproxy_net lock plus rcu grace period.
	 */
	struct kproxy_psock __rcu *socks[0];
};

struct kproxy_psock {
	struct rcu_head	rcu;

	/* datapath variables used under sock lock */
	struct sk_buff_head rxqueue;
	unsigned int queue_hiwat;
	unsigned int queue_lowat;
	unsigned int produced;
	unsigned int consumed;

	struct kproxy_stats stats;
	struct kproxy_peers *peers;

	/* datapath error path cache across tx work invocations */
	int save_sent;
	struct sk_buff *save_skb;
	u32 tx_stopped : 1;
	int deferred_err;

	struct strparser strp;
	struct bpf_prog *bpf_prog;
	struct bpf_prog *bpf_mux;

	/* refcnt is incremented/decremented for creation/deletion of peer
	 * psocks. Only modified under krpoxy_net lock and when reaching zero
	 * the kproxy_psock object is removed from kproxy_net and can be
	 * destroyed after a grace period.
	 */
	unsigned int refcnt;

	/* Back reference to the file descriptor of the sock */
	int fd;
	int index;
	struct sock *sock;

	struct list_head list;

	struct work_struct tx_work;

	void (*save_data_ready)(struct sock *sk);
	void (*save_write_space)(struct sock *sk);
	void (*save_state_change)(struct sock *sk);
};

struct kproxy_sock {
	struct sock sk;

	int bpf_fd_parse;
	int bpf_fd_mux;
	int max_peers;
	struct kproxy_peers *peers;

	bool attached;

	struct list_head list;
	struct list_head server_sock;
};

struct kproxy_net {
	struct mutex mutex;
	struct list_head kproxy_list;
	int count;
};

static inline unsigned int kproxy_enqueued(struct kproxy_psock *psock)
{
	return psock->produced - psock->consumed;
}

static inline struct kproxy_sock *kproxy_sk(const struct sock *sk)
{
	return (struct kproxy_sock *)sk;
}

static inline struct kproxy_psock *kproxy_psock_sk(const struct sock *sk)
{
	return (struct kproxy_psock *)sk->sk_user_data;
}

#ifdef CONFIG_PROC_FS
int kproxy_proc_init(void);
void kproxy_proc_exit(void);
#else
static inline int kproxy_proc_init(void) { return 0; }
static inline void kproxy_proc_exit(void) { }
#endif

#endif /* __NET_KPROXY_H_ */
