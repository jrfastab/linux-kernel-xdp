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

struct kproxy_stats {
	unsigned long long tx_bytes;
	unsigned long long rx_bytes;
};

struct kproxy_peers {
	struct rcu_head	rcu;

	u16	max_peers;
	u16	num_peers;
	struct bpf_prog __rcu *prog;
	struct kproxy_psock __rcu *socks[0];
};

struct kproxy_psock {
	struct rcu_head	rcu;

	struct sk_buff_head rxqueue;
	unsigned int queue_hiwat;
	unsigned int queue_lowat;
	unsigned int produced;
	unsigned int consumed;

	unsigned int refcnt;
	int fd;

	struct list_head list;

	struct kproxy_stats stats;

	int save_sent;
	struct sk_buff *save_skb;

	u32 tx_stopped : 1;
	int deferred_err;

	struct socket *sock;
	unsigned int num_peers;
	struct kproxy_peers *peers;
	struct work_struct tx_work;
	struct work_struct rx_work;

	struct strparser strp;
	struct bpf_prog *bpf_prog;
	struct bpf_prog *bpf_mux;

	void (*save_data_ready)(struct sock *sk);
	void (*save_write_space)(struct sock *sk);
	void (*save_state_change)(struct sock *sk);
};

struct kproxy_sock {
	struct sock sk;

	u32 running : 1;

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

#ifdef CONFIG_PROC_FS
int kproxy_proc_init(void);
void kproxy_proc_exit(void);
#else
static inline int kproxy_proc_init(void) { return 0; }
static inline void kproxy_proc_exit(void) { }
#endif

#endif /* __NET_KPROXY_H_ */
