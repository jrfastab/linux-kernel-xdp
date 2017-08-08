/* Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

/* A BPF sock_map is used to store sock objects. This is primarly used
 * for doing socket redirect with BPF helper routines.
 *
 * A sock map may have two BPF programs attached to it, a program used
 * to parse packets and a program to provide a verdict and redirect
 * decision on the packet. If no BPF parse program is provided it is
 * assumed that every skb is a "message" (skb->len). Otherwise the
 * parse program is attached to strparser and used to build messages
 * that may span multiple skbs. The verdict program will either select
 * a socket to send/receive the skb on or provide the drop code indicating
 * the skb should be dropped. More actions may be added later as needed.
 * The default program will drop packets.
 *
 * For reference this program is similar to devmap used in XDP context
 * reviewing these together may be useful. For a set of examples and
 * test codes using this map please review ./samples/bpf/sockmap/ here
 * you can find common usages such as a socket level load balancer and
 * cgroup integration.
 */
#include <linux/bpf.h>
#include <linux/jhash.h>
#include <linux/filter.h>
#include <net/sock.h>
#include <linux/rculist_nulls.h>
#include "percpu_freelist.h"
#include "bpf_lru_list.h"
#include "map_in_map.h"

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
#include <net/netns/generic.h>
#include <net/sock.h>

struct bpf_stab {
	struct bpf_map map;
	struct sock **sock_map;
	struct bpf_prog *bpf_parse;
	struct bpf_prog *bpf_verdict;
};

enum smap_psock_state {
	SMAP_TX_RUNNING,
};

struct smap_psock {
	struct rcu_head	rcu;

	/* datapath variables used under sock lock */
	struct sk_buff_head rxqueue;
	bool strp_enabled;

	/* datapath error path cache across tx work invocations */
	int save_rem;
	int save_off;
	struct sk_buff *save_skb;

	struct strparser strp;
	struct bpf_prog *bpf_parse;
	struct bpf_prog *bpf_verdict;
	struct bpf_map *map;

	/* Back reference to the file descriptor of the sock */
	int key;
	struct sock *sock;
	unsigned long state;

	struct work_struct tx_work;
	struct work_struct gc_work;

	void (*save_data_ready)(struct sock *sk);
	void (*save_write_space)(struct sock *sk);
	void (*save_state_change)(struct sock *sk);
};

static inline struct smap_psock *smap_psock_sk(const struct sock *sk)
{
	return (struct smap_psock *)sk->sk_user_data;
}

static int smap_verdict_func(struct smap_psock *psock, struct sk_buff *skb)
{
	struct bpf_prog *prog = psock->bpf_verdict;
	int rc;

	if (unlikely(!prog))
		return 0;

	skb->sk = psock->sock;
	rc = (*prog->bpf_func)(skb, prog->insnsi);
	skb->sk = NULL;

	return rc;
}

static struct smap_psock *smap_do_verdict(struct smap_psock *psock,
					  struct sk_buff *skb)
{
	struct sock *sock;
	int rc;

	rc = smap_verdict_func(psock, skb);
	switch (rc) {
	case BPF_REDIRECT:
		sock = do_sk_redirect_map();
		return smap_psock_sk(sock);
	case BPF_DROP:
	default:
		kfree_skb(skb);
		return NULL;
	}
}

static void smap_report_sk_error(struct smap_psock *psock, int err)
{
	struct sock *sk = psock->sock;

	sk->sk_err = err;
	sk->sk_error_report(sk);
}

static int sock_map_delete_elem(struct bpf_map *map, void *key);

static void smap_state_change(struct sock *sk)
{
	struct smap_psock *psock = smap_psock_sk(sk);

	/* Allowing transitions into established an syn_recv states allows
	 * for early binding sockets to a smap object before the connection
	 * is established. All other transitions indicate the connection is
	 * being torn down so tear down the smap socket.
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
		sock_map_delete_elem(psock->map, &psock->key);
		break;
	default:
		smap_report_sk_error(psock, EPIPE);
		break;
	}
}

static void smap_tx_work(struct work_struct *w);

void schedule_writer(struct smap_psock *psock)
{
	if (test_bit(SMAP_TX_RUNNING, &psock->state))
		schedule_work(&psock->tx_work);
}

static int smap_tx_writer(struct smap_psock *peer)
{
	schedule_writer(peer);
	return 0;
}

static void smap_read_sock_strparser(struct strparser *strp,
				     struct sk_buff *skb)
{
	struct smap_psock *psock = container_of(strp,
						  struct smap_psock, strp);
	struct smap_psock *peer;

	rcu_read_lock();
	peer = smap_do_verdict(psock, skb);
	if (unlikely(!peer))
		goto out;

	skb_queue_tail(&peer->rxqueue, skb);
	smap_tx_writer(peer);
out:
	rcu_read_unlock();
}

/* Called with lock held on socket */
static void smap_data_ready(struct sock *sk)
{
	struct smap_psock *psock;

	read_lock_bh(&sk->sk_callback_lock);

	psock = smap_psock_sk(sk);
	if (likely(psock))
		strp_data_ready(&psock->strp);

	read_unlock_bh(&sk->sk_callback_lock);
}

static void smap_tx_work(struct work_struct *w)
{
	struct smap_psock *psock;
	struct sk_buff *skb;
	int rem, off, n;

	psock = container_of(w, struct smap_psock, tx_work);

	if (psock->save_skb) {
		skb = psock->save_skb;
		rem = psock->save_rem;
		off = psock->save_off;
		psock->save_skb = NULL;
		goto start;
	}

	while ((skb = skb_dequeue(&psock->rxqueue))) {
		rem = skb->len;
		off = 0;
start:
		do {
			n = skb_send_sock(psock->sock, skb, off, rem);
			if (n <= 0) {
				if (n == -EAGAIN) {
					/* Save state to try again when
					 * there's write space on the
					 * socket.
					 */
					psock->save_skb = skb;
					psock->save_rem = rem;
					psock->save_off = off;
					goto out;
				}

				/* Got a hard error or socket had
				 * been closed somehow. Report this
				 * on the transport socket.
				 */
				smap_report_sk_error(psock, n ? -n : EPIPE);
				clear_bit(SMAP_TX_RUNNING, &psock->state);
				goto out;
			}
			rem -= n;
			off += n;
		} while (rem);
	}
out:
	return;
}

static void smap_write_space(struct sock *sk)
{
	struct smap_psock *psock = smap_psock_sk(sk);

	schedule_writer(psock);
}

/* When destroy is true the sock reference to psock is lost so be sure in this
 * case _not_ to use sk->sk_user_data.
 */
static void smap_stop_sock(struct smap_psock *psock)
{
	struct sock *sk = psock->sock;

	clear_bit(SMAP_TX_RUNNING, &psock->state);
	write_lock_bh(&sk->sk_callback_lock);
	if (psock->strp_enabled) {
		sk->sk_data_ready = psock->save_data_ready;
		sk->sk_write_space = psock->save_write_space;
		sk->sk_state_change = psock->save_state_change;
		strp_stop(&psock->strp);
	}
	write_unlock_bh(&sk->sk_callback_lock);
}

static void smap_destroy_psock(struct rcu_head *rcu)
{
	struct smap_psock *psock = container_of(rcu,
						  struct smap_psock, rcu);

	smap_stop_sock(psock);
	if (psock->bpf_parse)
		bpf_prog_sub(psock->bpf_parse, 1);
	if (psock->bpf_verdict)
		bpf_prog_sub(psock->bpf_verdict, 1);

	schedule_work(&psock->gc_work);
}

static void smap_release_psock(struct sock *sock)
{
	struct smap_psock *psock = smap_psock_sk(sock);

	/* At this point all TX work is complete and new work is blocked
	 * so it is safe to free data structures and release BPF programs,
	 * but we need to wait a grace period to ensure datapath is also
	 * done with psock.
	 */
	call_rcu_sched(&psock->rcu, smap_destroy_psock);
}

static int smap_parse_func_strparser(struct strparser *strp,
				       struct sk_buff *skb)
{
	struct smap_psock *psock = container_of(strp,
						  struct smap_psock, strp);
	struct bpf_prog *prog = psock->bpf_parse;

	if (unlikely(!prog))
		return skb->len;

	return (*prog->bpf_func)(skb, prog->insnsi);
}


static int smap_read_sock_done(struct strparser *strp, int err)
{
	return err;
}

static int smap_init_sock(struct smap_psock *psock,
			  struct sock *sock)
{
	struct strp_callbacks cb;
	int err;

	cb.rcv_msg = smap_read_sock_strparser;
	cb.abort_parser = NULL;
	cb.parse_msg = smap_parse_func_strparser;
	cb.read_sock_done = smap_read_sock_done;

	err = strp_init(&psock->strp, sock, &cb);
	if (err)
		return -EINVAL;
	return 0;
}

static void smap_init_progs(struct smap_psock *psock, struct bpf_stab *stab)
{
	struct bpf_prog *parse, *orig_parse, *verdict, *orig_verdict;

	/* Do accounting on program ref counts before assigning anything */
	if (psock->bpf_verdict != stab->bpf_verdict) {
		verdict = bpf_prog_add(stab->bpf_verdict, 1);
		if (IS_ERR(verdict))
			return;
	}

	if (psock->bpf_parse != stab->bpf_parse) {
		parse = bpf_prog_add(stab->bpf_parse, 1);
		if (IS_ERR(parse)) {
			bpf_prog_sub(verdict, 1);
			return;
		}
	}

	/* Now we have a reference to the new programs assign them and
	 * remove any old ones.
	 */
	orig_parse = psock->bpf_parse;
	orig_verdict = psock->bpf_verdict;

	psock->bpf_parse = parse;
	psock->bpf_verdict = verdict;

	if (orig_verdict)
		bpf_prog_sub(orig_verdict, 1);
	if (orig_parse)
		bpf_prog_sub(orig_parse, 1);
}

static int smap_start_sock(struct smap_psock *psock, struct sock *sk)
{
	int err = 0;

	write_lock_bh(&sk->sk_callback_lock);
	/* only start socket if it is not already running */
	if (psock->save_data_ready) {
		err = -EINVAL;
		goto out;
	}
	psock->save_data_ready = sk->sk_data_ready;
	psock->save_write_space = sk->sk_write_space;
	psock->save_state_change = sk->sk_state_change;
	sk->sk_data_ready = smap_data_ready;
	sk->sk_write_space = smap_write_space;
	sk->sk_state_change = smap_state_change;
out:
	write_unlock_bh(&sk->sk_callback_lock);
	return err;
}

static void smap_gc_work(struct work_struct *w)
{
	struct smap_psock *psock;

	psock = container_of(w, struct smap_psock, gc_work);

	if (psock->strp_enabled) {
		strp_done(&psock->strp);
		psock->strp_enabled = false;
	}
	cancel_work_sync(&psock->tx_work);
	psock->sock->sk_user_data = NULL;
	__skb_queue_purge(&psock->rxqueue);
	sock_put(psock->sock);

	kfree(psock);
}

static struct smap_psock *smap_init_psock(struct sock *sock,
					  struct bpf_stab *stab)
{
	struct smap_psock *psock;

	psock = kmalloc(sizeof(struct smap_psock), GFP_ATOMIC);
	if (!psock)
		return ERR_PTR(-ENOMEM);

	memset(psock, 0, sizeof(struct smap_psock));
	psock->sock = sock;

	skb_queue_head_init(&psock->rxqueue);
	INIT_WORK(&psock->tx_work, smap_tx_work);
	INIT_WORK(&psock->gc_work, smap_gc_work);

	write_lock_bh(&sock->sk_callback_lock);
	sock->sk_user_data = psock;
	write_unlock_bh(&sock->sk_callback_lock);

	sock_hold(sock);
	return psock;
}

/* BPF map logic */
static struct bpf_map *sock_map_alloc(union bpf_attr *attr)
{
	struct bpf_stab *stab;
	int err = -EINVAL;
	u64 cost;

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    attr->value_size != 4 || attr->map_flags)
		return ERR_PTR(-EINVAL);

	/* if value_size is bigger, the user space won't be able to
	 * access the elements.
	 */
	if (attr->value_size > KMALLOC_MAX_SIZE)
		return ERR_PTR(-E2BIG);

	stab = kzalloc(sizeof(*stab), GFP_USER);
	if (!stab)
		return ERR_PTR(-ENOMEM);

	/* mandatory map attributes */
	stab->map.map_type = attr->map_type;
	stab->map.key_size = attr->key_size;
	stab->map.value_size = attr->value_size;
	stab->map.max_entries = attr->max_entries;
	stab->map.map_flags = attr->map_flags;

	/* make sure page count doesn't overflow */
	cost = (u64) stab->map.max_entries * sizeof(struct sock *) +
			sizeof(struct socket *);
	stab->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

	err = -ENOMEM;

	/* if map size is larger than memlock limit, reject it early */
	err = bpf_map_precharge_memlock(stab->map.pages);
	if (err)
		goto free_stab;

	stab->sock_map = bpf_map_area_alloc(stab->map.max_entries *
					    sizeof(struct sock *));
	if (!stab->sock_map)
		goto free_stab;

	return &stab->map;
free_stab:
	kfree(stab);
	return ERR_PTR(err);
}

static void sock_map_free(struct bpf_map *map)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	int i;

	synchronize_rcu();

	for (i = 0; i < stab->map.max_entries; i++) {
		struct sock *sock;

		sock = stab->sock_map[i];
		if (!sock)
			continue;

		smap_release_psock(sock);
	}

	if (stab->bpf_verdict)
		bpf_prog_put(stab->bpf_verdict);
	if (stab->bpf_parse)
		bpf_prog_put(stab->bpf_verdict);
	bpf_map_area_free(stab->sock_map);
	kfree(stab);
}

static int sock_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	u32 i = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (i >= stab->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (i == stab->map.max_entries - 1)
		return -ENOENT;

	*next = i + 1;
	return 0;
}

struct sock  *__sock_map_lookup_elem(struct bpf_map *map, u32 key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);

	if (key >= map->max_entries)
		return NULL;

	return stab->sock_map[key];
}

static void *sock_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	struct sock *sock;
	u32 i = *(u32 *)key;

	if (i >= map->max_entries)
		return NULL;

	sock = stab->sock_map[i];
	return NULL;
}

static int sock_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	struct sock *sock;
	int k = *(u32 *)key;

	if (k >= map->max_entries)
		return -EINVAL;

	sock = stab->sock_map[k];
	if (!sock)
		return -EINVAL;

	smap_release_psock(sock);
	return 0;
}

static int sock_map_update_elem(struct bpf_sock_ops_kern *skops,
				struct bpf_map *map,
				void *key, u64 flags, u64 map_flags)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	struct sock *old_sock, *sock;
	struct smap_psock *psock = NULL;
	u32 i = *(u32 *)key;
	bool update = false;

	if (unlikely(flags > BPF_EXIST))
		return -EINVAL;

	if (unlikely(i >= stab->map.max_entries))
		return -E2BIG;

	if (unlikely(map_flags > BPF_SOCKMAP_STRPARSER))
		return -EINVAL;

	if (flags == BPF_EXIST || flags == BPF_ANY) {
		sock = rcu_dereference(stab->sock_map[i]);

		if (!sock && flags == BPF_EXIST) {
			return -ENOENT;
		} else if (sock && sock != skops->sk) {
			return -EINVAL;
		} else if (sock) {
			psock = smap_psock_sk(sock);
			update = true;
		}
	}

	if (!psock) {
		sock = skops->sk;
		psock = smap_init_psock(sock, stab);
		if (IS_ERR(psock))
			return PTR_ERR(psock);
		psock->key = i;
		psock->map = map;
		set_bit(SMAP_TX_RUNNING, &psock->state);
	}

	if (map_flags & BPF_SOCKMAP_STRPARSER) {
		smap_start_sock(psock, sock);
		smap_init_progs(psock, stab);
		smap_init_sock(psock, sock);
		psock->strp_enabled = true;
	} else if (update) {
		smap_stop_sock(psock);
	}

	if (!update) {
		old_sock = xchg(&stab->sock_map[i], skops->sk);
		if (old_sock)
			smap_release_psock(old_sock);
	}

	return 0;
}

static int sock_map_attach_prog(struct bpf_map *map,
				struct bpf_prog *parse,
				struct bpf_prog *verdict)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);

	stab->bpf_parse = parse;
	stab->bpf_verdict = verdict;
	return 0;
}

const struct bpf_map_ops sock_map_ops = {
	.map_alloc = sock_map_alloc,
	.map_free = sock_map_free,
	.map_get_next_key = sock_map_get_next_key,
	.map_lookup_elem = sock_map_lookup_elem,
	.map_ctx_update_elem = sock_map_update_elem,
	.map_delete_elem = sock_map_delete_elem,
	.map_attach = sock_map_attach_prog,
};
