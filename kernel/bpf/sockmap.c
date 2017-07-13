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

/* sockmap primary use is
 */
#include <linux/bpf.h>
#include <linux/jhash.h>
#include <linux/filter.h>
#include <net/sock.h>
#include <linux/rculist_nulls.h>
#include "percpu_freelist.h"
#include "bpf_lru_list.h"
#include "map_in_map.h"

struct bpf_stab {
	struct bpf_map map;
	struct socket **sock_map;
};

static struct bpf_map *sock_map_alloc(union bpf_attr *attr)
{
	struct bpf_stab *stab;
	u64 cost;
	int err;

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

	err = -ENOMEM;

	/* make sure page count doesn't overflow */
	cost = (u64) stab->map.max_entries * sizeof(struct socket *);
	stab->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

	/* if map size is larger than memlock limit, reject it early */
	err = bpf_map_precharge_memlock(stab->map.pages);
	if (err)
		goto free_stab;

	stab->sock_map = bpf_map_area_alloc(stab->map.max_entries *
					    sizeof(struct socket *));
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
		struct socket *sock;

		sock = stab->sock_map[i];
		if (!sock)
			continue;

		sock_put(sock->sk);
		fput(sock->file);
	}

	bpf_map_area_free(stab->sock_map);
	kfree(stab);
}

static int sock_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (index >= stab->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == stab->map.max_entries - 1)
		return -ENOENT;

	*next = index + 1;
	return 0;
}

struct socket  *__sock_map_lookup_elem(struct bpf_map *map, u32 key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);

	if (key >= map->max_entries)
		return NULL;

	return stab->sock_map[key];
}

static void *sock_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	struct socket *sock;
	u32 i = *(u32 *)key;

	if (i >= map->max_entries)
		return NULL;

	sock = stab->sock_map[i];
	return NULL;
}

static int sock_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	struct socket *sock;
	int k = *(u32 *)key;

	if (k >= map->max_entries)
		return -EINVAL;

	sock = stab->sock_map[k];
	if (!sock)
		return -EINVAL;

	sock_put(sock->sk);
	fput(sock->file);
	return 0;
}

// tbd socket locking
// tbd sock_map locking
static int sock_map_update_elem(struct bpf_map *map, void *key, void *value,
				u64 map_flags)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	struct socket *sock, *old_sock;
	u32 fd = *(u32 *)value;
	u32 i = *(u32 *)key;
	int err;

	if (unlikely(map_flags > BPF_EXIST))
		return -EINVAL;

	if (unlikely(i >= stab->map.max_entries))
		return -E2BIG;

	if (unlikely(map_flags == BPF_NOEXIST))
		return -EEXIST;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return err;

	sock_hold(sock->sk);
	old_sock = xchg(&stab->sock_map[i], sock);
	if (old_sock) {
		sock_put(old_sock->sk);
		fput(old_sock->file);
	}

	return 0;
}

const struct bpf_map_ops sock_map_ops = {
	.map_alloc = sock_map_alloc,
	.map_free = sock_map_free,
	.map_get_next_key = sock_map_get_next_key,
	.map_lookup_elem = sock_map_lookup_elem,
	.map_update_elem = sock_map_update_elem,
	.map_delete_elem = sock_map_delete_elem,
};
