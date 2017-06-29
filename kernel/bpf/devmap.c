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
#include <linux/bpf.h>
#include <linux/jhash.h>
#include <linux/filter.h>
#include <linux/rculist_nulls.h>
#include "percpu_freelist.h"
#include "bpf_lru_list.h"
#include "map_in_map.h"

struct bpf_dtab_netdev {
	struct net_device *dev;
};

struct bpf_dtab {
	struct bpf_map map;
	struct bpf_dtab_netdev **netdev_map;
};

static struct bpf_map *dev_map_alloc(union bpf_attr *attr)
{
	struct bpf_dtab *dtab;
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

	dtab = kzalloc(sizeof(*dtab), GFP_USER);
	if (!dtab)
		return ERR_PTR(-ENOMEM);

	/* mandatory map attributes */
	dtab->map.map_type = attr->map_type;
	dtab->map.key_size = attr->key_size;
	dtab->map.value_size = attr->value_size;
	dtab->map.max_entries = attr->max_entries;
	dtab->map.map_flags = attr->map_flags;

	err = -ENOMEM;

	/* make sure page count doesn't overflow */
	cost = (u64) dtab->map.max_entries * sizeof(struct bpf_dtab_netdev *);
	cost += sizeof(BITS_TO_LONGS(attr->max_entries));
	if (cost >= U32_MAX - PAGE_SIZE)
		goto free_dtab;

	dtab->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

	/* if map size is larger than memlock limit, reject it early */
	err = bpf_map_precharge_memlock(dtab->map.pages);
	if (err)
		goto free_dtab;

	dtab->netdev_map = bpf_map_area_alloc(dtab->map.max_entries *
					      sizeof(struct bpf_dtab_netdev *));
	if (!dtab->netdev_map)
		goto free_dtab;

	return &dtab->map;

free_dtab:
	kfree(dtab);
	return ERR_PTR(err);
}

static void dev_map_free(struct bpf_map *map)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	int i;

	/* At this point bpf_prog->aux->refcnt == 0 and this map->refcnt == 0,
	 * so the programs (can be more than one that used this map) were
	 * disconnected from events. Wait for outstanding critical sections in
	 * these programs to complete. The rcu critical section only guarantees
	 * no further reads against netdev_map. It does __not__ ensure pending
	 * flush operations (if any) are complete.
	 */
	synchronize_rcu();

	for (i = 0; i < dtab->map.max_entries; i++) {
		struct bpf_dtab_netdev *dev;

		dev = dtab->netdev_map[i];
		if (!dev)
			continue;

		dev_put(dev->dev);
		kfree(dev);
	}

	/* At this point bpf program is detached and all pending operations
	 * _must_ be complete */
	bpf_map_area_free(dtab->netdev_map);
	kfree(dtab);
}

static int dev_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (index >= dtab->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == dtab->map.max_entries - 1)
		return -ENOENT;

	*next = index + 1;
	return 0;
}

/* rcu_read_lock (from syscall and BPF contexts) ensures that if a delete and/or
 * update happens in parallel here a dev_put wont happen until after reading the
 * ifindex.
 */
static void *dev_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_netdev *dev;
	u32 i = *(u32 *)key;
	u32 ifindex;

	if (i >= map->max_entries)
		return NULL;

	dev = READ_ONCE(dtab->netdev_map[i]);
	if (dev)
		ifindex = dev->dev->ifindex;

	return ifindex ? &ifindex : NULL;
}

static int dev_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_netdev *old_dev;
	int k = *(u32 *)key;

	if (k >= map->max_entries)
		return -EINVAL;

	/* Use synchronize_rcu() here to ensure any rcu critical sections
	 * have completed, but this does not guarantee a flush has happened
	 * yet. Because driver side rcu_read_lock/unlock only protects the
	 * running XDP program. However, for pending flush operations the
	 * dev and ctx are stored in another per cpu map. And additionally,
	 * the driver tear down ensures all soft irqs are complete before
	 * removing the net device in the case of dev_put equals zero.
	 */
	old_dev = xchg(&dtab->netdev_map[k], NULL);
	if (old_dev) {
		synchronize_rcu();
		dev_put(old_dev->dev);
		kfree(old_dev);
	}
	return 0;
}

static int dev_map_update_elem(struct bpf_map *map, void *key, void *value,
				u64 map_flags)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct net *net = current->nsproxy->net_ns;
	struct bpf_dtab_netdev *dev, *old_dev;
	u32 i = *(u32 *)key;
	u32 ifindex = *(u32 *)value;

	if (unlikely(map_flags > BPF_EXIST))
		return -EINVAL;

	if (unlikely(i >= dtab->map.max_entries))
		return -E2BIG;

	if (unlikely(map_flags == BPF_NOEXIST))
		return -EEXIST;

	if (!ifindex) {
		dev = NULL;
	} else {
		dev = kmalloc(sizeof(*dev), GFP_ATOMIC | __GFP_NOWARN);
		if (!dev)
			return -ENOMEM;

		dev->dev = dev_get_by_index(net, ifindex);
		if (!dev->dev) {
			kfree(dev);
			return -EINVAL;
		}
	}

	/* Use synchronize_rcu() here to ensure rcu critical sections
	 * have completed. Remembering the driver side flush operation will
	 * happen before the net device is removed.
	 */
	old_dev = xchg(&dtab->netdev_map[i], dev);
	if (old_dev) {
		synchronize_rcu();

		dev_put(old_dev->dev);
		kfree(old_dev);
	}

	return 0;
}

const struct bpf_map_ops dev_map_ops = {
	.map_alloc = dev_map_alloc,
	.map_free = dev_map_free,
	.map_get_next_key = dev_map_get_next_key,
	.map_lookup_elem = dev_map_lookup_elem,
	.map_update_elem = dev_map_update_elem,
	.map_delete_elem = dev_map_delete_elem,
};
