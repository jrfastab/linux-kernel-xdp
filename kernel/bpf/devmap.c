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

struct bpf_dtab {
	struct bpf_map map;
	struct net_device **netdev_map;
};

static struct bpf_map *dev_map_alloc(union bpf_attr *attr)
{
	struct bpf_dtab *dtab;
	int err;
	u64 cost;

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    attr->value_size != 4 || attr->map_flags)
		return ERR_PTR(-EINVAL);

	if (attr->value_size > KMALLOC_MAX_SIZE)
		/* if value_size is bigger, the user space won't be able to
		 * access the elements.
		 */
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

	/* check sanity of attributes. */
	err = -EINVAL;
	if (dtab->map.max_entries == 0 || dtab->map.key_size == 0)
		goto free_dtab;

	/* make sure page count doesn't overflow */
	cost = (u64) dtab->map.max_entries * sizeof(struct net_device *);
	if (cost >= U32_MAX - PAGE_SIZE)
		goto free_dtab;

	dtab->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

	/* if map size is larger than memlock limit, reject it early */
	err = bpf_map_precharge_memlock(dtab->map.pages);
	if (err)
		goto free_dtab;

	err = -ENOMEM;
	dtab->netdev_map = bpf_map_area_alloc(dtab->map.max_entries *
					      sizeof(struct net_device *));
	if (!dtab->netdev_map)
		goto free_dtab;

	return &dtab->map;

free_dtab:
	kfree(dtab);
	return ERR_PTR(err);
}

static void delete_all_elements(struct bpf_dtab *dtab)
{
	int i;

	for (i = 0; i < dtab->map.max_entries; i++) {
		if (dtab->netdev_map[i]) {
			dev_put(dtab->netdev_map[i]);
			dtab->netdev_map[i] = NULL;
		}
	}
}

static void dev_map_free(struct bpf_map *map)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);

	/* at this point bpf_prog->aux->refcnt == 0 and this map->refcnt == 0,
	 * so the programs (can be more than one that used this map) were
	 * disconnected from events. Wait for outstanding critical sections in
	 * these programs to complete
	 */
	synchronize_rcu();

	delete_all_elements(dtab);
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

static void *dev_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	u32 i = *(u32 *)key;

	if (i >= map->max_entries)
		return NULL;

	return dtab->netdev_map[i] ? &dtab->netdev_map[i]->ifindex : NULL;
}

static int dev_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct net_device *dev;
	int k = *(u32 *)key;

	if (k >= map->max_entries)
		return -EINVAL;

	dev = dtab->netdev_map[k];
	if (dev) {
		dev_put(dev);
		dtab->netdev_map[k] = NULL;
	}
	return 0;
}

static int dev_map_update_elem(struct bpf_map *map, void *key, void *value,
				u64 map_flags)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct net *net = current->nsproxy->net_ns;
	struct net_device *dev;
	u32 i = *(u32 *)key;
	u32 ifindex = *(u32 *)value;

	if (unlikely(map_flags > BPF_EXIST))
		return -EINVAL;

	if (unlikely(i >= dtab->map.max_entries))
		return -E2BIG;

	if (unlikely(map_flags == BPF_NOEXIST))
		return -EEXIST;

	dev = dev_get_by_index(net, ifindex);
	if (!dev)
		return -EINVAL;
	dtab->netdev_map[i] = dev;

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
