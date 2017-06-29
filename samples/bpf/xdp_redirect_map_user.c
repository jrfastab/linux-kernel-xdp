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
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf_load.h"
#include "bpf_util.h"
#include "libbpf.h"

static int ifindex_in;
static int ifindex_out;

static void int_exit(int sig)
{
	set_link_xdp_fd(ifindex_in, -1, 0);
	exit(0);
}

/* simple per-protocol drop counter
 */
static void poll_stats(int interval, int ifindex)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus], prev[nr_cpus];
	__u32 mapid = 0, dev = 0;

	memset(prev, 0, sizeof(prev));

	while (1) {
		__u64 sum = 0;
		__u32 key = 0;
		int i, ret, zero = 0;

		sleep(interval);
		assert(bpf_map_lookup_elem(map_fd[1], &key, values) == 0);
		for (i = 0; i < nr_cpus; i++)
			sum += (values[i] - prev[i]);
		if (sum)
			printf("ifindex %i: %10llu pkt/s mapid %i\n",
			       ifindex, sum / interval, mapid);
		memcpy(prev, values, sizeof(values));

#if 0
		printf("clear map\n");
		for (i = 0; i < 100; i++) {
			ret = bpf_map_update_elem(map_fd[0],
						  &i,
						  &zero, 0);
			if (ret) {
				perror("bpf_update_elem");
			}
		}

		printf("ifindex out map\n");
		for (i = 0; i < 100; i++) {
			ret = bpf_map_update_elem(map_fd[0],
						  &i,
						  &ifindex_out, 0);
			if (ret) {
				perror("bpf_update_elem");
			}
		}
#endif
	}
}

int main(int ac, char **argv)
{
	char filename[256];
	int i, ret, key = 0;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (ac != 3) {
		printf("usage: %s IFINDEX_IN IFINDEX_OUT\n", argv[0]);
		return 1;
	}

	ifindex_in = strtoul(argv[1], NULL, 0);
	ifindex_out = strtoul(argv[2], NULL, 0);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	if (!prog_fd[0]) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return 1;
	}

	signal(SIGINT, int_exit);

	if (set_link_xdp_fd(ifindex_in, prog_fd[0], 0) < 0) {
		printf("link set xdp fd failed\n");
		return 1;
	}

	printf("map[0] (vports) = %i, map[1] (map) = %i, map[2] (count) = %i\n",
		map_fd[0], map_fd[1], map_fd[2]);

	/* populate virtual to physical port map */
	for (i = 0; i < 100; i++) {
		ret = bpf_map_update_elem(map_fd[0], &key, &ifindex_out, 0);
		if (ret) {
			perror("bpf_update_elem");
			goto out;
		}
	}

	poll_stats(2, ifindex_out);

out:
	return 0;
}
