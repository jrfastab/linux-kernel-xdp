/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/unistd.h>

int cg_fd;

static void usage(char *pname)
{
	printf("USAGE:\n  %s [-l] <cg-path> <prog filename>\n", pname);
	exit(1);
}

static void int_exit(int sig)
{
	bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
	exit(0);
}

static int init_kproxy()
{
	int kproxy;

	kproxy = socket(AF_KPROXY, SOCK_DGRAM, 0);
	if (kproxy < 0) {
		perror("kproxy error\n");
		goto out;
	}

	join.client_fd = frontend_server.accept;
	join.server_fd = backend_client.client;
	join.client_index = 0;
	join.server_index = 0;

	attach.bpf_fd_parse = prog_fd[0];
	attach.bpf_fd_mux = prog_fd[1];
	attach.max_peers = 3;

	printf("attach kproxy to bpf\n");
	err = ioctl(kproxy, SIOCKPROXYATTACH, &attach);
	if (err < 0) {
		perror("attach ioctl error\n");
		return 1;
	}

	printf("join frontend and backend\n");
	err = ioctl(kproxy, SIOCKPROXYJOIN, &join);
	if (err < 0) {
		perror("join ioctl error\n");
		return 1;
	}
out:
	return kproxy;
}

int main(int argc, char **argv)
{
	int error = 0;
	char *cg_path;
	char fn[500];
	char *prog;

	/* Arg parsing */
	if (argc < 3)
		usage(argv[0]);

	if (!strcmp(argv[1], "-h"))
		usage(argv[0]);

	prog = argv[argc - 1];
	cg_path = argv[argc - 2];
	if (strlen(prog) > 480) {
		fprintf(stderr, "ERROR: program name too long (> 480 chars)\n");
		return 3;
	}
	cg_fd = open(cg_path, O_DIRECTORY, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "ERROR: (%i) open cg path failed: %s\n", cg_fd, cg_path);
		return cg_fd;
	}
	fprintf(stderr, "CG_FD open %i:%s\n", cg_fd, cg_path);

	/* Signal handlers */
	signal(SIGINT, int_exit);

	/* Load BPF map and program */
	printf("loading bpf file:%s\n", fn);
	strcpy(fn, prog);
	if (load_bpf_file(fn)) {
		printf("ERROR: load_bpf_file failed for: %s\n", fn);
		printf("%s", bpf_log_buf);
		return 4;
	}

	/* Configure Kproxy and BPF Map */
	kproxy = init_kproxy();

	/* Attach to cgroups */
	error = bpf_prog_attach(prog_fd[0], cg_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (error) {
		printf("ERROR: bpf_prog_attach: %d (%s)\n",
		       error, strerror(errno));
		return 5;
	}

	/* Monitor trace pipe */
	read_trace_pipe();
	return error;
}
