#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <signal.h>
#include <fcntl.h>

#include <linux/netlink.h>
#include <linux/socket.h>
#include <linux/sock_diag.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <libgen.h>

#include "../bpf/bpf_load.h"
#include "../bpf/bpf_util.h"
#include "../bpf/libbpf.h"

int running;
void running_handler(int a);

int main(int argc, char **argv)
{
	int err, cg_fd;
	char filename[256];
	char *cg_path;

	cg_path = argv[argc - 1];
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	running = 1;

	/* catch SIGINT */
	signal(SIGINT, running_handler);
	sleep(1);

	if (load_bpf_file(filename)) {
		printf("load_bpf_file: (%s) %s\n", filename, strerror(errno));
		return 1;
	}

	/* Cgroup configuration */
	cg_fd = open(cg_path, O_DIRECTORY, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "ERROR: (%i) open cg path failed: %s\n", cg_fd, cg_path);
		return cg_fd;
	}
	fprintf(stderr, "CG_FD open %i:%s\n", cg_fd, cg_path);

	/* Attach programs to sockmap */
	err = _bpf_prog_attach(prog_fd[0], prog_fd[1], map_fd[0], BPF_SOCKMAP_INGRESS, 0);
	if (err) {
		printf("ERROR: bpf_prog_attach (sockmap): %d (%s)\n", err, strerror(errno));
		return err;
	}

	/* Attach to cgroups */
	err = bpf_prog_attach(prog_fd[2], cg_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (err) {
		printf("ERROR: bpf_prog_attach (reply): %d (%s)\n", err, strerror(errno));
		return err;
	}

	fprintf(stderr, "BPF_CGROUP_SOCKS_OPS attached: %d\n", err);

	while (running) {
		fprintf(stderr, ".");
		sleep(2);
	}
	return 0;
}

void running_handler(int a)
{
	running = 0;
}
