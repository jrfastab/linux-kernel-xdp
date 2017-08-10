#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>

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

static int error_cnt, pass_cnt;

#define S1_PORT 10001
#define S2_PORT 10000

/* create a frontend / backend connection with sockmap
 *
 *   s1 <--> p1 ---- s2 <--> p2
 *
 * Returns:
 *  - zero on success
 *  - negative value on error in socket setup
 *  - positive value if msgs are not complete
 */
static int traffic_ping_pong(int rate, int msgs, bool verbose)
{
	int i, sc, err, max_fd, one = 1;
	int s1, s2, c1, c2, p1, p2;
	struct sockaddr_in addr;
	struct timeval timeout;
	char buf[1024] = {0};
	int *fds[4] = {&s1, &s2, &c1, &c2};
	fd_set w;

	s1 = s2 = p1 = p2 = c1 = c2 = 0;

	/* Init sockets */
	for (i = 0; i < 4; i++) {
		*fds[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (*fds[i] < 0) {
			perror("socket s1 failed()");
			err = *fds[i];
			goto out;
		}
	}

	/* Allow reuse */
	for (i = 0; i < 2; i++) {
		err = setsockopt(*fds[i], SOL_SOCKET, SO_REUSEADDR,
				 (char *)&one, sizeof(one));
		if (err) {
			perror("setsockopt failed()");
			goto out;
		}
	}

	/* Non-blocking sockets */
	for (i = 0; i < 4; i++) {
		err = ioctl(*fds[i], FIONBIO, (char *)&one);
		if (err < 0) {
			perror("ioctl s1 failed()");
			goto out;
		}
	}

	/* Bind server sockets */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	addr.sin_port = htons(S1_PORT);
	err = bind(s1, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		perror("bind s1 failed()\n");
		goto out;
	}

	addr.sin_port = htons(S2_PORT);
	err = bind(s2, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		perror("bind s2 failed()\n");
		goto out;
	}

	/* Listen server sockets */
	addr.sin_port = htons(S1_PORT);
	err = listen(s1, 32);
	if (err < 0) {
		perror("listen s1 failed()\n");
		goto out;
	}

	addr.sin_port = htons(S2_PORT);
	err = listen(s2, 32);
	if (err < 0) {
		perror("listen s1 failed()\n");
		goto out;
	}

	/* Initiate Connect */
	addr.sin_port = htons(S1_PORT);
	err = connect(c1, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0 && errno != EINPROGRESS) {
		perror("connect c1 failed()\n");
		goto out;
	}

	addr.sin_port = htons(S2_PORT);
	err = connect(c2, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0 && errno != EINPROGRESS) {
		perror("connect c2 failed()\n");
		goto out;
	}

	/* Accept Connecrtions */
	p1 = accept(s1, NULL, NULL);
	if (p1 < 0) {
		perror("accept s1 failed()\n");
		goto out;
	}

	p2 = accept(s2, NULL, NULL);
	if (p2 < 0) {
		perror("accept s1 failed()\n");
		goto out;
	}

	max_fd = p2;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	printf("connected sockets: c1 <-> p1, c2 <-> p2\n");
	printf("cgroups binding: c1(%i) <-> s1(%i) - - - c2(%i) <-> s2(%i)\n",
		c1, s1, c2, s2);

	/* Ping/Pong data from client to server */
	if (verbose)
		printf("ping/pong:");
	sc = send(c1, buf, sizeof(buf), 0);
	if (sc < 0) {
		perror("send failed()\n");
		goto out;
	}

	err = 0;

	for (i = 0; i < msgs || !msgs; i++) {
		int s, rc, i;

		/* FD sets */
		FD_ZERO(&w);
		FD_SET(c1, &w);
		FD_SET(c2, &w);
		FD_SET(p1, &w);
		FD_SET(p2, &w);

		s = select(max_fd + 1, &w, NULL, NULL, &timeout);
		if (s == -1) {
			perror("select()");
			break;
		} else if (!s) {
			fprintf(stderr, "unexpected timeout\n");
			break;
		}

		for (i = 0; i <= max_fd && s > 0; ++i) {
			if (!FD_ISSET(i, &w))
				continue;

			s--;

			rc = recv(i, buf, sizeof(buf), 0);
			if (rc < 0) {
				if (errno != EWOULDBLOCK) {
					perror("recv failed()\n");
					break;
				}
			}

			if (rc == 0) {
				close(i);
				break;
			}

			sc = send(i, buf, rc, 0);
			if (sc < 0) {
				perror("send failed()\n");
				break;
			}
		}
		sleep(rate);
		if (verbose) {
			printf(".");
			fflush(stdout);
		}
	}
	if (verbose)
		printf("\n");

	/* Fail if packet transmission was interrupted */
	if (i != msgs)
		err = i;
out:
	close(s1);
	close(s2);
	close(p1);
	close(p2);
	close(c1);
	close(c2);
	return err;
}

/* BPF programs need to follow test format:
 *
 * prog_fd[0] parse program
 * prog_fd[1] verdict program
 * prog_fd[2] sock ops program
 * map_fd[0]  sockmap
 */
static int load_prog_cgroup(char *bpf_file, char *cg_path,
			    bool attach_progs,
			    bool attach_cgrp)
{
	int err, cg_fd;

	err = load_bpf_file(bpf_file);
	if (err) {
		fprintf(stderr, "bpf_prog_load: (%s) %s\n",
			bpf_file, strerror(errno));
		return 1;
	}

	/* Cgroup configuration */
	cg_fd = open(cg_path, O_DIRECTORY, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "ERROR: (%i) open cg path failed: %s\n",
			cg_fd, cg_path);
		return cg_fd;
	}

	/* Attach programs to sockmap */
	if (attach_progs) {
		err = __bpf_prog_attach(prog_fd[0], prog_fd[1], map_fd[0],
					BPF_CGROUP_SMAP_INGRESS, 0);
		if (err) {
			fprintf(stderr, "ERROR: bpf_prog_attach (sockmap): %d (%s)\n",
				err, strerror(errno));
			return err;
		}
	}

	/* Attach to cgroups */
	if (attach_cgrp) {
		err = bpf_prog_attach(prog_fd[2], cg_fd,
				      BPF_CGROUP_SOCK_OPS, 0);
		if (err) {
			fprintf(stderr, "ERROR: bpf_prog_attach (groups): %d (%s)\n",
				err, strerror(errno));
			return err;
		}
	}
	return 0;
}

static void test_basic_ping_pong(char *bpf_prog, char *cg_path)
{
	int err;

	err = load_prog_cgroup(bpf_prog, cg_path, true, true);
	if (err)
		goto out;

	err = traffic_ping_pong(0, 50000, false);
	if (err) {
		printf("%s: traffic_ping_ping failed()\n", __func__);
		goto out;
	}

	pass_cnt++;
	return;
out:
	error_cnt++;
	return;
}

static void test_invalid_ops(char *bpf_prog, char *cg_path)
{
	int err;
	int slot = 0;
	int garbage = 0xdeadbeef;

	err = load_prog_cgroup(bpf_prog, cg_path, true, true);
	if (err)
		goto out;

	err = bpf_map_update_elem(map_fd[0], &slot, &garbage, BPF_NOEXIST);
	if (!err) {
		printf("%s: map update elem failed()\n", __func__);
		goto out;
	}

	err = bpf_map_lookup_elem(map_fd[0], &slot, &garbage);
	if (!err) {
		printf("%s: map lookup elem failed()\n", __func__);
		goto out;
	}

	pass_cnt++;
	return;
out:
	error_cnt++;
	return;
}

static void test_missing_attach(char *bpf_prog, char *cg_path)
{
	int err;

	err = load_prog_cgroup(bpf_prog, cg_path, false, true);
	if (err)
		goto out;

	err = traffic_ping_pong(0, 500, false);
	if (err) {
		printf("%s: traffic_ping_ping failed()\n", __func__);
		goto out;
	}

	pass_cnt++;
	return;
out:
	error_cnt++;
	return;

}

static void test_attach_flood(char *bpf_prog, char *cg_path)
{
	pid_t pid;
	int err;

	err = load_prog_cgroup(bpf_prog, cg_path, true, true);
	if (err)
		goto out;

	/* not an exact science just throw some attach and ping/pongs
	 * up in the air
	 */
	pid = fork();
	if (pid == 0) {
		err = traffic_ping_pong(0, 50000, false);
		if (err) {
			printf("%s: traffic_ping_ping failed()\n", __func__);
			goto out;
		}
		exit(0);
	} else if (pid == -1) {
		printf("%s couldn't spawn process to test attach\n", __func__);
		goto out;
	} else {
		int i;

		sleep(1);
		for (i = 0; i < 50000; i++) {
			err = __bpf_prog_attach(prog_fd[0], prog_fd[1],
						map_fd[0],
						BPF_CGROUP_SMAP_INGRESS, 0);
			if (err) {
				printf("%s: bpf_prog_attach (sockmap): %d (%s)\n",
					__func__, err, strerror(errno));
				goto out;
			}
			usleep(400);
		}
		sleep(5);
	}

	pass_cnt++;
	return;
out:
	error_cnt++;
	return;

}

static void test_socket_up_down(char *bpf_prog, char *cg_path)
{
	int err, i;

	err = load_prog_cgroup(bpf_prog, cg_path, true, true);
	if (err)
		goto out;

	for (i = 0; i < 10000; i++) {
		err = traffic_ping_pong(0, 1, false);
		if (err) {
			printf("%s: traffic_ping_ping failed()\n", __func__);
			goto out;
		}
	}

	pass_cnt++;
	return;
out:
	error_cnt++;
	return;
}

int main(int argc, char **argv)
{
	char *bpf_prog = "sockmap_kern.o";
	char *cg_path = argv[argc - 1];

	test_basic_ping_pong(bpf_prog, cg_path);
	test_invalid_ops(bpf_prog, cg_path);
	test_missing_attach(bpf_prog, cg_path);
	test_attach_flood(bpf_prog, cg_path);
	test_socket_up_down(bpf_prog, cg_path);

	printf("Summary: %d PASSED, %d FAILED\n", pass_cnt, error_cnt);
	return error_cnt ? EXIT_FAILURE : EXIT_SUCCESS;
}
