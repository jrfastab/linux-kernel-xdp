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
#include <linux/kproxy.h>
#include <linux/kproxy_diag.h>
#include <linux/sock_diag.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <libgen.h>

#include "../bpf/bpf_load.h"
#include "../bpf/bpf_util.h"
#include "../bpf/libbpf.h"

#define AF_KPROXY	44

#define FRONTEND_PORT 9000
#define BACKEND_PORT 9800
#define BACKEND2_PORT 9900

struct kproxy_socks {
	int server;
	int accept;
	int client;
	int port;
	char *name;
	char msg[100];
	bool sender;
	bool recv;
};

int running, kproxy;
struct kproxy_join join, add, unjoin;
struct kproxy_attach attach;

static void *client_handler(void *fd)
{
	struct sockaddr_in client_in;
	struct kproxy_socks *ks;
	char buf[82];
	int err, one = 1;

	ks = (struct kproxy_socks *)fd;

	ks->client = socket(AF_INET, SOCK_STREAM, 0);
	if (ks->client < 0) {
		perror("client socket err\n");
		return NULL;
	}

	err = setsockopt(ks->client,
			 SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
			 &one, sizeof(one));
	if (err) {
		perror("setosckopt RESUSE failed\n");
		return NULL;
	}

	memset(&client_in, 0, sizeof(struct sockaddr_in));
	client_in.sin_family = AF_INET;
	client_in.sin_addr.s_addr = inet_addr("127.0.0.1");
	client_in.sin_port = htons(ks->port);

	printf("%s: connecting  @ %i...\n", ks->name, ks->port);
	err = connect(ks->client,
		      (struct sockaddr *)&client_in, sizeof(client_in));
	if (err < 0) {
		perror("connect error\n");
		return NULL;
	}
	printf("%s: connected  @ %i...\n", ks->name, ks->port);

	while (running) {
		if (ks->sender) {
			err = write(ks->client, ks->msg, strlen(ks->msg));
			if (err < 0)
				perror("client_handler sender error");
#ifdef DEBUG
			printf("send(@%s:%i:%lu -- %s\n", ks->name, err, strlen(ks->msg), ks->msg); 
#endif
		}
		if (ks->recv) {
			err = recv(ks->client, buf, 80, 0);
			if (err < 0) {
				perror("client handler recv error\n");
			} else {
#ifdef DEBBUG
				int i;

				printf("recv(@%s:%i): ", ks->name, err);
				for (i = 0; i < err; i++)
					printf(".%c", buf[i]);
				printf("\n");
#endif
			}
		}
		sleep(1);
	}

	close(ks->client);
	return NULL;
}

static void *server_handler(void *fd)
{
	struct sockaddr_in server_in, client_in;
	struct kproxy_socks *ks;
	int err, one = 1;
	char buf[82];
	size_t _c;

	ks = (struct kproxy_socks *)fd;

	ks->server = socket(AF_INET, SOCK_STREAM, 0);
	if (ks->server < 0) {
		printf("server socket err\n");
		return NULL;
	}

	err = setsockopt(ks->server,
			 SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
			 &one, sizeof(one));
	if (err) {
		perror("setosckopt RESUSE failed\n");
		return NULL;
	}

	memset(&server_in, 0, sizeof(struct sockaddr_in));
	server_in.sin_family = AF_INET;
	server_in.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_in.sin_port = htons(ks->port);

	err = bind(ks->server,
		   (struct sockaddr *)&server_in, sizeof(server_in));
	if (err < 0) {
		perror("bind error\n");
		return NULL;
	}

	printf("%s: server listening @ %i\n", ks->name, ks->port);
	listen(ks->server, 1);
	_c = sizeof(struct sockaddr_in);
	ks->accept = accept(ks->server,
			    (struct sockaddr *)&client_in, (socklen_t *)&_c);
	if (ks->accept < 0) {
		printf("accept error\n");
		return NULL;
	}

	printf("%s: server accepted @ %i\n", ks->name, ks->port);
	while (running) {
		if (ks->sender) {
			err = write(ks->accept, ks->msg, 4);//strlen(ks->msg));
			if (err < 0)
				perror("server handler sender error");
#ifdef DEBUG
			printf("send(@%s:%i:%u -- %s\n", ks->name, err, strlen(ks->msg), ks->msg); 
#endif
		}

		if (ks->recv) {
			err = recv(ks->accept, buf, 80, 0);
			if (err < 0) {
				printf("recv error @%s:%i\n", ks->name, err);
				perror("server handler recv error\n");
			} else {
#ifdef DEBUG
				int i;

				printf("recv(@%s:%i): ", ks->name, err);
				for (i = 0; i < err; i++)
					printf(".%c", buf[i]);
				printf("\n");
#endif
			}
		}
		sleep(1);
	}

	close(ks->accept);
	close(ks->server);
	return NULL;
}

void running_handler(int a);

struct diag_req {
	struct nlmsghdr nlh;
	struct kproxy_diag_req r;
};

struct diag_reply {
	struct nlmsghdr nlh;
	struct kproxy_diag_msg r;
};

#define SEQ_SEED 123456

static int rtnl_open(void)
{
	socklen_t addr_len;
	struct sockaddr_nl local;
	int rcvbuf = 1024 * 1024;
	int sndbuf = 32768;
	int fd, err;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
	if (fd < 0) {
		perror("Cannot open netlink socket");
		return fd;
	}

	err = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	if (err < 0) {
		perror("SO_SNDBUF");
		return err;
	}

	err = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	if (err < 0) {
		perror("SO_RCVBUF");
		return err;
	}

	addr_len = sizeof(local);
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = 0;
	err = bind(fd, (struct sockaddr*)&local, addr_len);
	if (err	< 0) {
		perror("Cannot bind netlink socket");
		return err;
	}

	err = getsockname(fd, (struct sockaddr*)&local, &addr_len);
	if (err	< 0) {
		perror("Cannot getsockname");
		return err;
	}
	if (addr_len != sizeof(local)) {
		fprintf(stderr, "Wrong address length %d\n", addr_len);
		return -EINVAL;
	}
	if (local.nl_family != AF_NETLINK) {
		fprintf(stderr, "Wrong address family %d\n", local.nl_family);
		return -EINVAL;
	}

	return fd;
}

#define NLATTR_LENGTH(len) (NLA_ALIGN(sizeof(struct nlattr)) + (len))
#define NLATTR_DATA(nlattr) ((void *)(((char*)(nlattr)) + NLATTR_LENGTH(0)))
#define NLATTR_PAYLOAD(nlattr) ((int)((nlattr)->nla_len) - NLATTR_LENGTH(0))
#define NLATTR_TYPE(nlattr) (nlattr->nla_type)

#define NLATTR_OK(attr,len) ((len) >= (int)sizeof(struct nlattr) && \
			       (attr)->nla_len >= sizeof(struct nlattr) && \
			       (attr)->nla_len <= (len))
#define NLATTR_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nla_len), \
				  (struct nlattr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nla_len)))


#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

static void show_psock_info(struct nlattr *nlh, int len)
{
	struct nlattr *attr = NLATTR_DATA(nlh);
	struct kproxy_diag_psock_stats *stats = NLATTR_DATA(attr);

#ifdef DEBUG
	printf("attr len %i type %i\n", __func__, attr->nla_len, attr->nla_type);
#endif
	printf("\ttx bytes %llu rx_bytes %llu\n", stats->tx_bytes, stats->rx_bytes);

	attr = NLATTR_NEXT(attr, len);

	if (attr->nla_type == KPROXY_DIAG_PSOCK_AF_INET) {
		struct kproxy_diag_psock_inet *inet = NLATTR_DATA(attr);

		printf("\taf_inet: %u.%u.%u.%u:%u->%u.%u.%u.%u:%u\n",
			NIPQUAD(inet->saddr), inet->sport,
			NIPQUAD(inet->daddr), inet->dport);
	} else if (attr->nla_type == KPROXY_DIAG_PSOCK_AF_INET6) {
		printf("\taf_inet6:\n");
	} else {
		printf("\t<unknown socket type>\n");
	}
}

static void show_proxy_info(struct nlattr *nlh, int len)
{
	struct nlattr *psock_list = NLATTR_DATA(nlh);
	struct nlattr *psock = NLATTR_DATA(psock_list);

	while (NLATTR_OK(psock, len)) {
		show_psock_info(psock, len);
		psock = NLATTR_NEXT(psock, len);

#ifdef DEBUG
		printf("%s: psock_list type %i len %i->%i->%i:%i psock %i %i\n",
			__func__, psock_list->nla_type, plen, olen, len, psock_list->nla_len,
			psock->nla_type, psock->nla_len);
#endif
	}
}

static void show_reply(struct nlmsghdr *nlh, int len)
{
	struct kproxy_diag_msg *reply = NLMSG_DATA(nlh);
	struct nlattr *proxy_list;

#ifdef DEBUG
	printf("family %u num %u cookie %08x\n",
		reply->kdiag_family, reply->kdiag_num,
		reply->kdiag_cookie[0]);
#else
	printf("%08x:\n", reply->kdiag_cookie[0]);
#endif

	proxy_list = (struct nlattr *)((char *)reply + NLMSG_ALIGN(sizeof(*reply)));

	//len = NLATTR_PAYLOAD(proxy_list);
	while (NLATTR_OK(proxy_list, len)) {
		show_proxy_info(proxy_list, len);
		proxy_list = NLATTR_NEXT(proxy_list, len);
	}
}

static void kproxy_query(void)
{
	int fd;
	struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK };
	struct diag_req req = {.nlh = {
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_ROOT | NLM_F_REQUEST,
			.nlmsg_seq = SEQ_SEED,
			.nlmsg_len = sizeof(req),
		},
	};
	struct nlmsghdr *n;
	struct msghdr msg;
	struct iovec iov[1];
	int err, iovlen = 1; 
	char buf[32768];

	/* open socket diag */
	fd = rtnl_open();
	if (fd < 0)
		return;

	/* kproxy request */
	memset(&req.r, 0, sizeof(req.r));
	req.r.diag_family = AF_KPROXY;
	//req.r.diag_protocol =  0;

	/* common nlmsg setup for sock diag request */
	iov[0].iov_base = &req;
	iov[0].iov_len = sizeof(req);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen,

	err = sendmsg(fd, &msg, 0);
	if (err < 0) {
		perror("sendmsg error");
		goto out;
	}
	
	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);
	err = recvmsg(fd, &msg, 0);
	if (err < 0) {
		perror("recvmsg error");
		goto out;
	}

#if 0
	if (err != sizeof(*reply)) {
		printf("kproxy query return size invalid (%i != %lu)\n", err, sizeof(*reply));
		goto out;
	}
#endif

	n = buf;
	//while (NLMSG_OK(n, err)) {
	if (n->nlmsg_type == NLMSG_ERROR) {
		printf("nlmsg reply errors\n");
		goto out;
	}
	show_reply(n, err);
	//	n = NLMSG_NEXT(n, err);
	//}
out:
	close(fd);
}

/* a bunch of global context */
struct kproxy_socks frontend_client = {0}, frontend_server = {0};
struct kproxy_socks backend_client = {0}, backend_server = {0};
struct kproxy_socks backend2_client = {0}, backend2_server = {0};

int main(int argc, char **argv)
{
	pthread_t frontend_client_t, frontend_server_t;
	pthread_t backend_client_t, backend_server_t;
	pthread_t backend2_client_t, backend2_server_t;
	int err, cg_fd, key;
	char filename[256];
	char *cg_path;

	cg_path = argv[argc - 1];
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return 1;
	}

	if (!prog_fd[0]) {
		printf("load_bpf_file prog_fd[0]: %s\n", strerror(errno));
		return 1;
	}

	running = 1;

	/* catch SIGINT */
	signal(SIGINT, running_handler);

	/* Configure Frontend */
	frontend_client.name = "frontend_client";
	frontend_client.msg[0] = 0x02;
	frontend_client.msg[1] = 0x02;
	frontend_client.msg[2] = 0x03;
	frontend_client.msg[3] = 0x04;
	frontend_client.msg[4] = 0x00;//"1hello frontend_client here\n";
	frontend_client.port = FRONTEND_PORT;
	frontend_client.sender = true;
	frontend_client.recv = false;

	frontend_server.name = "frontend_server";
	frontend_server.msg[0] = 0x02;//"1hello frontend_server here\n";
	frontend_server.msg[1] = 0x02;//"1hello frontend_server here\n";
	frontend_server.msg[2] = 0x03;//"1hello frontend_server here\n";
	frontend_server.msg[3] = 0x04;//"1hello frontend_server here\n";
	frontend_server.msg[4] = 0x00;//"1hello frontend_server here\n";
	frontend_server.port = FRONTEND_PORT;
	frontend_server.sender = false;
	frontend_server.recv = false;

	/* Configure Backend */
	backend_client.name = "backend_client";
	backend_client.msg[0] = 0x01;//"0hello backend_client here\n";
	backend_client.msg[1] = 0x01;//"0hello backend_client here\n";
	backend_client.msg[2] = 0x02;//"0hello backend_client here\n";
	backend_client.msg[3] = 0x03;//"0hello backend_client here\n";
	backend_client.msg[4] = 0x00;//"0hello backend_client here\n";
	backend_client.port = BACKEND_PORT;
	backend_client.sender = false;
	backend_client.recv = false;

	backend_server.name = "backend_server";
	backend_server.msg[0] = 0x01;// "0hello backend_server here\n";
	backend_server.msg[1] = 0x01;//"0hello backend_server here\n";
	backend_server.msg[2] = 0x02;//"0hello backend_server here\n";
	backend_server.msg[3] = 0x03;//"0hello backend_server here\n";
	backend_server.msg[4] = 0x00;//"0hello backend_server here\n";
	backend_server.port = BACKEND_PORT;
	backend_server.sender = true;
	backend_server.recv = true;

	/* Backend to ADD as second endpoint */
	backend2_client.name = "backend2_client";
	backend2_client.msg[0] = 0x01;//"0hello backend2_client here\n";
	backend2_client.msg[1] = 0x01;//"0hello backend2_client here\n";
	backend2_client.msg[2] = 0x02;//"0hello backend2_client here\n";
	backend2_client.msg[3] = 0x03;//"0hello backend2_client here\n";
	backend2_client.msg[4] = 0x00;//"0hello backend2_client here\n";
	backend2_client.port = BACKEND2_PORT;
	backend2_client.sender = false;
	backend2_client.recv = false;

	backend2_server.name = "backend2_server";
	backend2_server.msg[0] = 0x01;//"0hello backend2_server here\n";
	backend2_server.msg[1] = 0x01;//"0hello backend2_server here\n";
	backend2_server.msg[2] = 0x02;//"0hello backend2_server here\n";
	backend2_server.msg[3] = 0x03;//"0hello backend2_server here\n";
	backend2_server.msg[4] = 0x00;//"0hello backend2_server here\n";
	backend2_server.port = BACKEND2_PORT;
	backend2_server.sender = false;
	backend2_server.recv = true;

	sleep(1);

	/* setup kproxy socket */
	kproxy = socket(AF_KPROXY, SOCK_DGRAM, 0);
	if (kproxy < 0) {
		perror("kproxy error\n");
		return 1;
	}

	attach.bpf_fd_parse = prog_fd[0];
	attach.bpf_fd_mux = prog_fd[1];
	attach.max_peers = 3;

	printf("attach kproxy to bpf\n");
	err = ioctl(kproxy, SIOCKPROXYATTACH, &attach);
	if (err < 0) {
		perror("attach ioctl error\n");
		return 1;
	}

	/* Add kproxy to sockmap in zero slot */
	key = 0;
	err = bpf_map_update_elem(map_fd[0], &key, &kproxy, 0);
	if (err) {
		perror("sockmap kproxy insert failed: bpf_update_elem");
		return 1;
	}

	/* Cgroup configuration */
	cg_fd = open(cg_path, O_DIRECTORY, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "ERROR: (%i) open cg path failed: %s\n", cg_fd, cg_path);
		return cg_fd;
	}
	fprintf(stderr, "CG_FD open %i:%s\n", cg_fd, cg_path);

	/* Attach to cgroups */
	err = bpf_prog_attach(prog_fd[2], cg_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (err) {
		printf("ERROR: bpf_prog_attach: %d (%s)\n", err, strerror(errno));
		return err;
	}

	fprintf(stderr, "BPF_CGROUP_SOCKS_OPS attached: %d\n", err);

	/* Create frontend */
	printf("create frontend\n");
	pthread_create(&frontend_server_t, NULL,
		       server_handler, &frontend_server);
	sleep(1);
	pthread_create(&frontend_client_t, NULL,
		       client_handler, &frontend_client);

	sleep(1);

	/* Create backend */
	printf("create backend\n");
	pthread_create(&backend_server_t, NULL,
		       server_handler, &backend_server);
	sleep(1);
	pthread_create(&backend_client_t, NULL,
		       client_handler, &backend_client);

	sleep(1);

	/* Create backend2 */
/*
	printf("create backend2\n");
	pthread_create(&backend2_server_t, NULL,
		       server_handler, &backend2_server);
	sleep(1);
	pthread_create(&backend2_client_t, NULL,
		       client_handler, &backend2_client);
*/

	sleep(1);

	printf("wait for connections\n");
	while ((backend_client.client == 0 ||
		frontend_client.client == 0) && running)
		sleep(1);

	if (!running) {
		printf("not running stop\n");
		return 0;
	}

	sleep(2);


#if 0
	/* Kproxy configuration */
	printf("join frontend and backend\n");
	join.sock_fd = frontend_server.accept;
	join.index = 1;
	err = ioctl(kproxy, SIOCKPROXYJOIN, &join);
	if (err < 0) {
		perror("join ioctl error\n");
		return 1;
	}

	join.sock_fd = backend_client.client;
	join.index = 2;
	err = ioctl(kproxy, SIOCKPROXYJOIN, &join);
	if (err < 0) {
		perror("join ioctl error\n");
		return 1;
	}

#if 0
	printf("add additional backend\n");
	add.sock_fd = backend2_client.client;
	add.index = 2;

	err = ioctl(kproxy, SIOCKPROXYJOIN, &add);
	if (err < 0) {
		perror("join ioctl error\n");
		return 1;
	}
#endif
#endif

	printf("run threads\n");
	while (running) {
		kproxy_query();
		sleep(2);
	}
	pthread_join(frontend_client_t, NULL);
	pthread_join(frontend_server_t, NULL);
	pthread_join(backend_client_t, NULL);
	pthread_join(backend_server_t, NULL);
//	pthread_join(backend2_client_t, NULL);
//	pthread_join(backend2_server_t, NULL);
	printf("test complete\n");
	return 0;
}

void running_handler(int a)
{
	int err;

	printf("test: unjoin server and client\n");
	unjoin.sock_fd = frontend_server.accept;
	err = ioctl(kproxy, SIOCKPROXYUNJOIN, &unjoin);
	unjoin.sock_fd = backend_client.client;
	err = ioctl(kproxy, SIOCKPROXYUNJOIN, &unjoin);
	unjoin.sock_fd = backend2_client.client;
	err = ioctl(kproxy, SIOCKPROXYUNJOIN, &unjoin);
	if (err < 0)
		perror("ioctl error unjoin\n");

	printf("wait then stop threads\n");
	sleep(2);
	running = 0;
}

