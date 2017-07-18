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

#include <linux/kproxy.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <libgen.h>

#include "../bpf/bpf_load.h"
#include "../bpf/bpf_util.h"
#include "../bpf/libbpf.h"

#ifndef AF_KCM
#define AF_KCM		41	/* Kernel Connection Multiplexor*/
#endif

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

volatile int running, kproxy;
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
			printf("send(@%s:%i:%u -- %s\n", ks->name, err, strlen(ks->msg), ks->msg); 
		}
		if (ks->recv) {
			err = recv(ks->client, buf, 80, 0);
			if (err < 0) {
				perror("client handler recv error\n");
			} else {
				int i;

				printf("recv(@%s:%i): ", ks->name, err);
				for (i = 0; i < err; i++)
					printf("%c", buf[i]);
				printf("\n");
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

	while (running) {
		if (ks->sender) {
			err = write(ks->accept, ks->msg, 4);//strlen(ks->msg));
			if (err < 0)
				perror("server handler sender error");
			printf("send(@%s:%i:%u -- %s\n", ks->name, err, strlen(ks->msg), ks->msg); 
		}

		if (ks->recv) {
			err = recv(ks->accept, buf, 80, 0);
			if (err < 0) {
				perror("server handler recv error\n");
			} else {
				int i;

				printf("recv(@%s:%i): ", ks->name, err);
				for (i = 0; i < err; i++)
					printf("%c", buf[i]);
				printf("\n");
			}
		}
		sleep(1);
	}

	close(ks->accept);
	close(ks->server);
	return NULL;
}

void running_handler(int a);

/* a bunch of global context */
struct kproxy_socks frontend_client = {0}, frontend_server = {0};
struct kproxy_socks backend_client = {0}, backend_server = {0};
struct kproxy_socks backend2_client = {0}, backend2_server = {0};

int main(int argc, char **argv)
{
	pthread_t frontend_client_t, frontend_server_t;
	pthread_t backend_client_t, backend_server_t;
	pthread_t backend2_client_t, backend2_server_t;
	int err;
	char filename[256];

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
	frontend_client.msg[0] = 0x01;
	frontend_client.msg[1] = 0x02;
	frontend_client.msg[2] = 0x03;
	frontend_client.msg[3] = 0x04;
	frontend_client.msg[4] = 0x00;//"1hello frontend_client here\n";
	frontend_client.port = FRONTEND_PORT;
	frontend_client.sender = true;
	frontend_client.recv = false;

	frontend_server.name = "frontend_server";
	frontend_server.msg[0] = 0x01;//"1hello frontend_server here\n";
	frontend_server.msg[1] = 0x02;//"1hello frontend_server here\n";
	frontend_server.msg[2] = 0x03;//"1hello frontend_server here\n";
	frontend_server.msg[3] = 0x04;//"1hello frontend_server here\n";
	frontend_server.msg[4] = 0x00;//"1hello frontend_server here\n";
	frontend_server.port = FRONTEND_PORT;
	frontend_server.sender = false;
	frontend_server.recv = false;

	/* Configure Backend */
	backend_client.name = "backend_client";
	backend_client.msg[0] = 0x00;//"0hello backend_client here\n";
	backend_client.msg[1] = 0x01;//"0hello backend_client here\n";
	backend_client.msg[2] = 0x02;//"0hello backend_client here\n";
	backend_client.msg[3] = 0x03;//"0hello backend_client here\n";
	backend_client.msg[4] = 0x00;//"0hello backend_client here\n";
	backend_client.port = BACKEND_PORT;
	backend_client.sender = false;
	backend_client.recv = false;

	backend_server.name = "backend_server";
	backend_server.msg[0] = 0x00;// "0hello backend_server here\n";
	backend_server.msg[1] = 0x01;//"0hello backend_server here\n";
	backend_server.msg[2] = 0x02;//"0hello backend_server here\n";
	backend_server.msg[3] = 0x03;//"0hello backend_server here\n";
	backend_server.msg[4] = 0x00;//"0hello backend_server here\n";
	backend_server.port = BACKEND_PORT;
	backend_server.sender = false;
	backend_server.recv = true;

	/* Backend to ADD as second endpoint */
	backend2_client.name = "backend2_client";
	backend2_client.msg[0] = 0x00;//"0hello backend2_client here\n";
	backend2_client.msg[1] = 0x01;//"0hello backend2_client here\n";
	backend2_client.msg[2] = 0x02;//"0hello backend2_client here\n";
	backend2_client.msg[3] = 0x03;//"0hello backend2_client here\n";
	backend2_client.msg[4] = 0x00;//"0hello backend2_client here\n";
	backend2_client.port = BACKEND2_PORT;
	backend2_client.sender = false;
	backend2_client.recv = false;

	backend2_server.name = "backend2_server";
	backend2_server.msg[0] = 0x00;//"0hello backend2_server here\n";
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

	/* Create frontend */
	pthread_create(&frontend_server_t, NULL,
		       server_handler, &frontend_server);
	sleep(1);
	pthread_create(&frontend_client_t, NULL,
		       client_handler, &frontend_client);

	sleep(1);

	/* Create backend */
	pthread_create(&backend_server_t, NULL,
		       server_handler, &backend_server);
	sleep(1);
	pthread_create(&backend_client_t, NULL,
		       client_handler, &backend_client);

	sleep(1);

	/* Create backend2 */
	pthread_create(&backend2_server_t, NULL,
		       server_handler, &backend2_server);
	sleep(1);
	pthread_create(&backend2_client_t, NULL,
		       client_handler, &backend2_client);

	sleep(1);

	while ((backend_client.client == 0 ||
		frontend_client.client == 0) && running)
		sleep(1);

	if (!running)
		return 0;

	sleep(2);

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
	join.sock_fd = frontend_server.accept;
	join.index = 0;
	err = ioctl(kproxy, SIOCKPROXYJOIN, &join);
	if (err < 0) {
		perror("join ioctl error\n");
		return 1;
	}

	join.sock_fd = backend_client.client;
	join.index = 1;
	err = ioctl(kproxy, SIOCKPROXYJOIN, &join);
	if (err < 0) {
		perror("join ioctl error\n");
		return 1;
	}

	printf("add additional backend\n");
	add.sock_fd = backend2_client.client;
	add.index = 2;

	err = ioctl(kproxy, SIOCKPROXYJOIN, &add);
	if (err < 0) {
		perror("join ioctl error\n");
		return 1;
	}

	pthread_join(frontend_client_t, NULL);
	pthread_join(frontend_server_t, NULL);
	pthread_join(backend_client_t, NULL);
	pthread_join(backend_server_t, NULL);
	pthread_join(backend2_client_t, NULL);
	pthread_join(backend2_server_t, NULL);
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

