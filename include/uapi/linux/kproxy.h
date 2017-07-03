/*
 * Kernel Proxy
 *
 * Copyright (c) 2017 Tom Herbert <tom@herbertland.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * User API to create in-kernel proxies.
 */

#ifndef KPROXYKERNEL_H
#define KPROXYKERNEL_H

struct kproxy_join {
	int client_fd;
	int server_fd;
};

struct kproxy_unjoin {
	int client_fd;
	int server_fd;
};

#define SIOCKPROXYJOIN		(SIOCPROTOPRIVATE + 0)
#define SIOCKPROXYUNJOIN	(SIOCPROTOPRIVATE + 1)

#endif

