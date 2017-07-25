#ifndef __KPROXY_DIAG_H__
#define __KPROXY_DIAG_H__

#include <linux/inet_diag.h>
#include <linux/types.h>

struct kproxy_diag_req {
	__u8	diag_family;
	__u8	pad[2];
	__u8	diag_ext;		/* Query extended information */
	struct inet_diag_sockid	id;
};

#define KPROXY_SHOW_INFO	0x00000001 /* Basic packet_sk information */
#define KPROXY_SHOW_PROXY_LIST	0x00000002 /* List of running proxies */

struct kproxy_diag_msg {
	__u8	kdiag_family;
	__u16	kdiag_num;
	__u32	kdiag_cookie[2];
};

/* data structure for kproxy sock diag is as follows:
 *
 * kproxy_diag_info
 * kproxy_diag_proxy_list
 * 	kproxy_psock_list
 * 		psock
 * 			psock_stats
 * 			psock_inet
 * 			psock_index
 * 			psock_default
 * 		...
 * 		psock
 */
enum {
	/* KPROXY_DIAG_NONE, standard nl API requires this attribute!  */
	KPROXY_DIAG_INFO,
	KPROXY_DIAG_PROXY_LIST,

	__KPROXY_DIAG_MAX,
};

#define KPROXY_DIAG_MAX (__KPROXY_DIAG_MAX - 1)

enum {
	KPROXY_DIAG_PSOCK_LIST,

	__KPROXY_DIAG_PSOCK_LIST_MAX,
};

#define KPROXY_DIAG_PROXY_LIST_MAX (__KPROXY_DIAG_PROXY_LIST_MAX - 1)

enum {
	KPROXY_DIAG_PSOCK_ATTR_LIST,

	__KPROXY_DIAG_PSOCK_ATTR_LIST_MAX,
};

#define KPROXY_DIAG_PROXY_ATTR_LIST_MAX (__KPROXY_DIAG_PROXY_ATTR_LIST_MAX - 1)


enum {
	KPROXY_DIAG_PSOCK_STATS,
	KPROXY_DIAG_PSOCK_AF_INET,
	KPROXY_DIAG_PSOCK_AF_INET6,

	__KPROXY_DIAG_PSOCK_MAX,
};

#define KPROXY_DIAG_PSOCK_MAX (__KPROXY_DIAG_PSOCK_MAX - 1)

struct kproxy_diag_psock_stats {
	unsigned long long tx_bytes;
	unsigned long long rx_bytes;
};

struct kproxy_diag_psock_inet {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
};

struct kproxy_diag_psock_inet6 {
	__be16 sport;
	__be16 dport;
};

#endif
