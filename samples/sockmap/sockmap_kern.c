#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include "../../tools/testing/selftests/bpf/bpf_helpers.h"
#include "../../tools/testing/selftests/bpf/bpf_endian.h"

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

struct bpf_map_def SEC("maps") kproxy_map = {
	.type = BPF_MAP_TYPE_SOCKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") reply_port = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1,
};

#define FRONTEND_MAX = 10
#define BACKEND_MAX = 10

#define FRONTEND_PORT = 1 
#define BACKEND_PORT = 1

#define SVC_IP4 = 2.2.2.2

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	return skb->len;
}

#define NUM_PEERS 3

SEC("socket2")
int bpf_prog2(struct __sk_buff *skb)
{
	int ret = 0, loc = 0, *l, lp;
	__u32 local_port = bpf_skb_get_local_port(skb);
	__u32 remote_port = bpf_skb_get_remote_port(skb);
	/*    client:X <---> frontend:80 client:X <---> backend:80
	 *    A proxy has two components a frontend and backend here
	 *    we use kproxy to attach frontend:80 to client:X without
	 *    user space context switch and copy.
	 */
	if (local_port == 10001) {
		ret = 10;
	} else {
		ret=1;
		l = bpf_map_lookup_elem(&reply_port, &loc);
		lp = l ? *l : 0;
#if 0
		if (local_port == lp)
			ret = 1;
#endif
		bpf_printk("local_port %d lp %d ret %d\n", local_port, lp, ret);
	}

	bpf_printk("kproxy: %d -> %d return %d\n", local_port, remote_port, ret);
	bpf_printk("kproxy: local port %d remote port ntohl %d\n",
		bpf_ntohl(local_port), bpf_ntohl(remote_port));
	bpf_printk("kproxy: return %i\n", ret);

	return bpf_sk_redirect_map(&kproxy_map, ret, 0);
}


SEC("sockops")
int bpf_kproxy(struct bpf_sock_ops *skops)
{
	__u32 lport, rport;
	__u32 daddr, saddr;
	int op, err = 0, index, key, ret;


	op = (int) skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		lport = skops->local_port;
		rport = skops->remote_port;
		saddr = skops->local_ip4;
		daddr = skops->remote_ip4;

		if (0) {//lport == 80) {
			bpf_printk("family: %i\n", skops->family);
			bpf_printk("passive_established: %u.%u.%u",
				((unsigned char *)&saddr)[0],
				((unsigned char *)&saddr)[1],
				((unsigned char *)&saddr)[2]);
			bpf_printk("%u:%d -> ",
				((unsigned char *)&saddr)[3],
				lport);
 			bpf_printk("%u.%u.%u",
				((unsigned char *)&daddr)[0],
				((unsigned char *)&daddr)[1],
				((unsigned char *)&daddr)[2]);
 			bpf_printk("%u:%d\n",
				((unsigned char *)&daddr)[3], bpf_ntohl(rport));
		}


		if ((((unsigned char *)&saddr)[3] == 238) &&
		    (((unsigned char *)&saddr)[2] == 28)) {

		if (1) {//lport == 80) {
			bpf_printk("family: %i\n", skops->family);
			bpf_printk("passive_established: %u.%u.%u",
				((unsigned char *)&saddr)[0],
				((unsigned char *)&saddr)[1],
				((unsigned char *)&saddr)[2]);
			bpf_printk("%u:%d -> ",
				((unsigned char *)&saddr)[3],
				lport);
 			bpf_printk("%u.%u.%u",
				((unsigned char *)&daddr)[0],
				((unsigned char *)&daddr)[1],
				((unsigned char *)&daddr)[2]);
 			bpf_printk("%u:%d\n",
				((unsigned char *)&daddr)[3], bpf_ntohl(rport));
		}

			ret = 1;
			bpf_map_ctx_update_elem(skops, &kproxy_map, &ret, 1, 0x00);
			//bpf_sk_redirect_map(skops, &kproxy_map, 0, 1, 0x00);
			if (!err)
				bpf_printk("sk_redirect_map join success: 1: %d\n", err);
		}
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		lport = skops->local_port;
		rport = skops->remote_port;
		saddr = skops->local_ip4;
		daddr = skops->remote_ip4;
		if (bpf_ntohl(rport) == 80 && ((unsigned char *)&saddr)[3] == 238) {

		if (1) {
			bpf_printk("family: %i\n", skops->family);
			bpf_printk("active_established_cb: %u.%u.%u",
				((unsigned char *)&saddr)[0],
				((unsigned char *)&saddr)[1],
				((unsigned char *)&saddr)[2]);
			bpf_printk("%u:%d -> %d\n",
				((unsigned char *)&saddr)[3],
				lport);
 			bpf_printk("%u.%u.%u",
				((unsigned char *)&daddr)[0],
				((unsigned char *)&daddr)[1],
				((unsigned char *)&daddr)[2]);
 			bpf_printk("%u:%d\n",
				((unsigned char *)&daddr)[3], bpf_ntohl(rport));
		}

			ret = 10;
			//bpf_map_ctx_update_elem(&kproxy_map, &ret, skops, 0);
			//bpf_sk_redirect_map(skops, &kproxy_map, 0, 10, 0x02);
			err = bpf_map_ctx_update_elem(skops, &kproxy_map, &ret, 1, 0x01);
			key = 0;
			err = bpf_map_update_elem(&reply_port, &key, &lport, BPF_ANY);
			bpf_printk("sk_redirect_map join success: 10: %d\n", err);
		}
		break;
	default:
		break;
	}

	if (err)
		bpf_printk("sk_redirect_map err: %d\n", err);
	return 0;
}
char _license[] SEC("license") = "GPL";
