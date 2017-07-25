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

#define FRONTEND_MAX = 10
#define BACKEND_MAX = 10

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	return skb->len;
}

#define NUM_PEERS 3

SEC("socket2")
int bpf_prog2(struct __sk_buff *skb)
{
	__u8 proto[8];
	int ret;

	bpf_printk("run bpf prog2\n");

	ret = bpf_skb_load_bytes(skb, 0, &proto, 3);
	bpf_printk("data:%d %d %d\n", proto[0], proto[1], proto[2]);

	return proto[0];// % NUM_PEERS;
}

SEC("sockops")
int bpf_kproxy(struct bpf_sock_ops *skops)
{
	__u32 lport, rport;
	int op, err = 0, index;


	op = (int) skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		lport = skops->local_port;
		rport = skops->remote_port;
		bpf_printk("passive_established: %d -> %d\n", lport, bpf_ntohl(rport));

		if (lport == 9000) {
			err = bpf_sk_redirect_map(skops, &kproxy_map, 0, 1, 0);
		}
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		lport = skops->local_port;
		rport = skops->remote_port;

		bpf_printk("active_established_cb: %d -> %d\n", lport, bpf_ntohl(rport));

		if (bpf_ntohl(rport) == 9800) {
			err = bpf_sk_redirect_map(skops, &kproxy_map, 0, 2, 0);
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
