#include <linux/bpf.h>
#include "bpf_helpers.h"

int _version SEC("version") = 1;

SEC("sk_skb1")
int bpf_prog1(struct __sk_buff *skb)
{
	return skb->len;
}

