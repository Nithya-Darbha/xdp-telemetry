// SPDX-License-Identifier: GPL-2.0
/* XDP telemetry program.
 *
 * Phase 3: parse every frame and count outcomes in a per-CPU array.
 * Flow maps, fan-out sketches and the event ring buffer arrive in phase 4.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "shared/types.h"
#include "parse.h"

/* Global counters, one slot per enum xdpt_counter.
 * PERCPU_ARRAY: each CPU gets its own copy of every slot, so increments need
 * no atomics and never bounce cache lines. Userspace reads all copies and
 * sums them. The cost is that a read is not a snapshot across CPUs, which is
 * fine for counters that only grow. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDPT_C__MAX);
	__type(key, __u32);
	__type(value, __u64);
} xdpt_counters SEC(".maps");

static __always_inline void cnt_add(__u32 idx, __u64 v)
{
	__u64 *slot = bpf_map_lookup_elem(&xdpt_counters, &idx);
	if (slot) /* the verifier rejects the dereference without this check */
		*slot += v;
}

SEC("xdp")
int xdpt_main(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct pkt_meta m;
	int res = xdpt_parse(data, data_end, (__u32)(data_end - data), &m);

	cnt_add(XDPT_C_PKTS, 1);
	cnt_add(XDPT_C_BYTES, m.frame_len);
	cnt_add(XDPT_C_RESULT_BASE + (__u32)res, 1);

	if (res == XDPT_P_OK) {
		if (m.is_frag)
			cnt_add(XDPT_C_FRAG, 1);
		switch (m.proto) {
		case IPPROTO_TCP:  cnt_add(XDPT_C_TCP, 1); break;
		case IPPROTO_UDP:  cnt_add(XDPT_C_UDP, 1); break;
		case IPPROTO_ICMP: cnt_add(XDPT_C_ICMP, 1); break;
		default:           cnt_add(XDPT_C_L4_OTHER, 1); break;
		}
	}
	return XDP_PASS; /* monitor only: never drop, never rewrite */
}

char LICENSE[] SEC("license") = "GPL";
