// SPDX-License-Identifier: GPL-2.0
/* XDP telemetry program.
 *
 * Per packet: parse, then update
 *   xdpt_counters  PERCPU_ARRAY  global counters (no atomics, summed in userspace)
 *   xdpt_sizes     PERCPU_ARRAY  frame size histogram
 *   xdpt_flows     LRU_HASH      5-tuple -> flow_stats (shared, atomics)
 *   xdpt_srcs      LRU_HASH      saddr -> two tumbling-window slots with
 *                                dst port / dst IP fan-out sketches
 *   xdpt_events    RINGBUF       illegal TCP flags, malformed frames
 * and always return XDP_PASS.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "shared/types.h"
#include "parse.h"
#include "sketch.h"

/* Set by userspace before load (skeleton rodata). const volatile keeps
 * clang from folding the default value into the code. */
const volatile __u64 cfg_window_ns = 1000000000ULL;
const volatile __u8  cfg_events = 1;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDPT_C__MAX);
	__type(key, __u32);
	__type(value, __u64);
} xdpt_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDPT_SIZE_BUCKETS);
	__type(key, __u32);
	__type(value, __u64);
} xdpt_sizes SEC(".maps");

/* Shared LRU hash rather than LRU_PERCPU_HASH: a per-CPU hash multiplies
 * memory by the CPU count and splits one flow across CPUs. On a real NIC,
 * RSS pins a flow to one queue and one CPU, so the atomic increments below
 * almost never contend. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XDPT_FLOW_MAX);
	__type(key, struct flow_key);
	__type(value, struct flow_stats);
} xdpt_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XDPT_SRC_MAX);
	__type(key, __u32);
	__type(value, struct src_window);
} xdpt_srcs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, XDPT_RINGBUF_BYTES);
} xdpt_events SEC(".maps");

static __always_inline void cnt_add(__u32 idx, __u64 v)
{
	__u64 *slot = bpf_map_lookup_elem(&xdpt_counters, &idx);
	if (slot) /* the verifier rejects the dereference without this check */
		*slot += v;
}

/* Lookup, or insert then lookup. Two CPUs can both miss and both insert:
 * BPF_NOEXIST makes the second insert fail harmlessly, and both then find
 * the same entry on the second lookup. */
static __always_inline void *lookup_or_init(void *map, const void *key,
					    const void *init, __u32 fail_ctr)
{
	void *v = bpf_map_lookup_elem(map, key);
	if (v)
		return v;
	bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	v = bpf_map_lookup_elem(map, key);
	if (!v)
		cnt_add(fail_ctr, 1);
	return v;
}

static __always_inline void flow_update(const struct pkt_meta *m, __u64 now)
{
	struct flow_key k;
	__builtin_memset(&k, 0, sizeof(k)); /* zero the padding: keys compare as bytes */
	k.saddr = m->saddr;
	k.daddr = m->daddr;
	k.sport = m->sport;
	k.dport = m->dport;
	k.proto = m->proto;

	struct flow_stats init;
	__builtin_memset(&init, 0, sizeof(init));
	init.first_ns = now;
	init.min_len = 0xffff;

	struct flow_stats *fs = lookup_or_init(&xdpt_flows, &k, &init, XDPT_C_FLOW_FAIL);
	if (!fs)
		return;

	__u16 len = m->frame_len > 0xffff ? 0xffff : (__u16)m->frame_len;
	__sync_fetch_and_add(&fs->pkts, 1);
	__sync_fetch_and_add(&fs->bytes, m->frame_len);
	fs->last_ns = now;
	if (len < fs->min_len)
		fs->min_len = len;
	if (len > fs->max_len)
		fs->max_len = len;

	if (m->proto == IPPROTO_TCP && m->l4_valid) {
		__u8 f = m->tcp_flags;
		__sync_fetch_and_or(&fs->flags_seen, (__u32)f);
		if ((f & (XDPT_TCP_SYN | XDPT_TCP_ACK)) == XDPT_TCP_SYN)
			__sync_fetch_and_add(&fs->syn, 1);
		if (f & XDPT_TCP_RST)
			__sync_fetch_and_add(&fs->rst, 1);
	}
}

/* Insert template for xdpt_srcs. 464 bytes do not fit next to everything
 * else on the 512-byte BPF stack (clang refuses: "BPF stack limit is
 * exceeded"), so it lives in global data, which libbpf backs with an array
 * map; a map value pointer is a valid argument to bpf_map_update_elem.
 * Both slot epochs start at 0, which never equals a real epoch after the
 * first window since boot, so the first packet always clears its slot. */
static const struct src_window src_zero;

static __always_inline void src_update(const struct pkt_meta *m, __u64 now, int fclass)
{
	__u32 key = m->saddr;
	struct src_window *w = lookup_or_init(&xdpt_srcs, &key, &src_zero, XDPT_C_SRC_FAIL);
	if (!w)
		return;

	__u64 ep = now / cfg_window_ns;
	struct src_slot *s = &w->slot[ep & 1];

	if (s->epoch != ep) {
		/* First packet from this source in this window on this CPU's view.
		 * Clear the slot, then publish the epoch. Two CPUs may both clear;
		 * a few bits set in between are lost. Only happens at a window edge. */
		__builtin_memset(&s->pkts, 0, sizeof(*s) - sizeof(s->epoch));
		s->epoch = ep;
	}

	__sync_fetch_and_add(&s->pkts, 1);
	__sync_fetch_and_add(&s->bytes, m->frame_len);

	__u32 ib = xdpt_sketch_bit(m->daddr, XDPT_SEED_IP, XDPT_IP_BM_WORDS);
	__sync_fetch_and_or(&s->ip_bm[(ib >> 6) & (XDPT_IP_BM_WORDS - 1)], 1ULL << (ib & 63));

	if (!m->l4_valid || m->proto == IPPROTO_ICMP)
		return; /* ICMP "ports" are type/code, not a port fan-out */

	__u32 pb = xdpt_sketch_bit(m->dport, XDPT_SEED_PORT, XDPT_PORT_BM_WORDS);
	__sync_fetch_and_or(&s->port_bm[(pb >> 6) & (XDPT_PORT_BM_WORDS - 1)], 1ULL << (pb & 63));

	if (m->proto == IPPROTO_TCP) {
		__u8 f = m->tcp_flags;
		if ((f & (XDPT_TCP_SYN | XDPT_TCP_ACK)) == XDPT_TCP_SYN)
			__sync_fetch_and_add(&s->syn, 1);
		if (f & XDPT_TCP_RST)
			__sync_fetch_and_add(&s->rst, 1);
		if (fclass != XDPT_F_OK)
			__sync_fetch_and_add(&s->bad_flags, 1);
	}
}

static __always_inline void emit_event(const struct pkt_meta *m, __u64 now,
				       __u8 kind, __u8 reason)
{
	if (!cfg_events)
		return;
	struct xdpt_event *e = bpf_ringbuf_reserve(&xdpt_events, sizeof(*e), 0);
	if (!e) {
		cnt_add(XDPT_C_EV_DROP, 1);
		return;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = now;
	e->key.saddr = m->saddr;
	e->key.daddr = m->daddr;
	e->key.sport = m->sport;
	e->key.dport = m->dport;
	e->key.proto = m->proto;
	e->frame_len = m->frame_len;
	e->kind = kind;
	e->reason = reason;
	e->tcp_flags = m->tcp_flags;
	/* flags 0: the kernel wakes the reader only if it had caught up, so a
	 * burst costs one wakeup, not one per event. */
	bpf_ringbuf_submit(e, 0);
}

SEC("xdp")
int xdpt_main(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 now = bpf_ktime_get_ns();

	struct pkt_meta m;
	int res = xdpt_parse(data, data_end, (__u32)(data_end - data), &m);

	cnt_add(XDPT_C_PKTS, 1);
	cnt_add(XDPT_C_BYTES, m.frame_len);
	cnt_add(XDPT_C_RESULT_BASE + (__u32)res, 1);

	__u32 sb = xdpt_size_bucket(m.frame_len);
	__u64 *sz = bpf_map_lookup_elem(&xdpt_sizes, &sb);
	if (sz)
		*sz += 1;

	if (res != XDPT_P_OK) {
		if (xdpt_is_malformed(res))
			emit_event(&m, now, XDPT_EV_MALFORMED, (__u8)res);
		return XDP_PASS;
	}

	if (m.is_frag)
		cnt_add(XDPT_C_FRAG, 1);

	int fclass = XDPT_F_OK;
	switch (m.proto) {
	case IPPROTO_TCP:
		cnt_add(XDPT_C_TCP, 1);
		if (m.l4_valid) {
			__u8 f = m.tcp_flags;
			if ((f & (XDPT_TCP_SYN | XDPT_TCP_ACK)) == XDPT_TCP_SYN)
				cnt_add(XDPT_C_SYN, 1);
			else if ((f & (XDPT_TCP_SYN | XDPT_TCP_ACK)) == (XDPT_TCP_SYN | XDPT_TCP_ACK))
				cnt_add(XDPT_C_SYNACK, 1);
			if (f & XDPT_TCP_RST)
				cnt_add(XDPT_C_RST, 1);
			if (f & XDPT_TCP_FIN)
				cnt_add(XDPT_C_FIN, 1);
			fclass = xdpt_flag_class(f);
			cnt_add(XDPT_C_FLAG_BASE + (__u32)fclass, 1);
		}
		break;
	case IPPROTO_UDP:  cnt_add(XDPT_C_UDP, 1); break;
	case IPPROTO_ICMP: cnt_add(XDPT_C_ICMP, 1); break;
	default:           cnt_add(XDPT_C_L4_OTHER, 1); break;
	}

	flow_update(&m, now);
	src_update(&m, now, fclass);

	if (fclass != XDPT_F_OK)
		emit_event(&m, now, XDPT_EV_TCP_FLAGS, (__u8)fclass);

	return XDP_PASS; /* monitor only: never drop, never rewrite */
}

char LICENSE[] SEC("license") = "GPL";
