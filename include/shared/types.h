/* Types shared between the BPF program and userspace (C and C++).
 *
 * Rules for anything in this file:
 *  - fixed-width types only (__u8.. __u64), no pointers, no bool
 *  - padding is explicit and named _pad, so both compilers agree on layout
 *    and keys can be fully zeroed (hash maps compare keys as raw bytes)
 *  - every struct has a size assertion
 */
#ifndef XDPT_SHARED_TYPES_H
#define XDPT_SHARED_TYPES_H

#include <linux/types.h>

#ifdef __cplusplus
#define XDPT_ASSERT_SIZE(T, n) static_assert(sizeof(T) == (n), #T " layout changed")
#else
#define XDPT_ASSERT_SIZE(T, n) _Static_assert(sizeof(T) == (n), #T " layout changed")
#endif

/* IPv4 5-tuple. Addresses and ports are stored in network byte order,
 * exactly as they appear on the wire; userspace converts for display. */
struct flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  proto;
	__u8  _pad[3];
};
XDPT_ASSERT_SIZE(struct flow_key, 16);

/* Per-flow counters. Timestamps are bpf_ktime_get_ns(), i.e. CLOCK_MONOTONIC,
 * so userspace can compare them with clock_gettime(CLOCK_MONOTONIC). */
struct flow_stats {
	__u64 pkts;
	__u64 bytes;
	__u64 first_ns;
	__u64 last_ns;
	__u32 syn;
	__u32 rst;
	__u16 min_len;
	__u16 max_len;
	__u8  flags_seen; /* OR of all TCP flag bytes seen on this flow */
	__u8  _pad[3];
};
XDPT_ASSERT_SIZE(struct flow_stats, 48);

/* Outcome of parsing one frame. Values below XDPT_P_ERR_FIRST are normal
 * traffic; everything from XDPT_P_ERR_FIRST up is a malformed packet. */
enum xdpt_parse {
	XDPT_P_OK = 0,           /* IPv4 parsed (L4 too, unless non-first fragment) */
	XDPT_P_NON_IP,           /* ARP, LLDP, ... not ours */
	XDPT_P_IPV6,             /* recognised, not parsed yet */

	XDPT_P_ERR_FIRST,
	XDPT_P_ERR_ETH_TRUNC = XDPT_P_ERR_FIRST, /* frame shorter than Ethernet header */
	XDPT_P_ERR_VLAN_TRUNC,   /* VLAN tag cut off */
	XDPT_P_ERR_VLAN_DEPTH,   /* more than XDPT_MAX_VLAN tags */
	XDPT_P_ERR_IP_TRUNC,     /* IPv4 header (incl. options) cut off */
	XDPT_P_ERR_IP_VERSION,   /* ethertype IPv4 but version != 4 */
	XDPT_P_ERR_IP_IHL,       /* ihl < 5 */
	XDPT_P_ERR_IP_TOTLEN,    /* tot_len < header length, or > bytes in frame */
	XDPT_P_ERR_TCP_TRUNC,    /* TCP header doesn't fit in frame or tot_len */
	XDPT_P_ERR_TCP_DOFF,     /* doff < 5, or header longer than IP payload */
	XDPT_P_ERR_UDP_TRUNC,
	XDPT_P_ERR_UDP_LEN,      /* udp len < 8 or > IP payload */
	XDPT_P_ERR_ICMP_TRUNC,
	XDPT_P__MAX
};

/* Index into the global per-CPU counters array. */
enum xdpt_counter {
	XDPT_C_PKTS = 0,
	XDPT_C_BYTES,
	XDPT_C_TCP,
	XDPT_C_UDP,
	XDPT_C_ICMP,
	XDPT_C_L4_OTHER,
	XDPT_C_FRAG,
	XDPT_C_RESULT_BASE, /* XDPT_C_RESULT_BASE + enum xdpt_parse */
	XDPT_C__MAX = XDPT_C_RESULT_BASE + XDPT_P__MAX
};

#endif /* XDPT_SHARED_TYPES_H */
