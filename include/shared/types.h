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

/* ---- sizing ------------------------------------------------------------ */

#define XDPT_FLOW_MAX      65536  /* 5-tuple flows tracked at once (LRU) */
#define XDPT_SRC_MAX       16384  /* source IPs tracked at once (LRU) */
#define XDPT_RINGBUF_BYTES (256 * 1024)

#define XDPT_PORT_BM_WORDS 16     /* 1024-bit dst port sketch per source */
#define XDPT_IP_BM_WORDS   8      /* 512-bit dst IP sketch per source */

#define XDPT_SIZE_BUCKET   64     /* frame size histogram: 64-byte buckets */
#define XDPT_SIZE_BUCKETS  25     /* [0,64) [64,128) ... [1536, inf) */

/* ---- TCP flags (byte 13 of the TCP header) ------------------------------ */

#define XDPT_TCP_FIN 0x01
#define XDPT_TCP_SYN 0x02
#define XDPT_TCP_RST 0x04
#define XDPT_TCP_PSH 0x08
#define XDPT_TCP_ACK 0x10
#define XDPT_TCP_URG 0x20

/* ---- flow table: LRU_HASH flow_key -> flow_stats ------------------------ */

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

/* Per-flow counters, shared by all CPUs. pkts/bytes/syn/rst/flags_seen are
 * updated atomically; last_ns, min_len and max_len are plain stores and may
 * lose a race between CPUs (off by one packet at worst).
 * Timestamps are bpf_ktime_get_ns(), i.e. CLOCK_MONOTONIC. */
struct flow_stats {
	__u64 pkts;
	__u64 bytes;
	__u64 first_ns;
	__u64 last_ns;
	__u32 syn;        /* SYN without ACK */
	__u32 rst;
	__u16 min_len;
	__u16 max_len;
	__u32 flags_seen; /* OR of all TCP flag bytes; 32-bit so it can be atomic */
};
XDPT_ASSERT_SIZE(struct flow_stats, 48);

/* ---- per-source windows: LRU_HASH __u32 saddr -> src_window -------------
 *
 * Time is cut into tumbling windows of cfg_window_ns, numbered by
 * epoch = ktime_ns / cfg_window_ns. Each source has two slots and epoch E
 * writes slot E & 1. The kernel clears a slot when it first sees a new epoch
 * in it, so userspace never writes here: it reads slot (E-1) & 1 once window
 * E-1 has closed, and only trusts it if slot.epoch == E-1. */
struct src_slot {
	__u64 epoch;
	__u64 pkts;
	__u64 bytes;
	__u32 syn;        /* SYN without ACK */
	__u32 rst;
	__u32 bad_flags;  /* TCP packets with an illegal flag combination */
	__u32 _pad;
	__u64 port_bm[XDPT_PORT_BM_WORDS]; /* linear-counting sketch of dst ports */
	__u64 ip_bm[XDPT_IP_BM_WORDS];     /* linear-counting sketch of dst IPs */
};
XDPT_ASSERT_SIZE(struct src_slot, 232);

struct src_window {
	struct src_slot slot[2];
};
XDPT_ASSERT_SIZE(struct src_window, 464);

/* ---- parse outcomes ----------------------------------------------------- */

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

/* TCP flag combinations that no legitimate stack sends. Most are scanner
 * signatures (nmap -sN, -sF, -sX) or OS fingerprinting probes. */
enum xdpt_flag_class {
	XDPT_F_OK = 0,
	XDPT_F_NULL,       /* no flags at all */
	XDPT_F_SYN_FIN,
	XDPT_F_SYN_RST,
	XDPT_F_XMAS,       /* FIN + PSH + URG without ACK */
	XDPT_F_FIN_NO_ACK, /* FIN without ACK */
	XDPT_F__MAX
};

/* ---- global counters: PERCPU_ARRAY indexed by xdpt_counter ------------- */

enum xdpt_counter {
	XDPT_C_PKTS = 0,
	XDPT_C_BYTES,
	XDPT_C_TCP,
	XDPT_C_UDP,
	XDPT_C_ICMP,
	XDPT_C_L4_OTHER,
	XDPT_C_FRAG,
	XDPT_C_SYN,          /* SYN without ACK */
	XDPT_C_SYNACK,
	XDPT_C_RST,
	XDPT_C_FIN,
	XDPT_C_EV_DROP,      /* ring buffer full, event lost */
	XDPT_C_FLOW_FAIL,    /* could not insert a flow */
	XDPT_C_SRC_FAIL,     /* could not insert a source */
	XDPT_C_RESULT_BASE,  /* + enum xdpt_parse */
	XDPT_C_FLAG_BASE = XDPT_C_RESULT_BASE + XDPT_P__MAX, /* + enum xdpt_flag_class */
	XDPT_C__MAX = XDPT_C_FLAG_BASE + XDPT_F__MAX
};

/* ---- events: RINGBUF of xdpt_event --------------------------------------
 * Sent for single packets worth reporting immediately rather than at the
 * end of a window: illegal TCP flags and malformed frames. */
enum xdpt_event_kind {
	XDPT_EV_TCP_FLAGS = 1, /* reason = enum xdpt_flag_class */
	XDPT_EV_MALFORMED = 2, /* reason = enum xdpt_parse */
};

struct xdpt_event {
	__u64 ts_ns;          /* bpf_ktime_get_ns() */
	struct flow_key key;  /* whatever the parser reached; zero beyond that */
	__u32 frame_len;
	__u8  kind;
	__u8  reason;
	__u8  tcp_flags;
	__u8  _pad;
};
XDPT_ASSERT_SIZE(struct xdpt_event, 32);

#endif /* XDPT_SHARED_TYPES_H */
