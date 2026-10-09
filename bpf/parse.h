/* Verifier-safe Ethernet / VLAN / IPv4 / TCP / UDP / ICMP parser.
 *
 * Compiled twice: into the XDP program (clang -target bpf) and into userspace
 * (AF_PACKET baseline, unit tests). Plain C, no BPF helpers, no libc.
 *
 * Two kinds of checks, and the difference matters:
 *
 *  1. Memory safety. Before every read, the exact pointer about to be read is
 *     compared with data_end. This is what the verifier demands; without it
 *     the program does not load.
 *
 *  2. Protocol sanity. Lengths that come *from the packet* (tot_len, UDP len)
 *     are attacker controlled and up to 65535. They are only ever compared as
 *     integers against frame_len. Adding them to a packet pointer would give
 *     the verifier an offset range past its maximum packet offset (0xffff)
 *     and the program would be rejected.
 *
 * Header lengths from 4-bit fields (ihl, doff) are different: their range is
 * at most 60 bytes, so advancing a packet pointer by them is fine, as long as
 * the new pointer is bounds checked again before use.
 */
#ifndef XDPT_PARSE_H
#define XDPT_PARSE_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "shared/types.h"

#ifndef XDPT_INLINE
#define XDPT_INLINE static inline __attribute__((always_inline))
#endif

#ifndef XDPT_MAX_VLAN
#define XDPT_MAX_VLAN 2 /* 802.1Q + 802.1ad (QinQ) */
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define xdpt_htons(x) ((__u16)__builtin_bswap16((__u16)(x)))
#define xdpt_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#else
#define xdpt_htons(x) ((__u16)(x))
#define xdpt_ntohs(x) ((__u16)(x))
#endif

/* Not in uapi headers. */
struct xdpt_vlan_hdr {
	__be16 tci;
	__be16 encap_proto;
};

/* linux/icmp.h pulls in linux/if.h and from there glibc headers, which break
 * the -target bpf build. ICMP's fixed 8-byte header is all we need. */
struct xdpt_icmp_hdr {
	__u8   type;
	__u8   code;
	__sum16 checksum;
	__be32 rest; /* id/seq for echo, unused or MTU for others */
};

/* Result of a parse. Address and port fields are network byte order.
 * ICMP has no ports: sport carries htons(type), dport carries htons(code),
 * so flow keys still separate echo requests from unreachables. */
struct pkt_meta {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 frame_len;   /* bytes in the frame, i.e. data_end - data */
	__u16 ip_len;      /* IPv4 tot_len, host order */
	__u8  proto;       /* IPPROTO_* */
	__u8  tcp_flags;   /* byte 13 of the TCP header: CWR ECE URG ACK PSH RST SYN FIN */
	__u8  vlan_depth;
	__u8  is_frag;     /* any IPv4 fragment (MF set or offset != 0) */
	__u8  l4_valid;    /* sport/dport/tcp_flags are meaningful */
	__u8  _pad;
};

/* Parse one frame. Returns enum xdpt_parse. On XDPT_P_OK, *m is filled in;
 * on any other result, only frame_len and the fields reached so far are. */
XDPT_INLINE int xdpt_parse(void *data, void *data_end, __u32 frame_len,
			   struct pkt_meta *m)
{
	__builtin_memset(m, 0, sizeof(*m));
	m->frame_len = frame_len;

	/* ---- Ethernet ---------------------------------------------------- */
	struct ethhdr *eth = (struct ethhdr *)data;
	if ((void *)(eth + 1) > data_end)
		return XDPT_P_ERR_ETH_TRUNC;

	__u16 h_proto = eth->h_proto;
	void *cur = (void *)(eth + 1);
	__u32 off = sizeof(*eth); /* scalar twin of cur, for integer length checks */

	/* ---- VLAN: bounded loop, max XDPT_MAX_VLAN tags -------------------- */
#ifdef __clang__
#pragma unroll /* the kernel accepts bounded loops since 5.3, unrolling is simpler to verify */
#endif
	for (int i = 0; i < XDPT_MAX_VLAN; i++) {
		if (h_proto != xdpt_htons(ETH_P_8021Q) && h_proto != xdpt_htons(ETH_P_8021AD))
			break;
		struct xdpt_vlan_hdr *vh = (struct xdpt_vlan_hdr *)cur;
		if ((void *)(vh + 1) > data_end)
			return XDPT_P_ERR_VLAN_TRUNC;
		h_proto = vh->encap_proto;
		cur = (void *)(vh + 1);
		off += sizeof(*vh);
		m->vlan_depth++;
	}
	if (h_proto == xdpt_htons(ETH_P_8021Q) || h_proto == xdpt_htons(ETH_P_8021AD))
		return XDPT_P_ERR_VLAN_DEPTH;

	if (h_proto == xdpt_htons(ETH_P_IPV6))
		return XDPT_P_IPV6;
	if (h_proto != xdpt_htons(ETH_P_IP))
		return XDPT_P_NON_IP;

	/* ---- IPv4 -------------------------------------------------------- */
	struct iphdr *ip = (struct iphdr *)cur;
	if ((void *)(ip + 1) > data_end)
		return XDPT_P_ERR_IP_TRUNC;
	if (ip->version != 4)
		return XDPT_P_ERR_IP_VERSION;

	/* ihl is a 4-bit field, so hlen is provably in [0, 60]. */
	__u32 hlen = (__u32)ip->ihl * 4;
	if (hlen < sizeof(*ip))
		return XDPT_P_ERR_IP_IHL;
	if ((char *)ip + hlen > (char *)data_end) /* options cut off */
		return XDPT_P_ERR_IP_TRUNC;

	__u32 tot = xdpt_ntohs(ip->tot_len);
	/* Integer checks only, see the header comment. A frame may be longer
	 * than tot_len (Ethernet pads to 60 bytes) but never shorter. */
	if (tot < hlen || off + tot > frame_len)
		return XDPT_P_ERR_IP_TOTLEN;

	m->saddr = ip->saddr;
	m->daddr = ip->daddr;
	m->proto = ip->protocol;
	m->ip_len = (__u16)tot;

	__u16 frag = xdpt_ntohs(ip->frag_off);
	if (frag & 0x3FFF) /* MF flag or non-zero offset */
		m->is_frag = 1;
	if (frag & 0x1FFF) /* non-first fragment: no L4 header here */
		return XDPT_P_OK;

	void *l4 = (char *)ip + hlen;
	__u32 l4_room = tot - hlen; /* L4 bytes according to the IP header */

	/* ---- L4 ---------------------------------------------------------- */
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *)l4;
		if ((void *)(tcp + 1) > data_end || l4_room < sizeof(*tcp))
			return XDPT_P_ERR_TCP_TRUNC;
		__u32 doff = (__u32)tcp->doff * 4;
		if (doff < sizeof(*tcp) || doff > l4_room)
			return XDPT_P_ERR_TCP_DOFF;
		m->sport = tcp->source;
		m->dport = tcp->dest;
		m->tcp_flags = ((__u8 *)tcp)[13];
		m->l4_valid = 1;
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *)l4;
		if ((void *)(udp + 1) > data_end || l4_room < sizeof(*udp))
			return XDPT_P_ERR_UDP_TRUNC;
		__u32 ulen = xdpt_ntohs(udp->len);
		if (ulen < sizeof(*udp) || ulen > l4_room)
			return XDPT_P_ERR_UDP_LEN;
		m->sport = udp->source;
		m->dport = udp->dest;
		m->l4_valid = 1;
	} else if (ip->protocol == IPPROTO_ICMP) {
		struct xdpt_icmp_hdr *icmp = (struct xdpt_icmp_hdr *)l4;
		if ((void *)(icmp + 1) > data_end || l4_room < sizeof(*icmp))
			return XDPT_P_ERR_ICMP_TRUNC;
		m->sport = xdpt_htons(icmp->type);
		m->dport = xdpt_htons(icmp->code);
		m->l4_valid = 1;
	}
	return XDPT_P_OK;
}

XDPT_INLINE int xdpt_is_malformed(int res)
{
	return res >= XDPT_P_ERR_FIRST;
}

#endif /* XDPT_PARSE_H */
