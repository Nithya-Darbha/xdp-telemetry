/* Small helpers shared by the XDP program and userspace:
 * TCP flag classification, sketch hashing, size bucketing.
 * Plain C, no BPF helpers, no libc, so the AF_PACKET baseline computes
 * exactly the same values as the kernel path. */
#ifndef XDPT_SKETCH_H
#define XDPT_SKETCH_H

#include <linux/types.h>
#include "shared/types.h"

#ifndef XDPT_INLINE
#define XDPT_INLINE static inline __attribute__((always_inline))
#endif

/* Classify a TCP flag byte. Order matters: the first match wins. */
XDPT_INLINE int xdpt_flag_class(__u8 f)
{
	if (f == 0)
		return XDPT_F_NULL;
	if ((f & (XDPT_TCP_SYN | XDPT_TCP_FIN)) == (XDPT_TCP_SYN | XDPT_TCP_FIN))
		return XDPT_F_SYN_FIN;
	if ((f & (XDPT_TCP_SYN | XDPT_TCP_RST)) == (XDPT_TCP_SYN | XDPT_TCP_RST))
		return XDPT_F_SYN_RST;
	if (!(f & XDPT_TCP_ACK)) {
		if ((f & (XDPT_TCP_FIN | XDPT_TCP_PSH | XDPT_TCP_URG)) ==
		    (XDPT_TCP_FIN | XDPT_TCP_PSH | XDPT_TCP_URG))
			return XDPT_F_XMAS;
		if (f & XDPT_TCP_FIN)
			return XDPT_F_FIN_NO_ACK;
	}
	return XDPT_F_OK;
}

/* murmur3 finalizer: cheap, no tables, good avalanche. Ports and IPs are
 * highly structured (sequential scans), so the bit position must not be a
 * plain modulo of the value. */
XDPT_INLINE __u32 xdpt_mix32(__u32 h)
{
	h ^= h >> 16;
	h *= 0x85ebca6bU;
	h ^= h >> 13;
	h *= 0xc2b2ae35U;
	h ^= h >> 16;
	return h;
}

/* Bit index for a linear-counting bitmap of `words` 64-bit words.
 * words must be a power of two. Different seeds keep the port and IP
 * sketches independent. */
XDPT_INLINE __u32 xdpt_sketch_bit(__u32 value, __u32 seed, __u32 words)
{
	return xdpt_mix32(value ^ seed) & (words * 64 - 1);
}

#define XDPT_SEED_PORT 0x9e3779b9U
#define XDPT_SEED_IP   0x7f4a7c15U

XDPT_INLINE __u32 xdpt_size_bucket(__u32 len)
{
	__u32 b = len / XDPT_SIZE_BUCKET;
	return b < XDPT_SIZE_BUCKETS - 1 ? b : XDPT_SIZE_BUCKETS - 1;
}

#endif /* XDPT_SKETCH_H */
