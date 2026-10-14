// Runs the ACTUAL loaded XDP program over crafted byte buffers with
// BPF_PROG_TEST_RUN, then checks the right outcome counter moved. This tests
// the verified bytecode in the kernel, not parse.h in userspace, and reaches
// frames too short to ever transmit (eth_trunc).
//
// Needs root (loads BPF). Skips cleanly otherwise so CI without privileges
// still passes.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "shared/types.h"
#include "telemetry.skel.h"

namespace {
int g_run = 0, g_fail = 0;
int ncpu = 0;

using Bytes = std::vector<uint8_t>;
void put16(Bytes &b, size_t at, uint16_t v) { b[at] = v >> 8; b[at + 1] = v & 0xff; }

// Minimal valid Ethernet+IPv4+L4 frame builder, same shape as parser_test.
Bytes frame(uint8_t proto = IPPROTO_TCP, uint8_t ihl = 5, int payload = 0)
{
	size_t hl = ihl * 4u;
	size_t l4 = proto == IPPROTO_TCP ? 20 : proto == IPPROTO_UDP ? 8 : 8;
	size_t tot = hl + l4 + payload;
	Bytes b(14 + tot, 0);
	put16(b, 12, ETH_P_IP);
	b[14] = 0x40 | (ihl & 0xf);
	put16(b, 16, (uint16_t)tot);
	b[14 + 8] = 64;
	b[14 + 9] = proto;
	uint8_t s[4] = {10, 77, 0, 1}, d[4] = {10, 77, 0, 2};
	std::memcpy(&b[14 + 12], s, 4);
	std::memcpy(&b[14 + 16], d, 4);
	size_t o = 14 + hl;
	if (proto == IPPROTO_TCP) { put16(b, o, 44000); put16(b, o + 2, 80); b[o + 12] = 5 << 4; b[o + 13] = 0x02; }
	else if (proto == IPPROTO_UDP) { put16(b, o, 44000); put16(b, o + 2, 53); put16(b, o + 4, (uint16_t)(8 + payload)); }
	else if (proto == IPPROTO_ICMP) { b[o] = 8; }
	return b;
}

// Sum one per-CPU counter slot.
uint64_t counter(int fd, uint32_t idx)
{
	std::vector<uint64_t> buf(ncpu);
	if (bpf_map_lookup_elem(fd, &idx, buf.data()) != 0)
		return 0;
	uint64_t s = 0;
	for (uint64_t v : buf) s += v;
	return s;
}

telemetry *g_skel = nullptr;
int g_prog_fd = -1, g_ctr_fd = -1;

// Run one frame through the program, return the delta on counter `idx`.
uint64_t run_delta(const Bytes &b, uint32_t idx, int &retval)
{
	uint64_t before = counter(g_ctr_fd, idx);
	// XDP needs a little tailroom; give 256 bytes of output space.
	std::vector<uint8_t> out(b.size() + 256);
	LIBBPF_OPTS(bpf_test_run_opts, o);
	o.data_in = b.data();
	o.data_size_in = (uint32_t)b.size();
	o.data_out = out.data();
	o.data_size_out = (uint32_t)out.size();
	o.repeat = 1;
	int err = bpf_prog_test_run_opts(g_prog_fd, &o);
	if (err) { retval = -1; return UINT64_MAX; }
	retval = (int)o.retval;
	return counter(g_ctr_fd, idx) - before;
}

void expect(const char *name, const Bytes &b, int parse_res)
{
	g_run++;
	int rv = 0;
	uint64_t d = run_delta(b, XDPT_C_RESULT_BASE + parse_res, rv);
	if (d == UINT64_MAX) { g_fail++; std::printf("FAIL %-22s test_run error\n", name); return; }
	if (rv != XDP_PASS) { g_fail++; std::printf("FAIL %-22s retval %d != XDP_PASS\n", name, rv); return; }
	if (d != 1) { g_fail++; std::printf("FAIL %-22s counter delta %llu != 1\n", name, (unsigned long long)d); }
}
} // namespace

int main()
{
	if (geteuid() != 0) {
		std::printf("SKIP xdp_test_run (needs root)\n");
		return 0;
	}
	ncpu = libbpf_num_possible_cpus();

	g_skel = telemetry__open_and_load();
	if (!g_skel) { std::printf("FAIL could not load program\n"); return 1; }
	g_prog_fd = bpf_program__fd(g_skel->progs.xdpt_main);
	g_ctr_fd = bpf_map__fd(g_skel->maps.xdpt_counters);

	// valid traffic
	expect("tcp ok", frame(IPPROTO_TCP), XDPT_P_OK);
	expect("udp ok", frame(IPPROTO_UDP, 5, 16), XDPT_P_OK);
	expect("icmp ok", frame(IPPROTO_ICMP), XDPT_P_OK);
	expect("ip options ok", frame(IPPROTO_TCP, 6), XDPT_P_OK);

	// non-IP
	{ Bytes b = frame(); put16(b, 12, ETH_P_ARP); expect("arp non_ip", b, XDPT_P_NON_IP); }
	{ Bytes b = frame(); put16(b, 12, ETH_P_IPV6); expect("ipv6", b, XDPT_P_IPV6); }

	// A sub-14-byte frame: the kernel's TEST_RUN harness itself refuses input
	// shorter than an Ethernet header, so even this path cannot exercise
	// eth_trunc. That branch is covered by parser_test (13-byte buffer)
	// instead. Assert the refusal so the limit is documented, not silent.
	{
		g_run++;
		Bytes b(10, 0);
		int rv = 0;
		uint64_t d = run_delta(b, XDPT_C_RESULT_BASE + int(XDPT_P_ERR_ETH_TRUNC), rv);
		if (d == UINT64_MAX)
			std::printf("NOTE eth_trunc: TEST_RUN rejects <14B input (covered by parser_test)\n");
		else { g_fail++; std::printf("FAIL eth_trunc: expected harness to reject <14B\n"); }
	}
	{ Bytes b = frame(); b[14] = 0x44; expect("ihl < 5", b, XDPT_P_ERR_IP_IHL); }
	{ Bytes b = frame(); b[14] = 0x65; expect("ip version", b, XDPT_P_ERR_IP_VERSION); }
	{ Bytes b = frame(); put16(b, 16, 0xffff); expect("tot_len > frame", b, XDPT_P_ERR_IP_TOTLEN); }
	{ Bytes b = frame(); b.resize(14 + 19); expect("ip hdr truncated", b, XDPT_P_ERR_IP_TRUNC); }
	{ Bytes b = frame(); b[14 + 20 + 12] = 4 << 4; expect("tcp doff < 5", b, XDPT_P_ERR_TCP_DOFF); }
	{ Bytes b = frame(IPPROTO_UDP, 5, 4); put16(b, 14 + 20 + 4, 7); expect("udp len < 8", b, XDPT_P_ERR_UDP_LEN); }

	telemetry__destroy(g_skel);
	std::printf("%d/%d checks passed\n", g_run - g_fail, g_run);
	return g_fail ? 1 : 0;
}
