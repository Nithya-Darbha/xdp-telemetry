// Unit tests for bpf/parse.h, compiled as ordinary userspace C++.
// The same header runs inside the XDP program, so these cases cover the
// kernel path too. Phase 10 adds BPF_PROG_TEST_RUN against the loaded program.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "parse.h"

namespace {

using Bytes = std::vector<uint8_t>;

int g_fail = 0, g_run = 0;

void put16(Bytes &b, size_t at, uint16_t v) { b[at] = v >> 8; b[at + 1] = v & 0xff; }

// Builds Ethernet [+ VLAN tags] + IPv4 + L4 header + payload, all fields
// valid. Tests then corrupt one field at a time.
struct Pkt {
	int vlans = 0;
	uint8_t proto = IPPROTO_TCP;
	uint8_t ihl = 5;
	int payload = 0;
	uint8_t tcp_flags = 0x02; // SYN

	size_t ip_off() const { return 14 + 4 * static_cast<size_t>(vlans); }
	size_t l4_len() const
	{
		return proto == IPPROTO_TCP ? 20 : proto == IPPROTO_UDP ? 8 : proto == IPPROTO_ICMP ? 8 : 0;
	}

	Bytes build() const
	{
		size_t ip_hlen = ihl * 4u;
		size_t tot = ip_hlen + l4_len() + payload;
		Bytes b(ip_off() + tot, 0);

		put16(b, 12, vlans ? ETH_P_8021Q : ETH_P_IP);
		for (int i = 0; i < vlans; i++) {
			size_t o = 14 + 4 * i;
			put16(b, o, 100 + i);                                     // TCI
			put16(b, o + 2, i + 1 < vlans ? ETH_P_8021Q : ETH_P_IP);   // next type
		}

		size_t ip = ip_off();
		b[ip] = 0x40 | (ihl & 0x0f);
		put16(b, ip + 2, static_cast<uint16_t>(tot));
		b[ip + 8] = 64;
		b[ip + 9] = proto;
		uint8_t src[4] = {10, 77, 0, 1}, dst[4] = {10, 77, 0, 2};
		std::memcpy(&b[ip + 12], src, 4);
		std::memcpy(&b[ip + 16], dst, 4);

		size_t l4 = ip + ip_hlen;
		if (proto == IPPROTO_TCP) {
			put16(b, l4, 40000);
			put16(b, l4 + 2, 80);
			b[l4 + 12] = 5 << 4; // doff
			b[l4 + 13] = tcp_flags;
		} else if (proto == IPPROTO_UDP) {
			put16(b, l4, 40000);
			put16(b, l4 + 2, 53);
			put16(b, l4 + 4, static_cast<uint16_t>(8 + payload));
		} else if (proto == IPPROTO_ICMP) {
			b[l4] = 8; // echo request
		}
		return b;
	}
};

// Copies the frame into a heap buffer sized exactly to it, starting 2 bytes
// past a malloc-aligned address. That mirrors NET_IP_ALIGN: after the 14-byte
// Ethernet header the IP header lands 4-byte aligned, so UBSan's alignment
// check stays on. Exact sizing means ASan flags any read past the frame end.
int parse(const Bytes &b, pkt_meta &m)
{
	auto *raw = new uint8_t[b.size() + 2];
	uint8_t *frame = raw + 2;
	if (!b.empty())
		std::memcpy(frame, b.data(), b.size());
	int r = xdpt_parse(frame, frame + b.size(), static_cast<__u32>(b.size()), &m);
	delete[] raw;
	return r;
}

void expect(const char *name, int got, int want)
{
	g_run++;
	if (got != want) {
		g_fail++;
		std::printf("FAIL %-40s got %d want %d\n", name, got, want);
	}
}

void expect_true(const char *name, bool ok)
{
	expect(name, ok ? 1 : 0, 1);
}

} // namespace

int main()
{
	pkt_meta m;

	// ---- valid traffic ---------------------------------------------------
	{
		Bytes b = Pkt{}.build();
		expect("tcp syn parses", parse(b, m), XDPT_P_OK);
		expect("tcp proto", m.proto, IPPROTO_TCP);
		expect("tcp dport", xdpt_ntohs(m.dport), 80);
		expect("tcp sport", xdpt_ntohs(m.sport), 40000);
		expect("tcp flags", m.tcp_flags, 0x02);
		expect("tcp l4_valid", m.l4_valid, 1);
		expect("frame_len", m.frame_len, static_cast<int>(b.size()));
		uint8_t src[4] = {10, 77, 0, 1};
		expect_true("saddr network order", std::memcmp(&m.saddr, src, 4) == 0);
	}
	{
		Pkt p; p.proto = IPPROTO_UDP; p.payload = 32;
		Bytes b = p.build();
		expect("udp parses", parse(b, m), XDPT_P_OK);
		expect("udp dport", xdpt_ntohs(m.dport), 53);
	}
	{
		Pkt p; p.proto = IPPROTO_ICMP;
		Bytes b = p.build();
		expect("icmp parses", parse(b, m), XDPT_P_OK);
		expect("icmp type in sport", xdpt_ntohs(m.sport), 8);
	}
	{
		Pkt p; p.proto = 47; // GRE: IPv4 ok, no L4 parse
		Bytes b = p.build();
		expect("other l4 parses", parse(b, m), XDPT_P_OK);
		expect("other l4 not l4_valid", m.l4_valid, 0);
	}
	{
		Pkt p; p.vlans = 1;
		Bytes b = p.build();
		expect("single vlan", parse(b, m), XDPT_P_OK);
		expect("vlan depth 1", m.vlan_depth, 1);
	}
	{
		Pkt p; p.vlans = 2;
		Bytes b = p.build();
		expect("qinq", parse(b, m), XDPT_P_OK);
		expect("vlan depth 2", m.vlan_depth, 2);
	}
	{
		Pkt p; p.ihl = 6; // one word of IP options
		Bytes b = p.build();
		expect("ip options", parse(b, m), XDPT_P_OK);
		expect("ports after options", xdpt_ntohs(m.dport), 80);
	}
	{
		Bytes b = Pkt{}.build();
		b.resize(b.size() + 6, 0); // Ethernet padding beyond tot_len is legal
		expect("trailing padding ok", parse(b, m), XDPT_P_OK);
	}
	{
		Bytes b = Pkt{}.build();
		put16(b, 12, ETH_P_ARP);
		expect("arp is non_ip", parse(b, m), XDPT_P_NON_IP);
		put16(b, 12, ETH_P_IPV6);
		expect("ipv6 recognised", parse(b, m), XDPT_P_IPV6);
	}

	// ---- fragments ---------------------------------------------------------
	{
		Bytes b = Pkt{}.build();
		put16(b, 14 + 6, 0x2000); // MF, offset 0: first fragment, has L4
		expect("first fragment parses", parse(b, m), XDPT_P_OK);
		expect("first fragment is_frag", m.is_frag, 1);
		expect("first fragment l4_valid", m.l4_valid, 1);

		put16(b, 14 + 6, 0x0003); // offset 24 bytes, last fragment
		expect("later fragment parses", parse(b, m), XDPT_P_OK);
		expect("later fragment is_frag", m.is_frag, 1);
		expect("later fragment no l4", m.l4_valid, 0);
	}

	// ---- malformed ---------------------------------------------------------
	{
		Bytes b(13, 0);
		expect("eth truncated", parse(b, m), XDPT_P_ERR_ETH_TRUNC);
	}
	{
		Pkt p; p.vlans = 1;
		Bytes b = p.build();
		b.resize(16);
		expect("vlan truncated", parse(b, m), XDPT_P_ERR_VLAN_TRUNC);
	}
	{
		// Three stacked 802.1Q tags: one more than XDPT_MAX_VLAN.
		Pkt p; p.vlans = 3;
		Bytes b = p.build();
		expect("vlan too deep", parse(b, m), XDPT_P_ERR_VLAN_DEPTH);
	}
	{
		Bytes b = Pkt{}.build();
		b.resize(14 + 19);
		expect("ip header truncated", parse(b, m), XDPT_P_ERR_IP_TRUNC);
	}
	{
		Bytes b = Pkt{}.build();
		b[14] = 0x65; // version 6, ihl 5, under ethertype IPv4
		expect("ip version mismatch", parse(b, m), XDPT_P_ERR_IP_VERSION);
	}
	{
		Bytes b = Pkt{}.build();
		b[14] = 0x44; // ihl 4
		expect("ihl < 5", parse(b, m), XDPT_P_ERR_IP_IHL);
	}
	{
		Bytes b = Pkt{}.build();
		b[14] = 0x4f; // ihl 15 = 60 byte header, frame only has 40 after IP start
		expect("ihl past frame", parse(b, m), XDPT_P_ERR_IP_TRUNC);
	}
	{
		Bytes b = Pkt{}.build();
		put16(b, 14 + 2, 19);
		expect("tot_len < header", parse(b, m), XDPT_P_ERR_IP_TOTLEN);
		put16(b, 14 + 2, 0xffff);
		expect("tot_len > frame", parse(b, m), XDPT_P_ERR_IP_TOTLEN);
	}
	{
		Bytes b = Pkt{}.build();
		b.resize(14 + 20 + 10);
		put16(b, 14 + 2, 30);
		expect("tcp truncated", parse(b, m), XDPT_P_ERR_TCP_TRUNC);
	}
	{
		// TCP header fits in the frame (padding) but not in tot_len.
		Bytes b = Pkt{}.build();
		put16(b, 14 + 2, 20 + 12);
		expect("tcp past tot_len", parse(b, m), XDPT_P_ERR_TCP_TRUNC);
	}
	{
		Bytes b = Pkt{}.build();
		b[14 + 20 + 12] = 4 << 4;
		expect("tcp doff < 5", parse(b, m), XDPT_P_ERR_TCP_DOFF);
		b[14 + 20 + 12] = 15 << 4; // 60 byte header, only 20 bytes of L4
		expect("tcp doff past payload", parse(b, m), XDPT_P_ERR_TCP_DOFF);
	}
	{
		Pkt p; p.proto = IPPROTO_UDP;
		Bytes b = p.build();
		b.resize(14 + 20 + 4);
		put16(b, 14 + 2, 24);
		expect("udp truncated", parse(b, m), XDPT_P_ERR_UDP_TRUNC);
	}
	{
		Pkt p; p.proto = IPPROTO_UDP; p.payload = 4;
		Bytes b = p.build();
		put16(b, 14 + 20 + 4, 7);
		expect("udp len < 8", parse(b, m), XDPT_P_ERR_UDP_LEN);
		put16(b, 14 + 20 + 4, 100);
		expect("udp len > payload", parse(b, m), XDPT_P_ERR_UDP_LEN);
	}
	{
		Pkt p; p.proto = IPPROTO_ICMP;
		Bytes b = p.build();
		b.resize(14 + 20 + 4);
		put16(b, 14 + 2, 24);
		expect("icmp truncated", parse(b, m), XDPT_P_ERR_ICMP_TRUNC);
	}
	{
		// Every prefix of a valid packet must parse to *something* without
		// reading past the end. Run under ASan to make that a real check.
		Pkt p; p.vlans = 2; p.ihl = 7; p.payload = 8;
		Bytes full = p.build();
		int ok = 0;
		for (size_t n = 0; n <= full.size(); n++) {
			Bytes b(full.begin(), full.begin() + static_cast<long>(n));
			int r = parse(b, m);
			ok += (n == full.size()) ? (r == XDPT_P_OK) : xdpt_is_malformed(r);
		}
		expect("every truncation is malformed", ok, static_cast<int>(full.size()) + 1);
	}

	std::printf("%d/%d checks passed\n", g_run - g_fail, g_run);
	return g_fail ? 1 : 0;
}
