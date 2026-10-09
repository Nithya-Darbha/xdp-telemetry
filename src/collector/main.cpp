// xdpt: loads the XDP telemetry program and attaches it to an interface.
//
// Phase 3: load, attach, print per-interval counter deltas, detach on Ctrl-C.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>

#include <atomic>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string_view>
#include <unistd.h>
#include <vector>

#include "shared/types.h"
#include "telemetry.skel.h"

namespace {

std::atomic<bool> g_stop{false};
bool g_verbose = false;

int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	// Verifier logs come through at LIBBPF_DEBUG. Show them with -v.
	if (level == LIBBPF_DEBUG && !g_verbose)
		return 0;
	return std::vfprintf(stderr, fmt, args);
}

struct SkelDeleter {
	void operator()(telemetry *s) const { telemetry__destroy(s); }
};
using Skel = std::unique_ptr<telemetry, SkelDeleter>;

void usage(const char *argv0)
{
	std::fprintf(stderr,
		"usage: %s -i IFACE [-m native|generic|auto] [-I MS] [-v]\n"
		"  -i  interface to attach to\n"
		"  -m  XDP mode (default native; auto lets the kernel choose)\n"
		"  -I  print interval in milliseconds (default 1000)\n"
		"  -v  print libbpf debug output, including verifier logs\n",
		argv0);
}

const char *parse_name(int r)
{
	switch (r) {
	case XDPT_P_OK: return "ok";
	case XDPT_P_NON_IP: return "non_ip";
	case XDPT_P_IPV6: return "ipv6";
	case XDPT_P_ERR_ETH_TRUNC: return "eth_trunc";
	case XDPT_P_ERR_VLAN_TRUNC: return "vlan_trunc";
	case XDPT_P_ERR_VLAN_DEPTH: return "vlan_depth";
	case XDPT_P_ERR_IP_TRUNC: return "ip_trunc";
	case XDPT_P_ERR_IP_VERSION: return "ip_version";
	case XDPT_P_ERR_IP_IHL: return "ip_ihl";
	case XDPT_P_ERR_IP_TOTLEN: return "ip_totlen";
	case XDPT_P_ERR_TCP_TRUNC: return "tcp_trunc";
	case XDPT_P_ERR_TCP_DOFF: return "tcp_doff";
	case XDPT_P_ERR_UDP_TRUNC: return "udp_trunc";
	case XDPT_P_ERR_UDP_LEN: return "udp_len";
	case XDPT_P_ERR_ICMP_TRUNC: return "icmp_trunc";
	default: return "?";
	}
}

// Sums one slot of a BPF_MAP_TYPE_PERCPU_ARRAY. The kernel copies out one
// value per *possible* CPU (not online), each padded to 8 bytes.
class PercpuCounters {
public:
	explicit PercpuCounters(int map_fd)
		: fd_(map_fd), ncpu_(libbpf_num_possible_cpus()), buf_(ncpu_) {}

	bool read_all(std::vector<__u64> &out)
	{
		out.assign(XDPT_C__MAX, 0);
		for (__u32 k = 0; k < XDPT_C__MAX; k++) {
			if (bpf_map_lookup_elem(fd_, &k, buf_.data()) != 0)
				return false;
			for (__u64 v : buf_)
				out[k] += v;
		}
		return true;
	}

private:
	int fd_;
	int ncpu_;
	std::vector<__u64> buf_;
};

double mono_s()
{
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) * 1e-9;
}

void print_interval(const std::vector<__u64> &cur, const std::vector<__u64> &prev, double dt)
{
	auto d = [&](int i) { return cur[i] - prev[i]; };
	auto r = [&](int i) { return static_cast<double>(d(i)) / dt; };

	__u64 malformed = 0;
	for (int p = XDPT_P_ERR_FIRST; p < XDPT_P__MAX; p++)
		malformed += d(XDPT_C_RESULT_BASE + p);

	std::printf("pps=%10.0f  Mbit/s=%8.2f  tcp=%llu udp=%llu icmp=%llu other=%llu "
		    "frag=%llu ipv6=%llu non_ip=%llu malformed=%llu\n",
		    r(XDPT_C_PKTS), r(XDPT_C_BYTES) * 8 / 1e6,
		    (unsigned long long)d(XDPT_C_TCP), (unsigned long long)d(XDPT_C_UDP),
		    (unsigned long long)d(XDPT_C_ICMP), (unsigned long long)d(XDPT_C_L4_OTHER),
		    (unsigned long long)d(XDPT_C_FRAG),
		    (unsigned long long)d(XDPT_C_RESULT_BASE + int(XDPT_P_IPV6)),
		    (unsigned long long)d(XDPT_C_RESULT_BASE + int(XDPT_P_NON_IP)),
		    (unsigned long long)malformed);
	if (malformed) {
		std::printf("    malformed:");
		for (int p = XDPT_P_ERR_FIRST; p < XDPT_P__MAX; p++)
			if (__u64 n = d(XDPT_C_RESULT_BASE + p))
				std::printf(" %s=%llu", parse_name(p), (unsigned long long)n);
		std::printf("\n");
	}
	std::fflush(stdout);
}

const char *mode_name(__u8 m)
{
	switch (m) {
	case XDP_ATTACHED_DRV: return "native";
	case XDP_ATTACHED_SKB: return "generic";
	case XDP_ATTACHED_HW:  return "offload";
	case XDP_ATTACHED_MULTI: return "multi";
	default: return "none";
	}
}

} // namespace

int main(int argc, char **argv)
{
	const char *ifname = nullptr;
	__u32 mode_flag = XDP_FLAGS_DRV_MODE;
	long interval_ms = 1000;

	int opt;
	while ((opt = getopt(argc, argv, "i:m:I:vh")) != -1) {
		switch (opt) {
		case 'i': ifname = optarg; break;
		case 'm': {
			std::string_view m = optarg;
			if (m == "native") mode_flag = XDP_FLAGS_DRV_MODE;
			else if (m == "generic") mode_flag = XDP_FLAGS_SKB_MODE;
			else if (m == "auto") mode_flag = 0;
			else { usage(argv[0]); return 2; }
			break;
		}
		case 'I': interval_ms = std::strtol(optarg, nullptr, 10); break;
		case 'v': g_verbose = true; break;
		default: usage(argv[0]); return 2;
		}
	}
	if (!ifname || interval_ms <= 0) { usage(argv[0]); return 2; }

	const unsigned ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		std::fprintf(stderr, "unknown interface %s (wrong netns?)\n", ifname);
		return 1;
	}

	libbpf_set_print(libbpf_print);

	Skel skel{telemetry__open_and_load()};
	if (!skel) {
		std::fprintf(stderr, "failed to load BPF object (rerun with -v for the verifier log)\n");
		return 1;
	}

	// Attach through a bpf_link rather than bpf_xdp_attach(): the link is owned
	// by this process, so if the collector crashes the program detaches itself
	// instead of being left running on the interface with nobody reading maps.
	LIBBPF_OPTS(bpf_link_create_opts, lopts, .flags = mode_flag);
	int prog_fd = bpf_program__fd(skel->progs.xdpt_main);
	int link_fd = bpf_link_create(prog_fd, static_cast<int>(ifindex), BPF_XDP, &lopts);
	if (link_fd < 0) {
		std::fprintf(stderr, "attach to %s failed: %s\n", ifname, std::strerror(-link_fd));
		if (mode_flag == XDP_FLAGS_DRV_MODE)
			std::fprintf(stderr, "driver may not support native XDP, try -m generic\n");
		return 1;
	}

	LIBBPF_OPTS(bpf_xdp_query_opts, q);
	if (bpf_xdp_query(static_cast<int>(ifindex), 0, &q) == 0)
		std::printf("attached to %s (ifindex %u) in %s mode, prog id %u\n",
			    ifname, ifindex, mode_name(q.attach_mode),
			    q.attach_mode == XDP_ATTACHED_SKB ? q.skb_prog_id : q.drv_prog_id);

	std::signal(SIGINT, [](int) { g_stop = true; });
	std::signal(SIGTERM, [](int) { g_stop = true; });

	PercpuCounters counters(bpf_map__fd(skel->maps.xdpt_counters));
	std::vector<__u64> prev, cur;
	counters.read_all(prev);
	double t_prev = mono_s();

	const timespec interval{interval_ms / 1000, (interval_ms % 1000) * 1000000L};
	while (!g_stop) {
		nanosleep(&interval, nullptr); // returns early on SIGINT
		if (g_stop || !counters.read_all(cur))
			break;
		double t = mono_s();
		print_interval(cur, prev, t - t_prev);
		prev.swap(cur);
		t_prev = t;
	}

	close(link_fd); // detaches
	std::printf("\ndetached from %s\n", ifname);
	return 0;
}
