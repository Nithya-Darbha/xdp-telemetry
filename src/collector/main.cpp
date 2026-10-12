// xdpt: load the XDP telemetry program, read its maps once per window, and
// print a live line plus optional JSONL. Detection is wired in at phase 7.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>

#include <atomic>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string_view>
#include <unistd.h>

#include <arpa/inet.h>

#include "bpf_engine.h"
#include "core/detect.h"
#include "core/report.h"
#include "core/snapshot.h"
#include "shared/types.h"
#include "telemetry.skel.h"

namespace {

std::atomic<bool> g_stop{false};
bool g_verbose = false;

int libbpf_print(libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !g_verbose)
		return 0;
	return std::vfprintf(stderr, fmt, args);
}

struct SkelDeleter {
	void operator()(telemetry *s) const { telemetry__destroy(s); }
};
using Skel = std::unique_ptr<telemetry, SkelDeleter>;

void usage(const char *a0)
{
	std::fprintf(stderr,
		"usage: %s -i IFACE [-m native|generic|auto] [-w MS] [-j FILE] [-E] [-v]\n"
		"  -i  interface to attach to\n"
		"  -m  XDP mode (default native)\n"
		"  -w  window length in ms (default 1000)\n"
		"  -j  append one JSON object per window to FILE (- for stdout)\n"
		"  -E  disable per-packet events (ring buffer)\n"
		"  -v  libbpf debug output, including verifier logs\n",
		a0);
}

const char *mode_name(__u8 m)
{
	switch (m) {
	case XDP_ATTACHED_DRV: return "native";
	case XDP_ATTACHED_SKB: return "generic";
	case XDP_ATTACHED_HW:  return "offload";
	default: return "none";
	}
}

uint64_t mono_ns()
{
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}

void print_line(const xdpt::WindowSnapshot &s, const xdpt::WindowReport &rep)
{
	uint64_t malformed = 0;
	for (int p = XDPT_P_ERR_FIRST; p < XDPT_P__MAX; p++)
		malformed += s.delta[XDPT_C_RESULT_BASE + p];

	std::printf("w=%-4llu pps=%9.0f Mbit/s=%7.2f tcp=%llu udp=%llu icmp=%llu "
		    "syn=%llu rst=%llu p50=%u p99=%u flows=%llu srcs=%zu ev=%zu malf=%llu "
		    "collect=%.0fus\n",
		    (unsigned long long)s.seq, rep.pps, rep.mbps,
		    (unsigned long long)s.d(XDPT_C_TCP), (unsigned long long)s.d(XDPT_C_UDP),
		    (unsigned long long)s.d(XDPT_C_ICMP), (unsigned long long)s.d(XDPT_C_SYN),
		    (unsigned long long)s.d(XDPT_C_RST), rep.size_p50, rep.size_p99,
		    (unsigned long long)s.active_flows, s.srcs.size(), s.events.size(),
		    (unsigned long long)malformed, s.collect_us);

	// Per-source fan-out, the raw material phase 7 turns into scan alerts.
	for (const xdpt::SrcReport &sr : rep.srcs) {
		if (sr.pkts < 20) // skip chatter; a real scan sends far more
			continue;
		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &sr.saddr, ip, sizeof ip);
		std::printf("    src %-15s pkts=%llu ports~%.0f%s ips~%.0f%s syn=%u bad_flags=%u\n",
			    ip, (unsigned long long)sr.pkts,
			    sr.distinct_ports, sr.ports_saturated ? "+" : "",
			    sr.distinct_ips, sr.ips_saturated ? "+" : "",
			    sr.syn, sr.bad_flags);
	}
	std::fflush(stdout);
}

// Deliberately hand-rolled: no JSON dependency, one flat object per line.
void print_jsonl(std::FILE *f, const xdpt::WindowSnapshot &s)
{
	uint64_t malformed = 0;
	for (int p = XDPT_P_ERR_FIRST; p < XDPT_P__MAX; p++)
		malformed += s.delta[XDPT_C_RESULT_BASE + p];

	std::fprintf(f,
		"{\"seq\":%llu,\"t\":%.6f,\"dt\":%.6f,\"pkts\":%llu,\"bytes\":%llu,"
		"\"tcp\":%llu,\"udp\":%llu,\"icmp\":%llu,\"syn\":%llu,\"synack\":%llu,"
		"\"rst\":%llu,\"fin\":%llu,\"frag\":%llu,\"malformed\":%llu,"
		"\"ev_drop\":%llu,\"flow_fail\":%llu,\"src_fail\":%llu,"
		"\"active_flows\":%llu,\"aged_flows\":%llu,\"n_srcs\":%zu,\"n_events\":%zu,"
		"\"collect_us\":%.1f}\n",
		(unsigned long long)s.seq, s.t_mono, s.dt,
		(unsigned long long)s.d(XDPT_C_PKTS), (unsigned long long)s.d(XDPT_C_BYTES),
		(unsigned long long)s.d(XDPT_C_TCP), (unsigned long long)s.d(XDPT_C_UDP),
		(unsigned long long)s.d(XDPT_C_ICMP), (unsigned long long)s.d(XDPT_C_SYN),
		(unsigned long long)s.d(XDPT_C_SYNACK), (unsigned long long)s.d(XDPT_C_RST),
		(unsigned long long)s.d(XDPT_C_FIN), (unsigned long long)s.d(XDPT_C_FRAG),
		(unsigned long long)malformed, (unsigned long long)s.d(XDPT_C_EV_DROP),
		(unsigned long long)s.d(XDPT_C_FLOW_FAIL), (unsigned long long)s.d(XDPT_C_SRC_FAIL),
		(unsigned long long)s.active_flows, (unsigned long long)s.aged_flows,
		s.srcs.size(), s.events.size(), s.collect_us);
	std::fflush(f);
}

} // namespace

int main(int argc, char **argv)
{
	const char *ifname = nullptr;
	const char *jsonl = nullptr;
	__u32 mode_flag = XDP_FLAGS_DRV_MODE;
	long window_ms = 1000;
	bool events = true;

	int opt;
	while ((opt = getopt(argc, argv, "i:m:w:j:Evh")) != -1) {
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
		case 'w': window_ms = std::strtol(optarg, nullptr, 10); break;
		case 'j': jsonl = optarg; break;
		case 'E': events = false; break;
		case 'v': g_verbose = true; break;
		default: usage(argv[0]); return 2;
		}
	}
	if (!ifname || window_ms <= 0) { usage(argv[0]); return 2; }

	const unsigned ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		std::fprintf(stderr, "unknown interface %s (wrong netns?)\n", ifname);
		return 1;
	}

	std::FILE *jf = nullptr;
	if (jsonl) {
		jf = std::strcmp(jsonl, "-") == 0 ? stdout : std::fopen(jsonl, "a");
		if (!jf) { std::perror("open jsonl"); return 1; }
	}

	libbpf_set_print(libbpf_print);

	// open -> set config in .rodata -> load. The verifier sees the config as
	// a constant and can prune branches (e.g. the whole event path when off).
	Skel skel{telemetry__open()};
	if (!skel) { std::fprintf(stderr, "open failed\n"); return 1; }
	skel->rodata->cfg_window_ns = static_cast<__u64>(window_ms) * 1'000'000ULL;
	skel->rodata->cfg_events = events ? 1 : 0;
	if (telemetry__load(skel.get())) {
		std::fprintf(stderr, "load failed (rerun with -v for the verifier log)\n");
		return 1;
	}

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
		std::printf("attached to %s (ifindex %u) in %s mode, window %ldms%s\n",
			    ifname, ifindex, mode_name(q.attach_mode), window_ms,
			    events ? "" : ", events off");

	std::signal(SIGINT, [](int) { g_stop = true; });
	std::signal(SIGTERM, [](int) { g_stop = true; });

	xdpt::BpfEngine::Config ec;
	ec.window_ns = static_cast<uint64_t>(window_ms) * 1'000'000ULL;
	xdpt::BpfEngine engine(skel.get(), ec);
	xdpt::Detector detector;
	xdpt::WindowSnapshot snap;

	// Align window boundaries to the same epoch grid the kernel uses, so the
	// slot we read is the one the kernel just stopped writing.
	uint64_t next = (mono_ns() / ec.window_ns + 1) * ec.window_ns;
	while (!g_stop) {
		// Drain events as they arrive; wake at most at the boundary.
		uint64_t now = mono_ns();
		long wait_ms = next > now ? static_cast<long>((next - now) / 1'000'000ULL) + 1 : 0;
		engine.poll_events(wait_ms > 0 ? static_cast<int>(wait_ms) : 0);

		now = mono_ns();
		if (now < next)
			continue;
		next += ec.window_ns;

		engine.collect(now, snap);
		xdpt::WindowReport rep = xdpt::build_report(snap);
		print_line(snap, rep);

		for (const xdpt::Alert &al : detector.evaluate(rep)) {
			char ip[INET_ADDRSTRLEN] = "global";
			if (al.saddr)
				inet_ntop(AF_INET, &al.saddr, ip, sizeof ip);
			std::printf("  ALERT [%s] %-14s %-15s %s\n",
				    xdpt::severity_name(al.severity),
				    xdpt::alert_kind_name(al.kind), ip, al.detail.c_str());
			if (jf)
				std::fprintf(jf, "{\"alert\":\"%s\",\"severity\":\"%s\",\"src\":\"%s\","
					     "\"seq\":%llu,\"detail\":\"%s\"}\n",
					     xdpt::alert_kind_name(al.kind), xdpt::severity_name(al.severity),
					     ip, (unsigned long long)rep.seq, al.detail.c_str());
		}
		std::fflush(stdout);
		if (jf)
			print_jsonl(jf, snap);
	}

	close(link_fd); // detaches
	if (jf && jf != stdout)
		std::fclose(jf);
	std::printf("\ndetached from %s\n", ifname);
	return 0;
}
