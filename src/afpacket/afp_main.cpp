// xdpt-afp: the AF_PACKET baseline. Same windows, same report, same detector
// as xdpt; only the capture path differs. Benchmarks compare the two.
#include <arpa/inet.h>

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string_view>
#include <unistd.h>

#include "af_engine.h"
#include "core/detect.h"
#include "core/report.h"
#include "core/snapshot.h"
#include "shared/types.h"

namespace {
std::atomic<bool> g_stop{false};

uint64_t mono_ns()
{
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}

void print_line(const xdpt::WindowSnapshot &s, const xdpt::WindowReport &r)
{
	std::printf("w=%-4llu pps=%9.0f Mbit/s=%7.2f tcp=%llu udp=%llu icmp=%llu "
		    "syn=%llu p50=%u p99=%u flows=%llu srcs=%zu malf=%llu collect=%.0fus\n",
		    (unsigned long long)s.seq, r.pps, r.mbps,
		    (unsigned long long)s.d(XDPT_C_TCP), (unsigned long long)s.d(XDPT_C_UDP),
		    (unsigned long long)s.d(XDPT_C_ICMP), (unsigned long long)s.d(XDPT_C_SYN),
		    r.size_p50, r.size_p99, (unsigned long long)s.active_flows,
		    s.srcs.size(), (unsigned long long)r.win_malformed, s.collect_us);
	std::fflush(stdout);
}
} // namespace

int main(int argc, char **argv)
{
	const char *ifname = nullptr;
	const char *jsonl = nullptr;
	int threads = 1;
	long window_ms = 1000;

	int opt;
	while ((opt = getopt(argc, argv, "i:t:w:j:h")) != -1) {
		switch (opt) {
		case 'i': ifname = optarg; break;
		case 't': threads = std::atoi(optarg); break;
		case 'w': window_ms = std::strtol(optarg, nullptr, 10); break;
		case 'j': jsonl = optarg; break;
		default:
			std::fprintf(stderr, "usage: %s -i IFACE [-t THREADS] [-w MS] [-j FILE]\n", argv[0]);
			return 2;
		}
	}
	if (!ifname || threads < 1 || window_ms <= 0) {
		std::fprintf(stderr, "usage: %s -i IFACE [-t THREADS] [-w MS] [-j FILE]\n", argv[0]);
		return 2;
	}

	std::FILE *jf = nullptr;
	if (jsonl) {
		jf = std::strcmp(jsonl, "-") == 0 ? stdout : std::fopen(jsonl, "a");
		if (!jf) { std::perror("open jsonl"); return 1; }
	}

	xdpt::AfPacketEngine::Config cfg;
	cfg.threads = threads;
	cfg.window_ns = static_cast<uint64_t>(window_ms) * 1'000'000ULL;
	xdpt::AfPacketEngine engine(ifname, cfg);
	if (!engine.start()) {
		std::fprintf(stderr, "af_packet start failed: %s\n", engine.error().c_str());
		return 1;
	}
	std::printf("AF_PACKET baseline on %s, %d thread(s), window %ldms\n",
		    ifname, threads, window_ms);

	std::signal(SIGINT, [](int) { g_stop = true; });
	std::signal(SIGTERM, [](int) { g_stop = true; });

	xdpt::Detector detector;
	xdpt::WindowSnapshot snap;

	uint64_t next = (mono_ns() / cfg.window_ns + 1) * cfg.window_ns;
	timespec slice{0, 20'000'000}; // 20ms
	while (!g_stop) {
		nanosleep(&slice, nullptr);
		uint64_t now = mono_ns();
		if (now < next)
			continue;
		next += cfg.window_ns;

		engine.collect(now, snap);
		xdpt::WindowReport rep = xdpt::build_report(snap);
		print_line(snap, rep);
		for (const xdpt::Alert &al : detector.evaluate(rep)) {
			char ip[INET_ADDRSTRLEN] = "global";
			if (al.saddr) inet_ntop(AF_INET, &al.saddr, ip, sizeof ip);
			std::printf("  ALERT [%s] %-14s %-15s %s\n", xdpt::severity_name(al.severity),
				    xdpt::alert_kind_name(al.kind), ip, al.detail.c_str());
			if (jf)
				std::fprintf(jf, "{\"alert\":\"%s\",\"src\":\"%s\",\"seq\":%llu,\"detail\":\"%s\"}\n",
					     xdpt::alert_kind_name(al.kind), ip,
					     (unsigned long long)rep.seq, al.detail.c_str());
		}
		if (jf)
			std::fprintf(jf, "{\"seq\":%llu,\"pps\":%.0f,\"mbps\":%.2f,\"flows\":%llu,"
				     "\"srcs\":%zu,\"drops\":%llu,\"collect_us\":%.1f}\n",
				     (unsigned long long)snap.seq, rep.pps, rep.mbps,
				     (unsigned long long)snap.active_flows, snap.srcs.size(),
				     (unsigned long long)snap.drops, snap.collect_us);
		std::fflush(stdout);
	}

	engine.stop();
	if (jf && jf != stdout) std::fclose(jf);
	std::printf("\nstopped\n");
	return 0;
}
