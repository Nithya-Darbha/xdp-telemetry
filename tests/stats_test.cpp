// Unit tests for core/stats.h and core/report.cpp. Pure functions, run under
// ASan/UBSan. The linear-counting test uses the SAME sketch hash as the XDP
// program (bpf/sketch.h), so it also checks that the kernel and userspace
// agree on how bits are set.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <vector>

#include "core/report.h"
#include "core/snapshot.h"
#include "core/stats.h"
#include "sketch.h"

using namespace xdpt;

namespace {
int g_run = 0, g_fail = 0;

void ok(const char *name, bool cond)
{
	g_run++;
	if (!cond) { g_fail++; std::printf("FAIL %s\n", name); }
}

void near(const char *name, double got, double want, double tol)
{
	g_run++;
	if (std::fabs(got - want) > tol) {
		g_fail++;
		std::printf("FAIL %-36s got %.3f want %.3f (+-%.3f)\n", name, got, want, tol);
	}
}

// Set the sketch bits for `n` distinct dst ports exactly as the XDP program
// would, then return the popcount, so linear_count sees a real sketch.
uint32_t sketch_ports(uint32_t n, uint32_t words, uint32_t seed)
{
	std::vector<uint64_t> bm(words, 0);
	for (uint32_t v = 0; v < n; v++) {
		uint32_t b = xdpt_sketch_bit(v, seed, words);
		bm[(b >> 6) & (words - 1)] |= 1ULL << (b & 63);
	}
	uint32_t set = 0;
	for (uint64_t w : bm) set += __builtin_popcountll(w);
	return set;
}
} // namespace

int main()
{
	// ---- linear counting accuracy against the real sketch -----------------
	// 1024-bit port sketch. Estimates should track truth within a few percent
	// until the sketch starts to fill.
	for (uint32_t n : {10u, 50u, 100u, 300u, 600u}) {
		uint32_t bits = sketch_ports(n, XDPT_PORT_BM_WORDS, XDPT_SEED_PORT);
		auto e = linear_count(bits, XDPT_PORT_BM_WORDS * 64);
		char nm[64];
		std::snprintf(nm, sizeof nm, "linear_count n=%u", n);
		// tolerance grows with load; 12% is comfortable up to ~60% fill
		near(nm, e.value, n, std::max(3.0, n * 0.12));
		ok("not saturated below capacity", !e.saturated);
	}
	{
		// A genuinely full sketch (every bit set) must saturate and stay
		// finite rather than returning +inf from log(0).
		auto full = linear_count(1024, 1024);
		ok("full sketch saturates", full.saturated);
		ok("full sketch finite", std::isfinite(full.value));
		// Heavy but not full: large estimate, and underestimates the truth
		// once the sketch is crowded (expected, that is why detection
		// thresholds sit well below the sketch capacity).
		uint32_t bits = sketch_ports(5000, XDPT_PORT_BM_WORDS, XDPT_SEED_PORT);
		auto e = linear_count(bits, XDPT_PORT_BM_WORDS * 64);
		ok("heavy fill reads high", std::isfinite(e.value) && e.value > 600);
	}
	{
		auto e = linear_count(0, 1024);
		near("empty sketch ~0", e.value, 0.0, 1e-9);
	}

	// ---- EWMA --------------------------------------------------------------
	{
		Ewma w(0.5);
		ok("unprimed", !w.primed());
		w.update(100);
		ok("primed after first", w.primed());
		near("first mean == x", w.mean(), 100.0, 1e-9);
		near("first var 0", w.variance(), 0.0, 1e-9);
		for (int i = 0; i < 50; i++) w.update(100);
		near("mean holds on constant", w.mean(), 100.0, 1e-6);
		near("var ~0 on constant", w.variance(), 0.0, 1e-6);
		// a spike far above a quiet baseline is a large z-score
		double z = w.zscore(1000);
		ok("spike is high z", z > 100);
	}
	{
		// Mean tracks a step change within a few updates.
		Ewma w(0.5);
		for (int i = 0; i < 20; i++) w.update(10);
		for (int i = 0; i < 20; i++) w.update(20);
		near("tracks step", w.mean(), 20.0, 0.5);
	}

	// ---- size percentiles --------------------------------------------------
	{
		std::array<uint64_t, XDPT_SIZE_BUCKETS> h{};
		// 90 packets in bucket 1 [64,128), 10 in bucket 23 [1472,1536)
		h[1] = 90;
		h[23] = 10;
		ok("p50 in small bucket", size_percentile(h, 0.50) == 2 * XDPT_SIZE_BUCKET);
		ok("p90 still small", size_percentile(h, 0.90) == 2 * XDPT_SIZE_BUCKET);
		ok("p99 in large bucket", size_percentile(h, 0.99) == 24 * XDPT_SIZE_BUCKET);
		std::array<uint64_t, XDPT_SIZE_BUCKETS> empty{};
		ok("empty hist p50 == 0", size_percentile(empty, 0.50) == 0);
	}

	// ---- top-k flows -------------------------------------------------------
	{
		std::vector<FlowSummary> flows;
		for (uint32_t i = 0; i < 100; i++) {
			FlowSummary f{};
			f.key.saddr = i;
			f.stats.bytes = i * 10;
			flows.push_back(f);
		}
		auto top = top_k_flows(flows, 3, [](const FlowSummary &f) { return f.stats.bytes; });
		ok("top-k size", top.size() == 3);
		ok("top-k ordered", top[0].stats.bytes == 990 && top[1].stats.bytes == 980 &&
				    top[2].stats.bytes == 970);
		auto all = top_k_flows(flows, 1000, [](const FlowSummary &f) { return f.stats.bytes; });
		ok("top-k clamps to n", all.size() == 100);
	}

	// ---- report wiring -----------------------------------------------------
	{
		WindowSnapshot s;
		s.seq = 7;
		s.dt = 0.5;
		s.delta[XDPT_C_PKTS] = 1000;
		s.delta[XDPT_C_BYTES] = 64000;
		s.size_delta[1] = 1000;
		SrcSummary src{};
		src.saddr = 0x0100000a;
		src.pkts = 500;
		src.port_bits = sketch_ports(200, XDPT_PORT_BM_WORDS, XDPT_SEED_PORT);
		src.ip_bits = 1;
		s.srcs.push_back(src);
		FlowSummary f{};
		f.stats.bytes = 50000;
		s.flows.push_back(f);

		WindowReport r = build_report(s);
		near("pps", r.pps, 2000.0, 1e-6);
		near("mbps", r.mbps, 64000.0 * 8 / 1e6 / 0.5, 1e-6);
		ok("src carried", r.srcs.size() == 1);
		near("src distinct ports ~200", r.srcs[0].distinct_ports, 200.0, 30.0);
		near("src distinct ips ~1", r.srcs[0].distinct_ips, 1.0, 0.5);
		ok("top flow present", r.top_flows.size() == 1 && r.top_flows[0].stats.bytes == 50000);
	}

	std::printf("%d/%d checks passed\n", g_run - g_fail, g_run);
	return g_fail ? 1 : 0;
}
