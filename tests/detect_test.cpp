// Unit tests for the detector. Each test builds a synthetic WindowReport and
// checks that exactly the expected alert fires (or that none do on clean
// traffic). No network, no kernel.
#include <cstdio>
#include <string>
#include <vector>

#include "core/detect.h"
#include "core/report.h"

using namespace xdpt;

namespace {
int g_run = 0, g_fail = 0;

void ok(const char *name, bool cond)
{
	g_run++;
	if (!cond) { g_fail++; std::printf("FAIL %s\n", name); }
}

bool has(const std::vector<Alert> &v, AlertKind k)
{
	for (const Alert &a : v) if (a.kind == k) return true;
	return false;
}

SrcReport src(uint32_t ip, double ports, double ips, uint32_t syn, uint32_t bad)
{
	SrcReport s;
	s.saddr = ip; s.distinct_ports = ports; s.distinct_ips = ips;
	s.syn = syn; s.bad_flags = bad; s.pkts = 1000;
	return s;
}

// A steady, boring window: modest rate, one dst port, one dst IP.
WindowReport clean(uint64_t seq, double pps)
{
	WindowReport r;
	r.seq = seq; r.dt = 1.0; r.pps = pps; r.syn_pps = 5;
	r.win_pkts = uint64_t(pps); r.win_bytes = uint64_t(pps) * 500;
	r.srcs.push_back(src(0x0100000a, 2, 1, 2, 0));
	return r;
}
} // namespace

int main()
{
	// ---- clean traffic raises nothing (after baseline warms up) -----------
	{
		Detector d;
		std::vector<Alert> all;
		for (int i = 0; i < 30; i++) {
			auto a = d.evaluate(clean(i, 1000 + (i % 5) * 10));
			all.insert(all.end(), a.begin(), a.end());
		}
		ok("clean traffic: no alerts", all.empty());
	}

	// ---- port scan ---------------------------------------------------------
	{
		Detector d;
		WindowReport r = clean(0, 1000);
		r.srcs[0] = src(0x0100000a, 400, 1, 50, 0); // 400 distinct ports
		auto a = d.evaluate(r);
		ok("port scan fires", has(a, AlertKind::PortScan));
		ok("port scan not sweep", !has(a, AlertKind::IpSweep));
	}

	// ---- ip sweep ----------------------------------------------------------
	{
		Detector d;
		WindowReport r = clean(0, 1000);
		r.srcs[0] = src(0x0100000a, 1, 200, 10, 0); // 200 distinct IPs, one port
		auto a = d.evaluate(r);
		ok("ip sweep fires", has(a, AlertKind::IpSweep));
		ok("ip sweep not scan", !has(a, AlertKind::PortScan));
	}

	// ---- saturated sketch still alerts below threshold --------------------
	{
		Detector d;
		WindowReport r = clean(0, 1000);
		SrcReport s = src(0x0100000a, 40, 1, 0, 0); // estimate below scan_ports
		s.ports_saturated = true;
		r.srcs[0] = s;
		auto a = d.evaluate(r);
		ok("saturation forces scan alert", has(a, AlertKind::PortScan));
	}

	// ---- SYN flood ---------------------------------------------------------
	{
		Detector d;
		WindowReport r = clean(0, 1000);
		r.srcs[0] = src(0x0100000a, 1, 1, 5000, 0);
		auto a = d.evaluate(r);
		ok("syn flood fires", has(a, AlertKind::SynFlood));
	}

	// ---- bad flags ---------------------------------------------------------
	{
		Detector d;
		WindowReport r = clean(0, 1000);
		r.srcs[0] = src(0x0100000a, 2, 1, 0, 20);
		auto a = d.evaluate(r);
		ok("bad flags fires", has(a, AlertKind::BadFlags));
	}

	// ---- rate spike vs learned baseline -----------------------------------
	{
		Detector d;
		for (int i = 0; i < 40; i++)      // learn ~1000 pps as normal
			d.evaluate(clean(i, 1000));
		WindowReport spike = clean(40, 100000); // 100x
		auto a = d.evaluate(spike);
		ok("rate spike fires", has(a, AlertKind::RateSpike));
	}
	{
		// No spike on the very first windows: baseline isn't trustworthy yet,
		// so a cold start must not alarm on ordinary traffic.
		Detector d;
		auto a0 = d.evaluate(clean(0, 1000));
		ok("cold start: no rate spike", !has(a0, AlertKind::RateSpike));
	}

	// ---- malformed fraction ------------------------------------------------
	{
		Detector d;
		WindowReport r = clean(0, 1000);
		r.win_pkts = 1000; r.win_malformed = 300; // 30%
		auto a = d.evaluate(r);
		ok("malformed spike fires", has(a, AlertKind::MalformedSpike));
	}

	// ---- heavy hitter ------------------------------------------------------
	{
		Detector d;
		WindowReport r = clean(0, 1000);
		r.win_bytes = 10'000'000;
		FlowSummary f{};
		f.stats.bytes = 9'000'000; // 90% of bytes
		r.top_flows.push_back(f);
		auto a = d.evaluate(r);
		ok("heavy hitter fires", has(a, AlertKind::HeavyHitter));
	}

	std::printf("%d/%d checks passed\n", g_run - g_fail, g_run);
	return g_fail ? 1 : 0;
}
