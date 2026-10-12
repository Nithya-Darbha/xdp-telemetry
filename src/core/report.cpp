#include "core/report.h"

#include "core/stats.h"

namespace xdpt {

WindowReport build_report(const WindowSnapshot &snap, const ReportConfig &cfg)
{
	WindowReport r;
	r.seq = snap.seq;
	r.dt = snap.dt;

	r.win_pkts = snap.d(XDPT_C_PKTS);
	r.win_bytes = snap.d(XDPT_C_BYTES);
	for (int p = XDPT_P_ERR_FIRST; p < XDPT_P__MAX; p++)
		r.win_malformed += snap.delta[XDPT_C_RESULT_BASE + p];

	if (snap.dt > 0) {
		r.pps = static_cast<double>(r.win_pkts) / snap.dt;
		r.mbps = static_cast<double>(r.win_bytes) * 8.0 / 1e6 / snap.dt;
		r.syn_pps = static_cast<double>(snap.d(XDPT_C_SYN)) / snap.dt;
	}

	r.size_p50 = size_percentile(snap.size_delta, 0.50);
	r.size_p90 = size_percentile(snap.size_delta, 0.90);
	r.size_p99 = size_percentile(snap.size_delta, 0.99);

	r.srcs.reserve(snap.srcs.size());
	for (const SrcSummary &s : snap.srcs) {
		SrcReport sr;
		sr.saddr = s.saddr;
		sr.pkts = s.pkts;
		sr.bytes = s.bytes;
		sr.syn = s.syn;
		sr.rst = s.rst;
		sr.bad_flags = s.bad_flags;
		auto pe = linear_count(s.port_bits, XDPT_PORT_BM_WORDS * 64);
		auto ie = linear_count(s.ip_bits, XDPT_IP_BM_WORDS * 64);
		sr.distinct_ports = pe.value;
		sr.distinct_ips = ie.value;
		sr.ports_saturated = pe.saturated;
		sr.ips_saturated = ie.saturated;
		r.srcs.push_back(sr);
	}

	r.top_flows = top_k_flows(snap.flows, cfg.top_flows,
		[](const FlowSummary &f) { return f.stats.bytes; });

	return r;
}

} // namespace xdpt
