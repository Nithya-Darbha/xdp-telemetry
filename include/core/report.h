// A WindowReport is a WindowSnapshot plus the derived quantities detection and
// output actually use: rates, size percentiles, per-source fan-out estimates,
// and the heaviest flows. No EWMA state here; that lives in the detector.
#ifndef XDPT_CORE_REPORT_H
#define XDPT_CORE_REPORT_H

#include <cstdint>
#include <vector>

#include "core/snapshot.h"

namespace xdpt {

struct SrcReport {
	uint32_t saddr = 0;        // network byte order
	uint64_t pkts = 0;
	uint64_t bytes = 0;
	uint32_t syn = 0;
	uint32_t rst = 0;
	uint32_t bad_flags = 0;
	double   distinct_ports = 0;
	double   distinct_ips = 0;
	bool     ports_saturated = false;
	bool     ips_saturated = false;
};

struct WindowReport {
	uint64_t seq = 0;
	double   dt = 0;
	double   pps = 0;
	double   mbps = 0;
	double   syn_pps = 0;          // half-open SYN rate (global)
	uint64_t win_pkts = 0;         // packets this window
	uint64_t win_bytes = 0;        // bytes this window
	uint64_t win_malformed = 0;    // malformed frames this window
	uint32_t size_p50 = 0;
	uint32_t size_p90 = 0;
	uint32_t size_p99 = 0;
	std::vector<SrcReport>   srcs;        // fan-out resolved from sketches
	std::vector<FlowSummary> top_flows;    // by bytes, largest first
};

struct ReportConfig {
	size_t top_flows = 10;
};

// Build the derived view. Does not mutate the snapshot.
WindowReport build_report(const WindowSnapshot &snap, const ReportConfig &cfg = {});

} // namespace xdpt

#endif // XDPT_CORE_REPORT_H
