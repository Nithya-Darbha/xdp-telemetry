// Anomaly detection over WindowReports. Two kinds of rule:
//   * per-window thresholds (scans, sweeps, bad flags, heavy hitters) -- the
//     window itself is the evidence, no history needed
//   * baseline deviation (global packet-rate and SYN-rate spikes) -- an EWMA
//     learns normal and flags departures from it
// Keeping scans as thresholds and rate spikes as baselines is deliberate: a
// port scan is defined by its fan-out, not by being faster than yesterday.
#ifndef XDPT_CORE_DETECT_H
#define XDPT_CORE_DETECT_H

#include <cstdint>
#include <string>
#include <vector>

#include "core/report.h"
#include "core/snapshot.h"
#include "core/stats.h"

namespace xdpt {

enum class Severity { Info, Warn, Crit };

enum class AlertKind {
	PortScan,       // one source, many distinct dst ports
	IpSweep,        // one source, many distinct dst IPs
	SynFlood,       // one source, many half-open SYNs
	BadFlags,       // one source, illegal TCP flag combos
	RateSpike,      // global pps far above its baseline
	SynRateSpike,   // global SYN pps far above its baseline
	MalformedSpike, // malformed fraction of traffic too high
	HeavyHitter,    // one flow dominates the link
};

struct Alert {
	AlertKind kind;
	Severity  severity;
	uint32_t  saddr = 0;   // source IP (network order), 0 for global alerts
	double    value = 0;   // the measured quantity
	double    threshold = 0;
	std::string detail;    // human-readable, already formatted
};

struct DetectConfig {
	// per-source thresholds, per window
	double scan_ports = 100;   // distinct dst ports -> port scan
	double sweep_ips = 50;     // distinct dst IPs -> sweep
	uint32_t syn_per_src = 200; // half-open SYNs from one source
	uint32_t bad_flags_min = 3; // illegal-flag packets from one source

	// baseline deviation
	double z_threshold = 6.0;   // sigmas above EWMA to flag
	double ewma_alpha = 0.2;
	double min_pps = 200;       // don't flag rate spikes in near-idle traffic

	// heavy hitter
	double hh_share = 0.80;     // one flow this fraction of window bytes
	uint64_t hh_min_bytes = 1u << 20; // and at least this many bytes

	// alerts for saturated sketches even if the estimate is below threshold
	bool alert_on_saturation = true;
};

class Detector {
public:
	explicit Detector(const DetectConfig &cfg = {});

	// Evaluate one window. Baselines update from this window after the checks,
	// so a window is never compared against a baseline that already includes it.
	std::vector<Alert> evaluate(const WindowReport &rep);

	const Ewma &pps_baseline() const { return pps_; }
	const Ewma &syn_baseline() const { return syn_; }

private:
	DetectConfig cfg_;
	Ewma pps_;
	Ewma syn_;
	bool primed_ = false; // at least one window seen, so baselines mean something
};

const char *alert_kind_name(AlertKind k);
const char *severity_name(Severity s);

} // namespace xdpt

#endif // XDPT_CORE_DETECT_H
