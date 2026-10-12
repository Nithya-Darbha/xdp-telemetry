#include "core/detect.h"

#include <cstdio>

namespace xdpt {

const char *alert_kind_name(AlertKind k)
{
	switch (k) {
	case AlertKind::PortScan:       return "port_scan";
	case AlertKind::IpSweep:        return "ip_sweep";
	case AlertKind::SynFlood:       return "syn_flood";
	case AlertKind::BadFlags:       return "bad_flags";
	case AlertKind::RateSpike:      return "rate_spike";
	case AlertKind::SynRateSpike:   return "syn_rate_spike";
	case AlertKind::MalformedSpike: return "malformed_spike";
	case AlertKind::HeavyHitter:    return "heavy_hitter";
	}
	return "?";
}

const char *severity_name(Severity s)
{
	switch (s) {
	case Severity::Info: return "info";
	case Severity::Warn: return "warn";
	case Severity::Crit: return "crit";
	}
	return "?";
}

Detector::Detector(const DetectConfig &cfg)
	: cfg_(cfg), pps_(cfg.ewma_alpha), syn_(cfg.ewma_alpha) {}

namespace {
void fmt(Alert &a, const char *f, double v, double thr)
{
	char buf[160];
	std::snprintf(buf, sizeof buf, f, v, thr);
	a.detail = buf;
}
} // namespace

std::vector<Alert> Detector::evaluate(const WindowReport &rep)
{
	std::vector<Alert> out;

	// ---- per-source, per-window thresholds --------------------------------
	for (const SrcReport &s : rep.srcs) {
		if (s.distinct_ports >= cfg_.scan_ports ||
		    (cfg_.alert_on_saturation && s.ports_saturated)) {
			Alert a{AlertKind::PortScan, Severity::Crit, s.saddr,
				s.distinct_ports, cfg_.scan_ports, {}};
			fmt(a, "~%.0f distinct dst ports (>= %.0f)", s.distinct_ports, cfg_.scan_ports);
			if (s.ports_saturated) a.detail += " [sketch saturated]";
			out.push_back(a);
		}
		if (s.distinct_ips >= cfg_.sweep_ips ||
		    (cfg_.alert_on_saturation && s.ips_saturated)) {
			Alert a{AlertKind::IpSweep, Severity::Crit, s.saddr,
				s.distinct_ips, cfg_.sweep_ips, {}};
			fmt(a, "~%.0f distinct dst IPs (>= %.0f)", s.distinct_ips, cfg_.sweep_ips);
			if (s.ips_saturated) a.detail += " [sketch saturated]";
			out.push_back(a);
		}
		if (s.syn >= cfg_.syn_per_src) {
			Alert a{AlertKind::SynFlood, Severity::Crit, s.saddr,
				double(s.syn), double(cfg_.syn_per_src), {}};
			fmt(a, "%.0f half-open SYNs (>= %.0f)", double(s.syn), double(cfg_.syn_per_src));
			out.push_back(a);
		}
		if (s.bad_flags >= cfg_.bad_flags_min) {
			Alert a{AlertKind::BadFlags, Severity::Warn, s.saddr,
				double(s.bad_flags), double(cfg_.bad_flags_min), {}};
			fmt(a, "%.0f packets with illegal TCP flags (>= %.0f)",
			    double(s.bad_flags), double(cfg_.bad_flags_min));
			out.push_back(a);
		}
	}

	// ---- heavy hitter ------------------------------------------------------
	if (!rep.top_flows.empty() && rep.win_bytes > 0) {
		uint64_t top = rep.top_flows.front().stats.bytes;
		double share = double(top) / double(rep.win_bytes);
		// stats.bytes is cumulative per flow, not per window, so this flags a
		// flow that dominates total bytes seen. Good enough as a "one flow owns
		// the link" signal; a per-window flow delta would sharpen it (phase 9).
		if (share >= cfg_.hh_share && top >= cfg_.hh_min_bytes) {
			Alert a{AlertKind::HeavyHitter, Severity::Info, 0, share, cfg_.hh_share, {}};
			fmt(a, "top flow is %.0f%% of bytes (>= %.0f%%)", share * 100, cfg_.hh_share * 100);
			out.push_back(a);
		}
	}

	// ---- baseline deviation (only once a baseline exists) -----------------
	if (primed_) {
		if (rep.pps >= cfg_.min_pps && pps_.primed()) {
			double z = pps_.zscore(rep.pps, cfg_.min_pps * 0.1);
			if (z >= cfg_.z_threshold) {
				Alert a{AlertKind::RateSpike, Severity::Warn, 0, rep.pps, pps_.mean(), {}};
				fmt(a, "pps %.0f vs baseline %.0f", rep.pps, pps_.mean());
				char z2[48]; std::snprintf(z2, sizeof z2, " (z=%.1f)", z);
				a.detail += z2;
				out.push_back(a);
			}
		}
		if (rep.syn_pps >= cfg_.min_pps && syn_.primed()) {
			double z = syn_.zscore(rep.syn_pps, cfg_.min_pps * 0.1);
			if (z >= cfg_.z_threshold) {
				Alert a{AlertKind::SynRateSpike, Severity::Warn, 0, rep.syn_pps, syn_.mean(), {}};
				fmt(a, "SYN pps %.0f vs baseline %.0f", rep.syn_pps, syn_.mean());
				out.push_back(a);
			}
		}
	}

	// ---- malformed fraction ------------------------------------------------
	if (rep.win_pkts > 0) {
		double frac = double(rep.win_malformed) / double(rep.win_pkts);
		if (frac >= 0.05 && rep.win_malformed >= 10) {
			Alert a{AlertKind::MalformedSpike, Severity::Warn, 0, frac, 0.05, {}};
			fmt(a, "%.1f%% of frames malformed (>= %.0f%%)", frac * 100, 5.0);
			out.push_back(a);
		}
	}

	// Update baselines AFTER evaluation, so this window never grades itself.
	pps_.update(rep.pps);
	syn_.update(rep.syn_pps);
	primed_ = true;
	return out;
}

} // namespace xdpt
