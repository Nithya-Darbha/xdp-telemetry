// One window's worth of telemetry, independent of where it came from.
// The BPF engine (phase 5) and the AF_PACKET baseline (phase 8) both produce
// this, so detection (phase 7) and output never know which capture path ran.
#ifndef XDPT_CORE_SNAPSHOT_H
#define XDPT_CORE_SNAPSHOT_H

#include <array>
#include <cstdint>
#include <vector>

#include "shared/types.h"

namespace xdpt {

// A flow worth reporting: its key plus the counters read from the map.
struct FlowSummary {
	flow_key key;
	flow_stats stats;
};

// A source's just-closed window. port_bits / ip_bits are the raw popcounts of
// the fan-out sketches; phase 6 turns them into estimated distinct counts.
struct SrcSummary {
	uint32_t saddr;      // network byte order
	uint64_t epoch;
	uint64_t pkts;
	uint64_t bytes;
	uint32_t syn;
	uint32_t rst;
	uint32_t bad_flags;
	uint32_t port_bits;  // set bits in the 1024-bit dst-port sketch
	uint32_t ip_bits;    // set bits in the 512-bit dst-IP sketch
};

struct WindowSnapshot {
	uint64_t seq = 0;         // window index since start
	double   t_mono = 0;      // CLOCK_MONOTONIC seconds at read time
	double   dt = 0;          // seconds since the previous snapshot

	// Global counters: cumulative totals and this-window deltas, indexed by
	// enum xdpt_counter. Deltas are what detection and rates use.
	std::array<uint64_t, XDPT_C__MAX> total{};
	std::array<uint64_t, XDPT_C__MAX> delta{};

	// Frame-size histogram deltas, 64-byte buckets.
	std::array<uint64_t, XDPT_SIZE_BUCKETS> size_delta{};

	std::vector<FlowSummary> flows;   // live flows at read time
	std::vector<SrcSummary>  srcs;     // sources active in the closed window
	std::vector<xdpt_event>  events;   // ring-buffer events since last read

	uint64_t active_flows = 0;
	uint64_t aged_flows = 0;   // evicted from the userspace view this window
	uint64_t drops = 0;        // frames the capture path dropped this window
	double   collect_us = 0;   // wall-clock cost of building this snapshot

	uint64_t d(xdpt_counter c) const { return delta[c]; }
	uint64_t t(xdpt_counter c) const { return total[c]; }
};

} // namespace xdpt

#endif // XDPT_CORE_SNAPSHOT_H
