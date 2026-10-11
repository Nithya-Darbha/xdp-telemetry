// Reads the XDP program's maps into a WindowSnapshot once per window.
#ifndef XDPT_BPF_ENGINE_H
#define XDPT_BPF_ENGINE_H

#include <cstdint>
#include <vector>

#include "core/snapshot.h"

struct telemetry;   // libbpf skeleton
struct ring_buffer; // libbpf ringbuf reader

namespace xdpt {

class BpfEngine {
public:
	struct Config {
		uint64_t window_ns = 1'000'000'000ULL;
		uint64_t flow_ttl_ns = 10'000'000'000ULL; // drop idle flows from view after this
		uint32_t max_flows_reported = 4096;        // cap per-window flow dump
	};

	// skel must already be loaded. Does not take ownership.
	BpfEngine(telemetry *skel, const Config &cfg);
	~BpfEngine();
	BpfEngine(const BpfEngine &) = delete;
	BpfEngine &operator=(const BpfEngine &) = delete;

	// Fill `out` with the window that just closed. now_ns is CLOCK_MONOTONIC,
	// the same clock the kernel stamps packets with.
	bool collect(uint64_t now_ns, WindowSnapshot &out);

	// Non-blocking drain of pending events into the next snapshot.
	void poll_events(int timeout_ms);

private:
	void read_counters(WindowSnapshot &out);
	void read_sizes(WindowSnapshot &out);
	void read_flows(uint64_t now_ns, WindowSnapshot &out);
	void read_srcs(uint64_t now_ns, WindowSnapshot &out);

	telemetry *skel_;
	Config cfg_;
	int ncpu_;

	int fd_counters_, fd_sizes_, fd_flows_, fd_srcs_;
	ring_buffer *rb_ = nullptr;

	std::vector<uint64_t> prev_counters_;   // for deltas
	std::vector<uint64_t> prev_sizes_;
	std::vector<uint64_t> cpubuf_;          // scratch for per-CPU reads
	uint64_t seq_ = 0;
	double t_prev_ = 0;
	bool first_ = true;

	// Events land here from the ringbuf callback, then move into the snapshot.
	std::vector<xdpt_event> pending_events_;
	friend int bpf_engine_event_cb(void *ctx, void *data, size_t len);
};

} // namespace xdpt

#endif // XDPT_BPF_ENGINE_H
