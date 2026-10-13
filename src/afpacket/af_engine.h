// AF_PACKET baseline capture path.
//
// The point of comparison: this and the XDP engine must do the SAME work and
// differ only in where packets are captured. So this uses the strongest sane
// userspace setup -- TPACKET_V3 mmap rings with PACKET_FANOUT across threads,
// not a recvfrom() loop -- runs the identical bpf/parse.h on each frame, and
// produces the same WindowSnapshot the BPF engine does, so detection and
// reporting are byte-for-byte the same downstream.
#ifndef XDPT_AF_ENGINE_H
#define XDPT_AF_ENGINE_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>
#include <unordered_map>
#include <vector>

#include "core/snapshot.h"
#include "shared/types.h"

namespace xdpt {

// Per-thread aggregate. Each worker owns one, so the capture hot path never
// locks; the engine merges them at window boundaries.
struct AfAggregate {
	std::array<uint64_t, XDPT_C__MAX> counters{};
	std::array<uint64_t, XDPT_SIZE_BUCKETS> sizes{};

	struct FlowKeyHash {
		size_t operator()(const flow_key &k) const noexcept;
	};
	struct FlowKeyEq {
		bool operator()(const flow_key &a, const flow_key &b) const noexcept;
	};
	std::unordered_map<flow_key, flow_stats, FlowKeyHash, FlowKeyEq> flows;

	// Source windows: two slots keyed by epoch parity, same scheme as the BPF
	// side, so the fan-out sketches are computed identically.
	std::unordered_map<uint32_t, src_window> srcs;

	void reset_light() {} // nothing to reset; totals are cumulative
};

class AfPacketEngine {
public:
	struct Config {
		int threads = 1;             // PACKET_FANOUT workers
		uint64_t window_ns = 1'000'000'000ULL;
		unsigned block_size = 1 << 20;
		unsigned block_count = 16;
		unsigned frame_size = 2048;
		uint32_t max_flows_reported = 4096;
	};

	AfPacketEngine(const char *ifname, const Config &cfg);
	~AfPacketEngine();
	AfPacketEngine(const AfPacketEngine &) = delete;
	AfPacketEngine &operator=(const AfPacketEngine &) = delete;

	bool start();                 // open sockets, spawn workers
	void stop();                  // join workers
	bool collect(uint64_t now_ns, WindowSnapshot &out); // merge + deltas

	const std::string &error() const { return err_; }

private:
	struct Worker;
	void run_worker(Worker *w);

	std::string ifname_;
	Config cfg_;
	std::string err_;
	int ifindex_ = -1;

	std::vector<std::unique_ptr<Worker>> workers_;
	std::atomic<bool> running_{false};

	// delta bookkeeping, same as BpfEngine
	std::array<uint64_t, XDPT_C__MAX> prev_counters_{};
	std::array<uint64_t, XDPT_SIZE_BUCKETS> prev_sizes_{};
	uint64_t seq_ = 0;
	double t_prev_ = 0;
	bool first_ = true;
};

} // namespace xdpt

#endif // XDPT_AF_ENGINE_H
