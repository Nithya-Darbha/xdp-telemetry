#include "bpf_engine.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cstring>
#include <ctime>

#include "telemetry.skel.h"

namespace xdpt {

static double mono_us()
{
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<double>(ts.tv_sec) * 1e6 + static_cast<double>(ts.tv_nsec) * 1e-3;
}

static int popcount64(uint64_t x) { return __builtin_popcountll(x); }

// libbpf calls this once per event record. ctx is the BpfEngine.
int bpf_engine_event_cb(void *ctx, void *data, size_t len)
{
	auto *self = static_cast<BpfEngine *>(ctx);
	if (len >= sizeof(xdpt_event)) {
		xdpt_event e;
		std::memcpy(&e, data, sizeof(e)); // data may be unaligned in the ring
		self->pending_events_.push_back(e);
	}
	return 0;
}

BpfEngine::BpfEngine(telemetry *skel, const Config &cfg)
	: skel_(skel), cfg_(cfg), ncpu_(libbpf_num_possible_cpus())
{
	fd_counters_ = bpf_map__fd(skel_->maps.xdpt_counters);
	fd_sizes_    = bpf_map__fd(skel_->maps.xdpt_sizes);
	fd_flows_    = bpf_map__fd(skel_->maps.xdpt_flows);
	fd_srcs_     = bpf_map__fd(skel_->maps.xdpt_srcs);

	prev_counters_.assign(XDPT_C__MAX, 0);
	prev_sizes_.assign(XDPT_SIZE_BUCKETS, 0);
	cpubuf_.resize(ncpu_);

	rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.xdpt_events),
			       bpf_engine_event_cb, this, nullptr);
}

BpfEngine::~BpfEngine()
{
	if (rb_)
		ring_buffer__free(rb_);
}

void BpfEngine::poll_events(int timeout_ms)
{
	if (rb_)
		ring_buffer__poll(rb_, timeout_ms);
}

void BpfEngine::read_counters(WindowSnapshot &out)
{
	for (uint32_t k = 0; k < XDPT_C__MAX; k++) {
		uint64_t sum = 0;
		if (bpf_map_lookup_elem(fd_counters_, &k, cpubuf_.data()) == 0)
			for (int c = 0; c < ncpu_; c++)
				sum += cpubuf_[c];
		out.total[k] = sum;
		out.delta[k] = first_ ? 0 : sum - prev_counters_[k];
		prev_counters_[k] = sum;
	}
}

void BpfEngine::read_sizes(WindowSnapshot &out)
{
	for (uint32_t k = 0; k < XDPT_SIZE_BUCKETS; k++) {
		uint64_t sum = 0;
		if (bpf_map_lookup_elem(fd_sizes_, &k, cpubuf_.data()) == 0)
			for (int c = 0; c < ncpu_; c++)
				sum += cpubuf_[c];
		out.size_delta[k] = first_ ? 0 : sum - prev_sizes_[k];
		prev_sizes_[k] = sum;
	}
}

void BpfEngine::read_flows(uint64_t now_ns, WindowSnapshot &out)
{
	// Iterate with get_next_key. Collecting keys to delete first and deleting
	// after the walk avoids disturbing the iterator mid-traversal.
	flow_key key{}, next{};
	flow_stats fs{};
	std::vector<flow_key> to_delete;
	bool have = bpf_map_get_next_key(fd_flows_, nullptr, &next) == 0;

	while (have) {
		key = next;
		have = bpf_map_get_next_key(fd_flows_, &key, &next) == 0;

		if (bpf_map_lookup_elem(fd_flows_, &key, &fs) != 0)
			continue;
		out.active_flows++;

		bool idle = fs.last_ns != 0 && now_ns > fs.last_ns &&
			    now_ns - fs.last_ns > cfg_.flow_ttl_ns;
		if (idle) {
			to_delete.push_back(key);
			continue;
		}
		if (out.flows.size() < cfg_.max_flows_reported)
			out.flows.push_back({key, fs});
	}

	for (const auto &k : to_delete)
		if (bpf_map_delete_elem(fd_flows_, &k) == 0)
			out.aged_flows++;
}

void BpfEngine::read_srcs(uint64_t now_ns, WindowSnapshot &out)
{
	// Report the window that has fully closed: epoch E-1, where E = now/window.
	const uint64_t closed = now_ns / cfg_.window_ns;
	if (closed == 0)
		return;
	const uint64_t want = closed - 1;

	uint32_t key = 0, next = 0;
	src_window w{};
	bool have = bpf_map_get_next_key(fd_srcs_, nullptr, &next) == 0;

	while (have) {
		key = next;
		have = bpf_map_get_next_key(fd_srcs_, &key, &next) == 0;

		if (bpf_map_lookup_elem(fd_srcs_, &key, &w) != 0)
			continue;
		const src_slot &s = w.slot[want & 1];
		if (s.epoch != want || s.pkts == 0)
			continue; // this source was idle in the closed window

		SrcSummary ss{};
		ss.saddr = key;
		ss.epoch = s.epoch;
		ss.pkts = s.pkts;
		ss.bytes = s.bytes;
		ss.syn = s.syn;
		ss.rst = s.rst;
		ss.bad_flags = s.bad_flags;
		for (uint64_t word : s.port_bm) ss.port_bits += popcount64(word);
		for (uint64_t word : s.ip_bm)   ss.ip_bits += popcount64(word);
		out.srcs.push_back(ss);
	}
}

bool BpfEngine::collect(uint64_t now_ns, WindowSnapshot &out)
{
	double start = mono_us();

	out = WindowSnapshot{};
	out.seq = seq_++;
	out.t_mono = static_cast<double>(now_ns) * 1e-9;

	read_counters(out);
	read_sizes(out);
	read_flows(now_ns, out);
	read_srcs(now_ns, out);

	out.events.swap(pending_events_); // everything drained since last collect
	pending_events_.clear();

	double tnow = out.t_mono;
	out.dt = first_ ? 0 : tnow - t_prev_;
	t_prev_ = tnow;
	first_ = false;

	out.collect_us = mono_us() - start;
	return true;
}

} // namespace xdpt
