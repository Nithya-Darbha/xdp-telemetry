#include "af_engine.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <cerrno>

#include "parse.h"
#include "sketch.h"

namespace xdpt {

size_t AfAggregate::FlowKeyHash::operator()(const flow_key &k) const noexcept
{
	// FNV-1a over the 16 key bytes. Padding is always zeroed, so equal flows
	// hash equally.
	const uint8_t *p = reinterpret_cast<const uint8_t *>(&k);
	uint64_t h = 1469598103934665603ULL;
	for (size_t i = 0; i < sizeof(flow_key); i++) {
		h ^= p[i];
		h *= 1099511628211ULL;
	}
	return h;
}

bool AfAggregate::FlowKeyEq::operator()(const flow_key &a, const flow_key &b) const noexcept
{
	return std::memcmp(&a, &b, sizeof(flow_key)) == 0;
}

struct AfPacketEngine::Worker {
	int fd = -1;
	uint8_t *ring = nullptr;
	size_t ring_len = 0;
	unsigned block_count = 0;
	unsigned block_size = 0;
	unsigned next_block = 0;
	AfAggregate agg;
	std::thread th;
};

static uint64_t mono_ns()
{
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}

AfPacketEngine::AfPacketEngine(const char *ifname, const Config &cfg)
	: ifname_(ifname), cfg_(cfg) {}

AfPacketEngine::~AfPacketEngine()
{
	stop();
	for (auto &w : workers_) {
		if (w->ring && w->ring != MAP_FAILED)
			munmap(w->ring, w->ring_len);
		if (w->fd >= 0)
			close(w->fd);
	}
}

bool AfPacketEngine::start()
{
	ifindex_ = static_cast<int>(if_nametoindex(ifname_.c_str()));
	if (!ifindex_) { err_ = "unknown interface " + ifname_; return false; }

	// One fanout group shared by all workers; the kernel hashes each packet to
	// one socket by flow, so no packet is seen twice and flows stay on one CPU.
	const int fanout_id = static_cast<int>(getpid() & 0xffff);

	for (int i = 0; i < cfg_.threads; i++) {
		auto w = std::make_unique<Worker>();
		w->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (w->fd < 0) { err_ = "socket(AF_PACKET): need root"; return false; }

		int ver = TPACKET_V3;
		if (setsockopt(w->fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof ver) < 0) {
			err_ = "PACKET_VERSION TPACKET_V3 failed"; return false;
		}

		// XDP ingress sees inbound frames only. AF_PACKET captures both
		// directions by default, so without this the baseline would count the
		// target's replies too and the comparison would be unfair. Ignored on
		// kernels < 4.20, where the benchmark must note the caveat.
#ifdef PACKET_IGNORE_OUTGOING
		int one = 1;
		if (setsockopt(w->fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof one) < 0)
			std::fprintf(stderr, "warning: PACKET_IGNORE_OUTGOING failed: %s\n",
				     std::strerror(errno));
#endif

		tpacket_req3 req{};
		req.tp_block_size = cfg_.block_size;
		req.tp_block_nr = cfg_.block_count;
		req.tp_frame_size = cfg_.frame_size;
		req.tp_frame_nr = (cfg_.block_size / cfg_.frame_size) * cfg_.block_count;
		req.tp_retire_blk_tov = 60; // ms before kernel hands a partial block back
		req.tp_feature_req_word = 0;
		if (setsockopt(w->fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof req) < 0) {
			err_ = "PACKET_RX_RING failed"; return false;
		}

		w->ring_len = static_cast<size_t>(req.tp_block_size) * req.tp_block_nr;
		w->ring = static_cast<uint8_t *>(mmap(nullptr, w->ring_len, PROT_READ | PROT_WRITE,
						      MAP_SHARED | MAP_LOCKED, w->fd, 0));
		if (w->ring == MAP_FAILED) {
			w->ring = nullptr; err_ = "mmap ring failed"; return false;
		}
		w->block_count = req.tp_block_nr;
		w->block_size = req.tp_block_size;

		sockaddr_ll sll{};
		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_ALL);
		sll.sll_ifindex = ifindex_;
		if (bind(w->fd, reinterpret_cast<sockaddr *>(&sll), sizeof sll) < 0) {
			err_ = "bind failed"; return false;
		}

		if (cfg_.threads > 1) {
			int fo = fanout_id | (PACKET_FANOUT_HASH << 16);
			if (setsockopt(w->fd, SOL_PACKET, PACKET_FANOUT, &fo, sizeof fo) < 0) {
				err_ = "PACKET_FANOUT failed"; return false;
			}
		}
		workers_.push_back(std::move(w));
	}

	running_ = true;
	for (auto &w : workers_)
		w->th = std::thread([this, p = w.get()] { run_worker(p); });
	return true;
}

void AfPacketEngine::stop()
{
	if (!running_.exchange(false))
		return;
	for (auto &w : workers_)
		if (w->th.joinable())
			w->th.join();
}

// --- per-packet aggregation, mirroring bpf/telemetry.bpf.c -----------------

static void agg_flow(AfAggregate &a, const pkt_meta &m, uint64_t now)
{
	flow_key k;
	std::memset(&k, 0, sizeof k);
	k.saddr = m.saddr; k.daddr = m.daddr;
	k.sport = m.sport; k.dport = m.dport; k.proto = m.proto;

	auto it = a.flows.find(k);
	if (it == a.flows.end()) {
		flow_stats fs{};
		fs.first_ns = now;
		fs.min_len = 0xffff;
		it = a.flows.emplace(k, fs).first;
	}
	flow_stats &fs = it->second;
	uint16_t len = m.frame_len > 0xffff ? 0xffff : uint16_t(m.frame_len);
	fs.pkts++;
	fs.bytes += m.frame_len;
	fs.last_ns = now;
	if (len < fs.min_len) fs.min_len = len;
	if (len > fs.max_len) fs.max_len = len;
	if (m.proto == IPPROTO_TCP && m.l4_valid) {
		fs.flags_seen |= m.tcp_flags;
		if ((m.tcp_flags & (XDPT_TCP_SYN | XDPT_TCP_ACK)) == XDPT_TCP_SYN) fs.syn++;
		if (m.tcp_flags & XDPT_TCP_RST) fs.rst++;
	}
}

static void agg_src(AfAggregate &a, const pkt_meta &m, uint64_t now,
		    uint64_t window_ns, int fclass)
{
	auto it = a.srcs.find(m.saddr);
	if (it == a.srcs.end()) {
		src_window w{};
		w.slot[0].epoch = ~0ULL;
		w.slot[1].epoch = ~0ULL;
		it = a.srcs.emplace(m.saddr, w).first;
	}
	uint64_t ep = now / window_ns;
	src_slot &s = it->second.slot[ep & 1];
	if (s.epoch != ep) {
		std::memset(reinterpret_cast<uint8_t *>(&s) + sizeof(s.epoch), 0,
			    sizeof(s) - sizeof(s.epoch));
		s.epoch = ep;
	}
	s.pkts++;
	s.bytes += m.frame_len;
	uint32_t ib = xdpt_sketch_bit(m.daddr, XDPT_SEED_IP, XDPT_IP_BM_WORDS);
	s.ip_bm[(ib >> 6) & (XDPT_IP_BM_WORDS - 1)] |= 1ULL << (ib & 63);

	if (!m.l4_valid || m.proto == IPPROTO_ICMP)
		return;
	uint32_t pb = xdpt_sketch_bit(m.dport, XDPT_SEED_PORT, XDPT_PORT_BM_WORDS);
	s.port_bm[(pb >> 6) & (XDPT_PORT_BM_WORDS - 1)] |= 1ULL << (pb & 63);
	if (m.proto == IPPROTO_TCP) {
		if ((m.tcp_flags & (XDPT_TCP_SYN | XDPT_TCP_ACK)) == XDPT_TCP_SYN) s.syn++;
		if (m.tcp_flags & XDPT_TCP_RST) s.rst++;
		if (fclass != XDPT_F_OK) s.bad_flags++;
	}
}

static void agg_packet(AfAggregate &a, const uint8_t *frame, uint32_t len,
		       uint64_t now, uint64_t window_ns)
{
	pkt_meta m;
	int res = xdpt_parse(const_cast<uint8_t *>(frame),
			     const_cast<uint8_t *>(frame) + len, len, &m);

	a.counters[XDPT_C_PKTS]++;
	a.counters[XDPT_C_BYTES] += m.frame_len;
	a.counters[XDPT_C_RESULT_BASE + res]++;
	a.sizes[xdpt_size_bucket(m.frame_len)]++;
	if (res != XDPT_P_OK)
		return;

	if (m.is_frag) a.counters[XDPT_C_FRAG]++;
	int fclass = XDPT_F_OK;
	switch (m.proto) {
	case IPPROTO_TCP:
		a.counters[XDPT_C_TCP]++;
		if (m.l4_valid) {
			uint8_t f = m.tcp_flags;
			if ((f & (XDPT_TCP_SYN | XDPT_TCP_ACK)) == XDPT_TCP_SYN) a.counters[XDPT_C_SYN]++;
			else if ((f & (XDPT_TCP_SYN | XDPT_TCP_ACK)) == (XDPT_TCP_SYN | XDPT_TCP_ACK))
				a.counters[XDPT_C_SYNACK]++;
			if (f & XDPT_TCP_RST) a.counters[XDPT_C_RST]++;
			if (f & XDPT_TCP_FIN) a.counters[XDPT_C_FIN]++;
			fclass = xdpt_flag_class(f);
			a.counters[XDPT_C_FLAG_BASE + fclass]++;
		}
		break;
	case IPPROTO_UDP:  a.counters[XDPT_C_UDP]++; break;
	case IPPROTO_ICMP: a.counters[XDPT_C_ICMP]++; break;
	default:           a.counters[XDPT_C_L4_OTHER]++; break;
	}
	agg_flow(a, m, now);
	agg_src(a, m, now, window_ns, fclass);
}

void AfPacketEngine::run_worker(Worker *w)
{
	pollfd pfd{w->fd, POLLIN, 0};
	while (running_.load(std::memory_order_relaxed)) {
		auto *bd = reinterpret_cast<tpacket_block_desc *>(w->ring + w->next_block * w->block_size);
		if (!(bd->hdr.bh1.block_status & TP_STATUS_USER)) {
			poll(&pfd, 1, 100); // wait up to 100ms for this block to fill
			continue;
		}
		uint64_t now = mono_ns();
		uint32_t n = bd->hdr.bh1.num_pkts;
		auto *ph = reinterpret_cast<tpacket3_hdr *>(
			reinterpret_cast<uint8_t *>(bd) + bd->hdr.bh1.offset_to_first_pkt);
		for (uint32_t i = 0; i < n; i++) {
			const uint8_t *frame = reinterpret_cast<const uint8_t *>(ph) + ph->tp_mac;
			agg_packet(w->agg, frame, ph->tp_snaplen, now, cfg_.window_ns);
			ph = reinterpret_cast<tpacket3_hdr *>(
				reinterpret_cast<uint8_t *>(ph) + ph->tp_next_offset);
		}
		bd->hdr.bh1.block_status = TP_STATUS_KERNEL; // hand the block back
		w->next_block = (w->next_block + 1) % w->block_count;
	}
}

// --- merge all workers into one snapshot -----------------------------------

bool AfPacketEngine::collect(uint64_t now_ns, WindowSnapshot &out)
{
	double start = static_cast<double>(mono_ns()) * 1e-3;
	out = WindowSnapshot{};
	out.seq = seq_++;
	out.t_mono = static_cast<double>(now_ns) * 1e-9;

	// counters + sizes: sum across workers, report deltas
	std::array<uint64_t, XDPT_C__MAX> ctot{};
	std::array<uint64_t, XDPT_SIZE_BUCKETS> stot{};
	for (auto &w : workers_) {
		for (size_t i = 0; i < XDPT_C__MAX; i++) ctot[i] += w->agg.counters[i];
		for (size_t i = 0; i < XDPT_SIZE_BUCKETS; i++) stot[i] += w->agg.sizes[i];
	}
	for (size_t i = 0; i < XDPT_C__MAX; i++) {
		out.total[i] = ctot[i];
		out.delta[i] = first_ ? 0 : ctot[i] - prev_counters_[i];
		prev_counters_[i] = ctot[i];
	}
	for (size_t i = 0; i < XDPT_SIZE_BUCKETS; i++) {
		out.size_delta[i] = first_ ? 0 : stot[i] - prev_sizes_[i];
		prev_sizes_[i] = stot[i];
	}

	// flows: merge by summing. Reading worker maps without a lock is a benign
	// race (a few counts may be mid-update); acceptable for a monitor, and the
	// hot path stays lock-free, which is the whole point of the baseline.
	std::unordered_map<flow_key, flow_stats, AfAggregate::FlowKeyHash, AfAggregate::FlowKeyEq> merged;
	for (auto &w : workers_) {
		for (const auto &[k, fs] : w->agg.flows) {
			auto [it, isnew] = merged.emplace(k, fs);
			if (!isnew) {
				flow_stats &d = it->second;
				d.pkts += fs.pkts; d.bytes += fs.bytes;
				d.syn += fs.syn; d.rst += fs.rst;
				d.flags_seen |= fs.flags_seen;
				if (fs.min_len < d.min_len) d.min_len = fs.min_len;
				if (fs.max_len > d.max_len) d.max_len = fs.max_len;
				if (fs.first_ns < d.first_ns) d.first_ns = fs.first_ns;
				if (fs.last_ns > d.last_ns) d.last_ns = fs.last_ns;
			}
		}
	}
	out.active_flows = merged.size();
	for (const auto &[k, fs] : merged) {
		if (out.flows.size() >= cfg_.max_flows_reported) break;
		out.flows.push_back({k, fs});
	}

	// srcs: the window that just closed, merged across workers
	uint64_t closed = now_ns / cfg_.window_ns;
	if (closed > 0) {
		uint64_t want = closed - 1;
		std::unordered_map<uint32_t, SrcSummary> acc;
		for (auto &w : workers_) {
			for (const auto &[ip, win] : w->agg.srcs) {
				const src_slot &s = win.slot[want & 1];
				if (s.epoch != want || s.pkts == 0) continue;
				SrcSummary &ss = acc[ip];
				ss.saddr = ip; ss.epoch = want;
				ss.pkts += s.pkts; ss.bytes += s.bytes;
				ss.syn += s.syn; ss.rst += s.rst; ss.bad_flags += s.bad_flags;
				// OR sketches across workers, then popcount once at the end
			}
		}
		// second pass for sketch popcounts (OR of per-worker bitmaps)
		for (auto &[ip, ss] : acc) {
			uint64_t pbm[XDPT_PORT_BM_WORDS] = {0};
			uint64_t ibm[XDPT_IP_BM_WORDS] = {0};
			for (auto &w : workers_) {
				auto it = w->agg.srcs.find(ip);
				if (it == w->agg.srcs.end()) continue;
				const src_slot &s = it->second.slot[want & 1];
				if (s.epoch != want) continue;
				for (int j = 0; j < XDPT_PORT_BM_WORDS; j++) pbm[j] |= s.port_bm[j];
				for (int j = 0; j < XDPT_IP_BM_WORDS; j++)   ibm[j] |= s.ip_bm[j];
			}
			for (uint64_t x : pbm) ss.port_bits += __builtin_popcountll(x);
			for (uint64_t x : ibm) ss.ip_bits += __builtin_popcountll(x);
			out.srcs.push_back(ss);
		}
	}

	// Ring-overflow drops: the kernel counted frames it could not queue
	// because the ring was full. This is the baseline's loss metric under load.
	for (auto &w : workers_) {
		tpacket_stats_v3 st{};
		socklen_t len = sizeof st;
		if (getsockopt(w->fd, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0)
			out.drops += st.tp_drops; // PACKET_STATISTICS resets on read, so accumulate
	}

	out.dt = first_ ? 0 : out.t_mono - t_prev_;
	t_prev_ = out.t_mono;
	first_ = false;
	out.collect_us = static_cast<double>(mono_ns()) * 1e-3 - start;
	return true;
}

} // namespace xdpt
