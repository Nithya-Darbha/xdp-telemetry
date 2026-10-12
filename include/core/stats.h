// Statistical primitives over a WindowSnapshot. Pure and header-only so they
// are trivial to unit-test and reusable by both engines and the detector.
#ifndef XDPT_CORE_STATS_H
#define XDPT_CORE_STATS_H

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <vector>

#include "core/snapshot.h"
#include "shared/types.h"

namespace xdpt {

// Linear counting: estimate the number of distinct items hashed into an
// m-bit sketch from the number of bits still zero.
//   n_hat = -m * ln(zeros / m)
// Unbiased well past m distinct items; blows up as zeros -> 0. We clamp the
// zero count to >= 0.5 so a full sketch returns a finite floor instead of inf,
// and report saturation separately so callers can treat it as ">= floor".
struct DistinctEstimate {
	double value = 0;
	bool saturated = false;
};

inline DistinctEstimate linear_count(uint32_t set_bits, uint32_t total_bits)
{
	DistinctEstimate e;
	if (total_bits == 0)
		return e;
	double zeros = static_cast<double>(total_bits) - static_cast<double>(set_bits);
	if (zeros <= 0.5) {
		zeros = 0.5;
		e.saturated = true;
	}
	e.value = -static_cast<double>(total_bits) *
		  std::log(zeros / static_cast<double>(total_bits));
	e.value += 0.0; // normalize -0.0 (set_bits==0) to +0.0 for display
	return e;
}

// Exponentially weighted mean and variance, the baseline a rate is compared
// against. alpha in (0,1]: higher forgets faster. Welford-style EWMA so the
// variance tracks the same window the mean does.
class Ewma {
public:
	explicit Ewma(double alpha = 0.3) : alpha_(alpha) {}

	void update(double x)
	{
		if (!primed_) {
			mean_ = x;
			var_ = 0;
			primed_ = true;
			return;
		}
		double diff = x - mean_;
		double incr = alpha_ * diff;
		mean_ += incr;
		// EW variance (West 1979): var = (1-alpha)(var + alpha*diff^2)
		var_ = (1 - alpha_) * (var_ + alpha_ * diff * diff);
	}

	bool primed() const { return primed_; }
	double mean() const { return mean_; }
	double variance() const { return var_; }
	double stddev() const { return std::sqrt(var_); }

	// How many standard deviations x sits above the mean. Guards against a
	// zero/near-zero stddev with an absolute floor so a dead-quiet baseline
	// does not make every packet look like a 1e9-sigma event.
	double zscore(double x, double floor_sd = 1.0) const
	{
		double sd = std::max(stddev(), floor_sd);
		return (x - mean_) / sd;
	}

private:
	double alpha_;
	double mean_ = 0;
	double var_ = 0;
	bool primed_ = false;
};

// Percentile of a frame-size histogram. p in [0,1]. Returns the upper edge of
// the bucket the p-th packet falls in; the last bucket is open-ended so it
// reports its lower edge.
inline uint32_t size_percentile(const std::array<uint64_t, XDPT_SIZE_BUCKETS> &h, double p)
{
	uint64_t total = 0;
	for (uint64_t c : h)
		total += c;
	if (total == 0)
		return 0;
	uint64_t target = static_cast<uint64_t>(std::ceil(p * static_cast<double>(total)));
	if (target == 0)
		target = 1;
	uint64_t cum = 0;
	for (uint32_t b = 0; b < XDPT_SIZE_BUCKETS; b++) {
		cum += h[b];
		if (cum >= target) {
			if (b == XDPT_SIZE_BUCKETS - 1)
				return b * XDPT_SIZE_BUCKET; // open-ended last bucket
			return (b + 1) * XDPT_SIZE_BUCKET;
		}
	}
	return XDPT_SIZE_BUCKETS * XDPT_SIZE_BUCKET;
}

// Top-k flows by a scalar extracted from flow_stats, largest first. Uses
// nth_element + partial sort so it stays O(n) in the common case.
template <typename KeyFn>
inline std::vector<FlowSummary> top_k_flows(const std::vector<FlowSummary> &flows,
					    size_t k, KeyFn key)
{
	std::vector<FlowSummary> v = flows;
	if (v.size() > k) {
		std::nth_element(v.begin(), v.begin() + k, v.end(),
			[&](const FlowSummary &a, const FlowSummary &b) { return key(a) > key(b); });
		v.resize(k);
	}
	std::sort(v.begin(), v.end(),
		[&](const FlowSummary &a, const FlowSummary &b) { return key(a) > key(b); });
	return v;
}

} // namespace xdpt

#endif // XDPT_CORE_STATS_H
