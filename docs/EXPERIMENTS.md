# Experiments (phase 9)

## What is measured

For each engine at each offered load, one CSV row:

| column | meaning |
|---|---|
| `offered_pps` | target rate = `mbps * 1e6 / 8 / pktlen` |
| `proc_pps` | median per-window pps the monitor accounted for |
| `cpu_pct` | system-wide busy % during the load, from `/proc/stat` across all cores |
| `ns_per_pkt` | XDP only: `run_time_ns / run_cnt` from `bpf_stats` |
| `drops` | AF_PACKET ring-overflow drops from `PACKET_STATISTICS` |

Engines: `none` (control), `xdp` (native), `xdp-generic` (skb), `afp1`, `afp2`.

## Why these choices

**System-wide CPU, not process CPU.** XDP runs in softirq context, so its cost
never shows up in the collector process. The only honest way to see it is the
whole-system busy fraction, monitor on versus off at the same load.

**`bpf_stats` for exact XDP cost.** `kernel.bpf_stats_enabled=1` makes the
kernel accumulate run time and run count per program, so `run_time_ns/run_cnt`
is the mean nanoseconds the XDP program spends per packet, independent of the
noisy system CPU number.

**AF_PACKET drops from the kernel, not inferred.** `PACKET_STATISTICS` reports
frames the kernel could not queue because the ring was full. That is the
baseline's loss metric; comparing it to offered load shows where userspace
capture starts falling behind.

**Same offered load across engines.** The generator is identical for every
engine, so a difference in processed pps, CPU or drops is a difference in the
capture path, which is the whole question.

## Running it properly

The dev-VM run checked into the repo is illustrative (see the README caveat).
For numbers worth quoting:

1. Pin the generator and monitor to different CPUs, or use two machines.
2. On real hardware, bind XDP to the NIC in native mode and confirm with
   `bpftool net show` that it is `drv`, not `generic`.
3. Raise `LOADS_MBPS` until an engine starts dropping or its processed pps
   stops tracking offered pps. That knee is the interesting part.
4. `DUR=30` or more per point to average out noise.

## Reproducing the scan-detection result

Not a throughput test, but the functional one behind phase 7:

```sh
sudo ip netns exec xdpt-mon ./build/xdpt -i mon0 -w 1000 &
sudo ip netns exec xdpt-gen nmap -sS -p 1-2000 -T4 10.77.0.2
```

Both `xdpt` and `xdpt-afp` raise the same `port_scan`, `syn_flood` and
rate-spike alerts, with the sketch estimating ~2045 distinct ports against the
2000 real ones.
