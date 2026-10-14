# xdp-telemetry

Real-time network telemetry and anomaly detection with eBPF/XDP, benchmarked
against an AF_PACKET userspace baseline in isolated network namespaces.


## Requirements

Linux 5.15+, clang 14+, libbpf 1.0+, bpftool, cmake, iproute2, ethtool, root.

```sh
sudo apt install clang llvm libbpf-dev linux-tools-generic cmake iproute2 ethtool
scripts/check_env.sh
```

## Test topology

```sh
sudo scripts/netns.sh up      # xdpt-gen:gen0 <-> xdpt-mon:mon0
sudo scripts/netns.sh down
```

## Build and run

```sh
cmake -S . -B build && cmake --build build -j
sudo scripts/netns.sh up
sudo ip netns exec xdpt-mon ./build/xdpt -i mon0     # Ctrl-C detaches
ctest --test-dir build                                # unit tests (ASan/UBSan)

# AF_PACKET baseline, same detection, benchmarked against xdpt (see Experiments below)
sudo ip netns exec xdpt-mon ./build/xdpt-afp -i mon0 -t 2
```

Live output while an `nmap -sS` scan of 2000 ports hits the monitored host:

```
attached to mon0 (ifindex 2) in native mode, window 1000ms
w=14   pps=     1999 Mbit/s=   0.93 tcp=2000 udp=0 icmp=0 syn=2000 rst=0 p50=64 p99=64 flows=2000 srcs=1 ev=0 malf=0 collect=287us
    src 10.77.0.1       pkts=2000 ports~2045 ips~1 syn=2000 bad_flags=0
  ALERT [crit] port_scan      10.77.0.1       ~2045 distinct dst ports (>= 100)
  ALERT [crit] syn_flood      10.77.0.1       2000 half-open SYNs (>= 200)
```

If cmake can't find bpftool, pass `-DBPFTOOL=/path/to/bpftool`.

## Layout

```
bpf/              XDP program (C, compiled with clang -target bpf)
include/shared/   structs shared by BPF and userspace
core/ (headers)   WindowSnapshot + stats + report (engine-independent)
src/core/         report builder (links into xdpt and tests)
src/collector/    skeleton loader + map/ringbuf reader (C++20)
src/afpacket/     AF_PACKET baseline (TPACKET_V3 + fanout), same core
tests/            parser, stats, detection + BPF_PROG_TEST_RUN
scripts/          environment check, netns topology
bench/            experiment runner, plots, results
docs/             design notes
```


## Experiments and results

`bench/run_bench.sh` drives a fixed offered load (iperf3 UDP) through `mon0` and
measures each capture engine at matching load: XDP native, XDP generic, and the
AF_PACKET baseline with 1 and 2 fanout threads, against a no-monitor control.
`bench/plot.py` renders the CSV.

```sh
sudo scripts/netns.sh up
sudo DUR=15 LOADS_MBPS="200 500 1000 2000" bench/run_bench.sh bench/results.csv
python3 bench/plot.py bench/results.csv      # -> bench/pps.png, bench/ns_per_pkt.png
```

Metrics: processed pps (the monitor's own windows), system CPU during the load,
XDP per-packet cost from `bpf_stats` (`run_time_ns/run_cnt`), and AF_PACKET
ring-overflow drops from `PACKET_STATISTICS`.

`bench/results.csv` was measured in a privileged container on an ARM64 Linux
kernel (OrbStack, 7.0.14), XDP attached in native mode on veth:

* **XDP program cost ~52 ns/packet**, stable from 125k to 625k pps. Generic
  (skb) mode runs 80-127 ns/packet, so native is ~35-60% cheaper per packet.
* Both XDP and the AF_PACKET baseline processed 100% of offered traffic up to
  625k pps with **zero drops**, and sustained ~1 Mpps at the generator ceiling.
* System CPU stayed low (10-20%) and the gap between engines was within noise.

Honest limits:
* **veth, not a real NIC.** Native XDP still receives an skb the sender already
  allocated, so XDP's "before skb allocation" advantage does not show here, and
  it has no CPU edge over AF_PACKET on veth. That needs a driver-XDP NIC
  (i40e/ice/mlx5).
* Past ~1 Mpps the UDP generator is the bottleneck, so the top-load row reflects
  the generator ceiling, not capture capacity.

See [docs/DESIGN.md](docs/DESIGN.md) and [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md).
