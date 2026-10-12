# xdp-telemetry

Real-time network telemetry and anomaly detection with eBPF/XDP, benchmarked
against an AF_PACKET userspace baseline in isolated network namespaces.

Work in progress. Built phase by phase; the commit history shows each step.

## Progress

- [x] 1. Environment checks, test topology, design decisions
- [x] 2. Repository layout and BPF build pipeline
- [x] 3. Verifier-safe packet parser
- [x] 4. BPF maps (flows, fan-out, histograms, events)
- [x] 5. Userspace collector
- [x] 6. Flow and statistical logic
- [x] 7. Anomaly detection
- [ ] 8. AF_PACKET baseline
- [ ] 9. Controlled experiments
- [ ] 10. Tests and malformed packet validation
- [ ] 11. Benchmark results

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
ctest --test-dir build                                # parser unit tests (ASan/UBSan)
```

Sample output with a flood ping and a burst of crafted malformed frames:

```
attached to mon0 (ifindex 2) in native mode, prog id 39
pps=        60  Mbit/s=    0.03  tcp=10 udp=0 icmp=0 other=0 frag=0 ipv6=0 non_ip=0 malformed=50
    malformed: vlan_depth=10 ip_version=10 ip_ihl=10 ip_totlen=20
```

If cmake can't find bpftool, pass `-DBPFTOOL=/path/to/bpftool`.

## Layout

```
bpf/              XDP program (C, compiled with clang -target bpf)
include/shared/   structs shared by BPF and userspace
core/ (headers)   WindowSnapshot + stats + report (engine-independent)
src/core/         report builder (links into xdpt and tests)
src/collector/    skeleton loader + map/ringbuf reader (C++20)
tests/            parser unit tests
scripts/          environment check, netns topology
docs/             design notes
```

See [docs/DESIGN.md](docs/DESIGN.md) for design decisions.
