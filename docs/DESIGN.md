# Design notes

Running log of decisions and why. Each phase adds to this.

## Goals

Show kernel side packet processing, telemetry and detection, and measure it
honestly against a strong userspace baseline. Not a sniffer: no payload
capture, no pcap writing, fixed memory per flow.

## Decisions locked in phase 1

**One parser, two engines.** `bpf/parse.h` is written in verifier-safe style
(`data` / `data_end` pointers, explicit bounds checks) and compiled into both
the XDP program and the AF_PACKET baseline. Detection lives in a shared
library that both engines feed with the same snapshot type. The comparison
then measures the capture path, not two different implementations.

**Strong baseline.** AF_PACKET uses a TPACKET_V3 mmap ring with PACKET_FANOUT
across threads. A `recvfrom` loop may be plotted as a third series, never as
the only baseline.

**System-wide CPU accounting.** XDP runs in softirq context, so its cost never
appears in the collector process. CPU cost is measured from `/proc/stat`
deltas across all cores, monitor on versus off at the same offered load.
Per-packet BPF cost comes from `kernel.bpf_stats_enabled=1`
(`run_time_ns / run_cnt` in `bpftool prog show`).

**Honest veth caveat.** Native XDP on veth still receives skbs that the
sending namespace already allocated, so the "process before skb allocation"
advantage of XDP on a real NIC driver does not exist here. Results show
relative cost on veth only. Real NIC runs (i40e, ice, mlx5) are a stretch goal.

## Test topology

`scripts/netns.sh up` creates two namespaces joined by one veth pair:
generators in `xdpt-gen`, monitor on `mon0` in `xdpt-mon`. GRO, GSO and TSO
are disabled on both ends so one wire packet equals one XDP invocation.

XDP is ingress only. The monitor sees generator to target traffic. Target
replies (SYN-ACK, RST from closed ports) leave `mon0` as egress and are
invisible to XDP. Detectors in the MVP use attacker-side signals only.

## Verifier rules this codebase follows

* Every packet read is preceded by a check of the exact pointer being read
  against `data_end`.
* Variable header lengths (`ihl * 4`, `doff * 4`) come from 4-bit fields, so
  their range is provably small. After advancing by them, bounds are checked
  again on the new pointer.
* Lengths taken from packet contents (`tot_len`, UDP `len`) are compared as
  plain integers against the frame length, never added to a packet pointer.
  A packet pointer plus a value up to 65535 can exceed the verifier's maximum
  packet offset and gets rejected.
* Loops are bounded by a compile-time constant (VLAN depth max 2).
* Helpers are `static inline __attribute__((always_inline))`.
* Map lookups are null checked before use.
* Map keys have explicit padding fields and are zeroed before use, because
  hash maps compare keys as raw bytes.

## Build pipeline (phase 2)

`clang -target bpf` compiles `bpf/*.bpf.c` to an ELF object, `bpftool gen
skeleton` turns it into a header with typed accessors for programs and maps,
and the C++ collector includes that header. No runtime path to a `.o` file,
no string lookups of map names.

The collector attaches through a `bpf_link` instead of `bpf_xdp_attach()`.
The link belongs to the process, so a crash detaches the program instead of
leaving it on the interface with nobody reading its maps.

Shared structs in `include/shared/types.h` use fixed-width types, explicit
padding and size assertions, so the BPF and C++ compilers cannot silently
disagree on layout.

## Parser (phase 3)

`bpf/parse.h` returns one `enum xdpt_parse` per frame: three normal outcomes
(IPv4, IPv6 seen but not parsed, non-IP) and twelve malformed reasons. The
XDP program counts each outcome in a per-CPU array, no atomics needed.

**Two kinds of checks.** Pointer checks against `data_end` are for the
verifier. Integer checks of `tot_len`, `doff` and UDP `len` against the frame
length are for protocol sanity. Once the `tot_len` check passes, the TCP
pointer check can never fail, but the verifier does not derive pointer bounds
from integer comparisons, so it stays. Proof: deleting it still passes every
unit test, and the verifier rejects the program with
`invalid access to packet, off=34 size=2 ... R3 offset is outside of the packet`.

**Frame length.** `data_end - data` is pointer minus pointer, which the
verifier only accepts from privileged loaders (root, or CAP_BPF plus
CAP_PERFMON). Fine for a monitor that needs root to attach anyway.

**Fragments.** Non-first fragments carry no L4 header: `proto` is set,
`l4_valid` is 0, ports are 0. The first fragment (MF set, offset 0) is parsed
normally. Both are flagged `is_frag`.

**ICMP** uses a local 8-byte header struct because `linux/icmp.h` pulls in
glibc headers that break the `-target bpf` build.

**Alignment.** After a 14-byte Ethernet header, IP is only 2-byte aligned.
Fine on x86, and the verifier only enforces strict alignment on
architectures without efficient unaligned access. Unit tests place frames at
a 2-byte offset (like NET_IP_ALIGN) so UBSan's alignment check stays on and
stays meaningful. The AF_PACKET baseline must handle this too (phase 8).

**What tests cannot reach.** The kernel refuses to transmit frames shorter
than 14 bytes, so `eth_trunc` is only testable with `BPF_PROG_TEST_RUN`
(phase 10). Everything else was checked live through XDP on `mon0`.
