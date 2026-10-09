#!/usr/bin/env bash
# Checks that this machine can build and run the XDP telemetry engine.
# Usage: scripts/check_env.sh
set -u

ok=0; warn=0; bad=0
pass() { printf '  [ok]   %s\n' "$1"; ok=$((ok+1)); }
note() { printf '  [warn] %s\n' "$1"; warn=$((warn+1)); }
fail() { printf '  [FAIL] %s\n' "$1"; bad=$((bad+1)); }

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

echo "kernel"
kv=$(uname -r | grep -oE '^[0-9]+\.[0-9]+')
if ver_ge "$kv" "5.15"; then pass "kernel $(uname -r) >= 5.15"
else fail "kernel $(uname -r) < 5.15 (need bounded loops 5.3, ringbuf 5.8, BPF atomics 5.12)"; fi
[ -r /sys/kernel/btf/vmlinux ] && pass "BTF at /sys/kernel/btf/vmlinux" \
  || note "no kernel BTF (fine for XDP, we don't use CO-RE)"

echo "toolchain"
if command -v clang >/dev/null; then
  cv=$(clang -dumpversion | cut -d. -f1)
  if [ "$cv" -ge 14 ]; then pass "clang $cv"; else fail "clang $cv < 14"; fi
  echo 'int x;' | clang -target bpf -x c -c - -o /dev/null 2>/dev/null \
    && pass "clang can emit BPF" || fail "clang has no BPF backend"
else fail "clang missing (apt install clang llvm)"; fi
command -v cmake >/dev/null && pass "cmake $(cmake --version | head -n1 | awk '{print $3}')" \
  || fail "cmake missing"
if pkg-config --exists libbpf 2>/dev/null; then
  lv=$(pkg-config --modversion libbpf)
  ver_ge "$lv" "1.0" && pass "libbpf $lv" || fail "libbpf $lv < 1.0"
else fail "libbpf missing (apt install libbpf-dev)"; fi

# Ubuntu's /usr/sbin/bpftool is a wrapper that refuses to run on kernels
# without a matching linux-tools package. Find a real binary.
bt=""
for c in "${BPFTOOL:-}" $(command -v bpftool 2>/dev/null) /usr/lib/linux-tools/*/bpftool; do
  [ -n "$c" ] && [ -x "$c" ] && "$c" version >/dev/null 2>&1 && { bt=$c; break; }
done
[ -n "$bt" ] && pass "bpftool: $bt" \
  || fail "no working bpftool (apt install linux-tools-generic, or build from github.com/libbpf/bpftool)"

echo "runtime"
[ "$(id -u)" -eq 0 ] && pass "running as root" \
  || note "not root: loading XDP needs root or CAP_BPF + CAP_NET_ADMIN"
command -v ip >/dev/null && pass "iproute2" || fail "ip missing (apt install iproute2)"
command -v ethtool >/dev/null && pass "ethtool" \
  || note "ethtool missing: netns.sh can't disable GRO/GSO/TSO (apt install ethtool)"
if grep -q '^flags.*hypervisor' /proc/cpuinfo 2>/dev/null; then
  note "running in a VM: pin vCPUs and expect noisier benchmarks"
fi

echo
echo "ok=$ok warn=$warn fail=$bad"
[ "$bad" -eq 0 ]
