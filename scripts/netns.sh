#!/usr/bin/env bash
# Isolated test topology. Nothing touches the root namespace's interfaces.
#
#   netns xdpt-gen              netns xdpt-mon
#   +--------------+            +--------------+
#   | gen0         |<--veth---->| mon0  <- XDP |
#   | 10.77.0.1/24 |            | 10.77.0.2/24 |
#   +--------------+            +--------------+
#
# Traffic generators run in xdpt-gen, the monitor (XDP or AF_PACKET) attaches
# to mon0 in xdpt-mon. Run the monitor with: ip netns exec xdpt-mon <cmd>
#
# Usage: sudo scripts/netns.sh up|down|status
set -euo pipefail

GEN_NS=xdpt-gen
MON_NS=xdpt-mon
GEN_IF=gen0
MON_IF=mon0
GEN_IP=10.77.0.1/24
MON_IP=10.77.0.2/24

up() {
  ip netns add "$GEN_NS"
  ip netns add "$MON_NS"
  ip link add "$GEN_IF" netns "$GEN_NS" type veth peer name "$MON_IF" netns "$MON_NS"
  ip -n "$GEN_NS" addr add "$GEN_IP" dev "$GEN_IF"
  ip -n "$MON_NS" addr add "$MON_IP" dev "$MON_IF"
  ip -n "$GEN_NS" link set lo up
  ip -n "$MON_NS" link set lo up
  ip -n "$GEN_NS" link set "$GEN_IF" up
  ip -n "$MON_NS" link set "$MON_IF" up

  # One wire packet = one XDP invocation. Without this, TSO/GSO hand veth
  # 64 KB super-packets and every per-packet number in the benchmark is wrong.
  if command -v ethtool >/dev/null; then
    for pair in "$GEN_NS:$GEN_IF" "$MON_NS:$MON_IF"; do
      ns=${pair%%:*}; dev=${pair##*:}
      ip netns exec "$ns" ethtool -K "$dev" tso off gso off gro off >/dev/null 2>&1 || true
    done
  else
    echo "warning: ethtool missing, offloads left on" >&2
  fi
  status
}

down() {
  ip netns del "$GEN_NS" 2>/dev/null || true
  ip netns del "$MON_NS" 2>/dev/null || true
  echo "removed $GEN_NS and $MON_NS"
}

status() {
  for ns in "$GEN_NS" "$MON_NS"; do
    echo "== $ns"
    ip -n "$ns" -brief addr 2>/dev/null || echo "  (missing)"
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
