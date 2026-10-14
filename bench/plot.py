#!/usr/bin/env python3
"""Plot bench/results.csv. Usage: python3 bench/plot.py [results.csv]

Produces, next to the CSV:
  pps.png        processed pps vs offered pps, one line per engine
  ns_per_pkt.png XDP per-packet cost (bpf_stats) vs offered load

No seaborn, no styling tricks; just readable matplotlib.
"""
import csv
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

path = sys.argv[1] if len(sys.argv) > 1 else "bench/results.csv"
rows = list(csv.DictReader(open(path)))

def series(engine, x, y):
    xs, ys = [], []
    for r in rows:
        if r["engine"] != engine:
            continue
        try:
            xv, yv = float(r[x]), float(r[y])
        except ValueError:
            continue
        xs.append(xv)
        ys.append(yv)
    return xs, ys

engines = [e for e in ["xdp", "xdp-generic", "afp1", "afp2"]
           if any(r["engine"] == e for r in rows)]

# --- processed vs offered pps ---------------------------------------------
plt.figure(figsize=(7, 4.5))
lim = max((float(r["offered_pps"]) for r in rows), default=1)
plt.plot([0, lim], [0, lim], "k--", lw=1, label="ideal (no loss)")
for e in engines:
    xs, ys = series(e, "offered_pps", "proc_pps")
    plt.plot(xs, ys, "o-", label=e)
plt.xlabel("offered pps")
plt.ylabel("processed pps")
plt.title("Packets processed vs offered")
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
out = path.rsplit("/", 1)[0] if "/" in path else "."
plt.savefig(f"{out}/pps.png", dpi=120)

# --- XDP per-packet cost ---------------------------------------------------
plt.figure(figsize=(7, 4.5))
drew = False
for e in ("xdp", "xdp-generic"):
    xs, ys = series(e, "offered_pps", "ns_per_pkt")
    if ys:
        plt.plot(xs, ys, "o-", label=e)
        drew = True
if drew:
    plt.xlabel("offered pps")
    plt.ylabel("ns per packet (bpf_stats)")
    plt.title("XDP program cost per packet")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{out}/ns_per_pkt.png", dpi=120)

print(f"wrote {out}/pps.png" + (f" and {out}/ns_per_pkt.png" if drew else ""))
