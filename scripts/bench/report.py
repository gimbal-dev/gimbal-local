#!/usr/bin/env python3
"""report.py — aggregate M32.2 benchmark result JSON files into a markdown report.

Reads one or more results files written by run-docker.sh / run-gimbal.sh and
prints a comparison table: mean +/- stddev per metric per runtime, over the
successful (ok=1) trials, plus a gimbal/docker ratio when both are present.

    ./report.py results/docker-redis.json results/gimbal-redis.json

It computes nothing it was not given: only real trial values are aggregated, and
failed trials (ok=0) are excluded and counted separately. No numbers are
invented.
"""

import json
import statistics
import sys
from pathlib import Path


def _mean_std(values):
    """Return (mean, stddev) for a list of floats; stddev is 0 for <2 samples."""
    if not values:
        return None, None
    mean = statistics.fmean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    return mean, std


def load(path):
    doc = json.loads(Path(path).read_text())
    trials = doc.get("trials", [])
    ok = [t for t in trials if t.get("ok") == 1]
    metrics = {}
    for key in ("wall_s", "cold_start_s", "host_envelope_s"):
        vals = [float(t[key]) for t in ok if key in t and t[key] is not None]
        if vals:
            metrics[key] = _mean_std(vals)
    return {
        "runtime": doc.get("runtime", "?"),
        "workload": doc.get("workload", "?"),
        "n_ok": len(ok),
        "n_total": len(trials),
        "metrics": metrics,
    }


def fmt(pair):
    if not pair or pair[0] is None:
        return "-"
    mean, std = pair
    return f"{mean:.2f} +/- {std:.2f}"


METRIC_LABELS = {
    "wall_s": "In-guest/container build (s)",
    "cold_start_s": "Cold start (s)",
    "host_envelope_s": "Host envelope: rehydrate+build+teardown (s)",
}


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    reports = [load(p) for p in argv]
    workloads = {r["workload"] for r in reports}
    workload = ", ".join(sorted(workloads))

    print(f"# Build benchmark: gimbal microVM vs Docker ({workload})\n")
    print("Mean +/- stddev over successful trials. Wall = pure build time inside "
          "the runtime (directly comparable). See scripts/bench/README.md for "
          "methodology and the honest expectation band.\n")

    # Header row: one column per runtime.
    header = "| Metric | " + " | ".join(f"{r['runtime']} (n={r['n_ok']}/{r['n_total']})" for r in reports) + " |"
    sep = "| --- | " + " | ".join("---" for _ in reports) + " |"
    print(header)
    print(sep)

    all_metrics = []
    for key in ("wall_s", "cold_start_s", "host_envelope_s"):
        if any(key in r["metrics"] for r in reports):
            all_metrics.append(key)

    for key in all_metrics:
        cells = [fmt(r["metrics"].get(key)) for r in reports]
        print(f"| {METRIC_LABELS.get(key, key)} | " + " | ".join(cells) + " |")

    # Ratio, when exactly one gimbal and one docker report expose wall_s.
    by_runtime = {r["runtime"]: r for r in reports}
    g, d = by_runtime.get("gimbal"), by_runtime.get("docker")
    if g and d and "wall_s" in g["metrics"] and "wall_s" in d["metrics"]:
        gmean = g["metrics"]["wall_s"][0]
        dmean = d["metrics"]["wall_s"][0]
        if dmean > 0:
            ratio = gmean / dmean
            pct = (ratio - 1.0) * 100.0
            faster = "slower" if ratio > 1 else "faster"
            print(f"\n**Build wall-clock:** gimbal is {ratio:.2f}x Docker "
                  f"({abs(pct):.1f}% {faster}). Prior art for microVMs is "
                  f"~92-97% of Docker CPU-bound build throughput (i.e. ~1.03-1.09x).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
