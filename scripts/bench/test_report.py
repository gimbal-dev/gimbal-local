#!/usr/bin/env python3
"""test_report.py — unit test for report.py's aggregation (M32.2).

The end-to-end benchmark cannot run in CI (it needs Docker Desktop and a
Docker-capable gimbal snapshot), so this tests the one piece of pure logic the
harness owns: turning trial JSON into mean/stddev, excluding failed trials. The
numbers here are SYNTHETIC fixtures chosen to make the math checkable by hand —
they are not benchmark results.

    python3 scripts/bench/test_report.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report  # noqa: E402


def _approx(a, b, eps=1e-6):
    return abs(a - b) <= eps


def test_mean_std():
    mean, std = report._mean_std([2.0, 4.0, 6.0])
    assert _approx(mean, 4.0), mean
    assert _approx(std, 2.0), std  # stdev of {2,4,6} is exactly 2.0
    # A single sample has zero stddev, not an error.
    mean, std = report._mean_std([5.0])
    assert _approx(mean, 5.0) and _approx(std, 0.0)
    # Empty -> (None, None), not a crash.
    assert report._mean_std([]) == (None, None)


def test_load_excludes_failed_trials(tmp_path):
    doc = tmp_path / "r.json"
    doc.write_text(
        '{"runtime":"docker","workload":"redis","trials":['
        '{"wall_s":10.0,"ok":1},'
        '{"wall_s":20.0,"ok":1},'
        '{"wall_s":999.0,"ok":0}]}'  # a failed trial must be excluded
    )
    r = report.load(str(doc))
    assert r["n_total"] == 3
    assert r["n_ok"] == 2
    mean, _ = r["metrics"]["wall_s"]
    assert _approx(mean, 15.0), mean  # (10+20)/2, the ok=0 trial ignored


def _run():
    # Minimal runner so this works without pytest installed.
    import tempfile

    test_mean_std()
    with tempfile.TemporaryDirectory() as d:
        test_load_excludes_failed_trials(Path(d))
    print("test_report.py: all assertions passed")


if __name__ == "__main__":
    _run()
