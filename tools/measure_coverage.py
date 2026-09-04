#!/usr/bin/env python3
"""Measure normalisation coverage on the public corpora, one category at a time.

Runs the release binary over each dataset fetched by tools/fetch_datasets.py
and prints the table in docs/DATASETS.md. Every number is produced here; none
is copied from a vendor benchmark.

    cargo build --release --locked
    python tools/measure_coverage.py
"""

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

# (category, source file, label used in the report)
CORPORA = [
    ("firewall", "iptables.log", "iptables (Honeynet SotM34)"),
    ("IDS", "snort.log", "Snort (Honeynet SotM34)"),
    ("IDS", "dragon-nids.log", "Enterasys Dragon (Honeynet)"),
    ("web", "apache-access.log", "Apache access (Honeynet)"),
    ("web", "Apache_2k.log", "Apache error (Loghub)"),
    ("auth", "OpenSSH_2k.log", "OpenSSH (Loghub)"),
    ("host", "linux-messages.log", "Linux syslog (Honeynet)"),
    ("host", "Linux_2k.log", "Linux (Loghub)"),
    ("mail", "sendmail.log", "Sendmail MTA (Honeynet)"),
    ("proxy", "Proxifier_2k.log", "Proxifier (Loghub)"),
]

RECEIVED = re.compile(r"received\s+(\d+)")
PARSED = re.compile(r"parsed\s+(\d+)")


def binary() -> pathlib.Path:
    for name in ("ulpf.exe", "ulpf"):
        path = pathlib.Path("target/release") / name
        if path.exists():
            return path
    print("build first:  cargo build --release --locked", file=sys.stderr)
    raise SystemExit(1)


def measure(exe: pathlib.Path, packs: str, corpus: pathlib.Path) -> tuple[int, int]:
    """Run one corpus through the pipeline and return (received, parsed)."""
    work = pathlib.Path(tempfile.mkdtemp(prefix="ulpf-cov-"))
    try:
        result = subprocess.run(
            [
                str(exe), "run",
                "--packs", packs,
                "--vault", str(work / "vault"),
                "--integrity-dir", str(work / "integrity"),
                "--input", str(corpus),
                "--output", "nul" if sys.platform == "win32" else "/dev/null",
            ],
            capture_output=True,
            text=True,
            timeout=1800,
        )
        # The run summary is written to stderr.
        text = result.stderr + result.stdout
        received = RECEIVED.search(text)
        parsed = PARSED.search(text)
        if not received or not parsed:
            return 0, 0
        return int(received.group(1)), int(parsed.group(1))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="../realdata")
    parser.add_argument("--packs", default="packs")
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare against the recorded baseline and exit non-zero on a drop",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="record the measured figures as the new baseline",
    )
    parser.add_argument("--baseline", default="tools/coverage_baseline.json")
    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.05,
        help="percentage points a corpus may drop before it counts as a regression",
    )
    args = parser.parse_args()

    exe = binary()
    data = pathlib.Path(args.data)
    if not data.exists():
        print(f"{data} not found. Run: python tools/fetch_datasets.py", file=sys.stderr)
        raise SystemExit(1)

    print(f"{'CATEGORY':<10} {'SOURCE':<32} {'EVENTS':>9} {'PARSED':>9} {'COVERAGE':>10}")
    print("-" * 74)

    total_events = 0
    total_parsed = 0
    missing = []
    measured = {}

    for category, filename, label in CORPORA:
        corpus = data / filename
        if not corpus.exists():
            missing.append(filename)
            continue
        events, parsed = measure(exe, args.packs, corpus)
        if events == 0:
            missing.append(filename)
            continue
        total_events += events
        total_parsed += parsed
        pct = 100.0 * parsed / events
        measured[filename] = pct
        print(f"{category:<10} {label:<32} {events:>9,} {parsed:>9,} {pct:>9.4f}%")

    print("-" * 74)
    if total_events:
        pct = 100.0 * total_parsed / total_events
        print(f"{'TOTAL':<43} {total_events:>9,} {total_parsed:>9,} {pct:>9.4f}%")

    if missing:
        print(f"\nnot measured (absent): {', '.join(missing)}")

    total_pct = 100.0 * total_parsed / total_events if total_events else 0.0

    if args.write_baseline:
        write_baseline(pathlib.Path(args.baseline), measured, total_pct)
        return

    if args.check:
        # A partial run must not pass: a missing corpus is exactly how a broken
        # pack would hide from the check that exists to catch it.
        if missing:
            print(
                f"refusing to check with {len(missing)} corpus/corpora absent",
                file=sys.stderr,
            )
            raise SystemExit(1)
        raise SystemExit(
            check_baseline(
                pathlib.Path(args.baseline), measured, total_pct, args.tolerance
            )
        )


def write_baseline(path, measured, total_pct):
    """Record what the packs achieve today, so a later drop is visible."""
    payload = {
        "note": "Regenerate with: python tools/measure_coverage.py --write-baseline",
        "total": round(total_pct, 4),
        "per_corpus": {k: round(v, 4) for k, v in sorted(measured.items())},
    }
    path.write_text(json.dumps(payload, indent=2) + chr(10), encoding="utf-8")
    print(f"baseline written to {path}")


def check_baseline(path, measured, total_pct, tolerance):
    """Fail when any corpus, or the total, drops below what was recorded.

    Coverage is a ratio over a fixed corpus, so it reproduces to the digit.
    The tolerance is there for floating-point noise, not for genuine drift:
    anything larger is a real change and deserves a human looking at it.
    """
    if not path.exists():
        print(
            f"no baseline at {path}; create one with --write-baseline once the "
            "figures are known good",
            file=sys.stderr,
        )
        return 1

    baseline = json.loads(path.read_text(encoding="utf-8"))
    per_corpus = baseline.get("per_corpus", {})
    was_total = baseline.get("total", 0.0)
    failures = []

    for name, was in sorted(per_corpus.items()):
        now = measured.get(name)
        if now is None:
            failures.append(f"{name}: in the baseline but not measured")
        elif now < was - tolerance:
            failures.append(
                f"{name}: {was:.4f}% -> {now:.4f}% ({was - now:.4f} points lost)"
            )

    if total_pct < was_total - tolerance:
        failures.append(f"TOTAL: {was_total:.4f}% -> {total_pct:.4f}%")

    print()
    if failures:
        print("COVERAGE REGRESSION")
        for line in failures:
            print(f"  {line}")
        print()
        print("If the drop is intended, re-record it with --write-baseline")
        return 1

    print(f"No regression. Total {total_pct:.4f}%, baseline {was_total:.4f}%.")
    new_corpora = sorted(set(measured) - set(per_corpus))
    if new_corpora:
        print(f"Not yet in the baseline: {', '.join(new_corpora)}")
    return 0


if __name__ == "__main__":
    main()
