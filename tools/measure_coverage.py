#!/usr/bin/env python3
"""Measure normalisation coverage on the public corpora, one category at a time.

Runs the release binary over each dataset fetched by tools/fetch_datasets.py
and prints the table in docs/DATASETS.md. Every number is produced here; none
is copied from a vendor benchmark.

    cargo build --release --locked
    python tools/measure_coverage.py
"""

import argparse
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
        print(f"{category:<10} {label:<32} {events:>9,} {parsed:>9,} {pct:>9.4f}%")

    print("-" * 74)
    if total_events:
        pct = 100.0 * total_parsed / total_events
        print(f"{'TOTAL':<43} {total_events:>9,} {total_parsed:>9,} {pct:>9.4f}%")

    if missing:
        print(f"\nnot measured (absent): {', '.join(missing)}")


if __name__ == "__main__":
    main()
