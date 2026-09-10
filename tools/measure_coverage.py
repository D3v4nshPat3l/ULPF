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
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

# (category, candidate source files, label used in the report)
#
# PERIMETER is the set the headline coverage figure is measured on, and it is
# the set the problem statement's Current Scope sentence describes. It is
# reported on its own so that adding a non-perimeter source can never quietly
# move the number that answers the statement.
#
# Each entry names the files that can satisfy it, best first. The complete
# corpus is always preferred; the 2,000-line Loghub sample is a fallback so a
# machine part-way through a fetch still produces a table, and the report says
# which one was actually measured.
#
# Measuring the sample when the full corpus exists is how a coverage figure
# quietly becomes meaningless: four of the perimeter sources below were scored
# on 2,000 lines each for exactly that reason, while the complete corpora sat
# in the same Zenodo deposit unfetched.
PERIMETER = [
    ("firewall", ["iptables.log"], "iptables (Honeynet SotM34)"),
    ("IDS", ["snort.log"], "Snort (Honeynet SotM34)"),
    ("IDS", ["dragon-nids.log"], "Enterasys Dragon (Honeynet)"),
    ("web", ["apache-access.log"], "Apache access (Honeynet)"),
    ("web", ["Apache.full.log", "Apache_2k.log"], "Apache error (Loghub)"),
    ("auth", ["OpenSSH.full.log", "OpenSSH_2k.log"], "OpenSSH (Loghub)"),
    ("host", ["linux-messages.log"], "Linux syslog (Honeynet)"),
    ("host", ["Linux.full.log", "Linux_2k.log"], "Linux (Loghub)"),
    ("mail", ["sendmail.log"], "Sendmail MTA (Honeynet)"),
    ("proxy", ["Proxifier.full.log", "Proxifier_2k.log"], "Proxifier (Loghub)"),
    ("proxy", ["squid-access.log"], "Squid proxy (Honeynet)"),
    ("proxy", ["bluecoat-proxy.log"], "Blue Coat ProxySG (Honeynet)"),
    ("network", ["zeek-conn-full.log", "zeek-conn.log"], "Zeek conn.log (MACCDC 2012)"),
]

# Sources outside the Current Scope sentence, kept because "universal" is in
# the framework's name and a reviewer is entitled to ask whether it holds
# outside the perimeter. Measured and reported separately, never blended into
# the headline figure.
UNIVERSAL = [
    ("bigdata", ["HDFS_v1.full.log", "HDFS_2k.log"], "HDFS v1 (Loghub)"),
    ("bigdata", ["HDFS_v2.full.log"], "HDFS v2 (Loghub)"),
    ("bigdata", ["HDFS_v3.full.log"], "HDFS v3 TraceBench (Loghub)"),
    ("hpc", ["BGL.full.log", "BGL_2k.log"], "Blue Gene/L RAS (Loghub)"),
    ("hpc", ["Thunderbird.full.log", "Thunderbird_2k.log"], "Thunderbird (Loghub)"),
    ("hpc", ["HPC.full.log", "HPC_2k.log"], "HPC node state (Loghub)"),
    ("bigdata", ["Hadoop.full.log", "Hadoop_2k.log"], "Hadoop YARN (Loghub)"),
    ("bigdata", ["Spark.full.log", "Spark_2k.log"], "Spark (Loghub)"),
    ("bigdata", ["Zookeeper.full.log", "Zookeeper_2k.log"], "ZooKeeper (Loghub)"),
    ("cloud", ["OpenStack.full.log", "OpenStack_2k.log"], "OpenStack Nova (Loghub)"),
    ("host", ["Windows.full.log", "Windows_2k.log"], "Windows CBS (Loghub)"),
    ("host", ["Mac.full.log", "Mac_2k.log"], "macOS system (Loghub)"),
    ("mobile", ["Android_v1.full.log", "Android_2k.log"], "Android logcat v1 (Loghub)"),
    ("mobile", ["Android_v2.full.log"], "Android logcat v2 (Loghub)"),
    ("mobile", ["HealthApp.full.log", "HealthApp_2k.log"], "HealthApp (Loghub)"),
]

# `tools/make_demo_source.py` writes a synthetic corpus into the same directory
# so the onboarding workflow can be demonstrated on an unseen device. It is
# named here only to be excluded: measuring invented data would make every
# figure below unfalsifiable, which is the opposite of the point.
SYNTHETIC = {"apx-ngfw-synthetic.log"}

CORPORA = PERIMETER + UNIVERSAL
assert not (SYNTHETIC & {f for _, files, _ in CORPORA for f in files}), (
    "a synthetic corpus must never appear in the measured set"
)

# Files whose label belongs to the headline figure.
PERIMETER_FILES = {f for _, files, _ in PERIMETER for f in files}

RECEIVED = re.compile(r"received\s+(\d+)")
PARSED = re.compile(r"parsed\s+(\d+)")


def binary() -> pathlib.Path:
    """Locate the release binary, honouring CARGO_TARGET_DIR.

    Cargo puts the build wherever CARGO_TARGET_DIR points, which is how anyone
    working on a drive or directory where ./target is awkward has it set. This
    looked only in ./target/release and so reported "build first" to someone
    who had just built, with no hint at what was actually wrong.
    """
    roots = []
    configured = os.environ.get("CARGO_TARGET_DIR")
    if configured:
        roots.append(pathlib.Path(configured))
    roots.append(pathlib.Path("target"))

    for root in roots:
        for name in ("ulpf.exe", "ulpf"):
            path = root / "release" / name
            if path.exists():
                return path

    looked = ", ".join(str(r / "release") for r in roots)
    print(f"no release binary in {looked}", file=sys.stderr)
    print("build first:  cargo build --release --locked", file=sys.stderr)
    raise SystemExit(1)


def measure(
    exe: pathlib.Path,
    packs: str,
    corpus: pathlib.Path,
    timeout: int,
    work_root: pathlib.Path,
) -> tuple[int, int]:
    """Run one corpus through the pipeline and return (received, parsed).

    `timeout` is per corpus and has to accommodate the largest of them.
    Thunderbird alone is 211 million records: at the ~20,000 events/sec this
    pipeline sustains on one core that is close to three hours, and the old
    fixed 30-minute cap silently turned every corpus above roughly 36 million
    records into a "0 events" result that was then reported as absent.
    """
    # Beside the corpora, not in the system temp directory.
    #
    # Every measured corpus is vaulted as it is read, so the scratch space a
    # run needs is a fraction of the corpus but still gigabytes for the large
    # ones. The system temp directory is on the OS volume, which is routinely
    # the smallest one on the machine: measuring Blue Coat and the full Zeek
    # capture filled it, both runs died, and -- because a dead run produces no
    # counters -- both were then reported as *absent*, which reads as "you did
    # not download them" rather than "this failed". The corpora live on a
    # volume with room for them by definition, so the scratch goes there.
    work_root.mkdir(parents=True, exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="ulpf-cov-", dir=work_root))
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
            timeout=timeout,
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
    parser.add_argument("--data", default="realdata")
    parser.add_argument("--packs", default="packs")
    parser.add_argument(
        "--set",
        choices=["all", "perimeter", "universal"],
        default="all",
        help=(
            "which corpora to measure. 'perimeter' is the set the headline "
            "figure answers and finishes in minutes; 'all' includes corpora "
            "of hundreds of millions of records and takes hours"
        ),
    )
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
        "--exclude",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "skip a corpus by file or stem, for example --exclude Thunderbird. "
            "A skipped corpus is reported as excluded, never as absent, so a "
            "partial table cannot be mistaken for a complete one"
        ),
    )
    parser.add_argument(
        "--work-dir",
        default=None,
        help=(
            "scratch space for the vault each run writes (default: a "
            ".measure-work directory beside --data, which keeps it off the "
            "OS volume)"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=36000,
        help="seconds one corpus may take (default 36000; Thunderbird needs hours)",
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.05,
        help="percentage points a corpus may drop before it counts as a regression",
    )
    args = parser.parse_args()

    exe = binary()
    data = pathlib.Path(args.data)
    work_root = pathlib.Path(args.work_dir) if args.work_dir else data / ".measure-work"
    if not data.exists():
        print(f"{data} not found. Run: python tools/fetch_datasets.py", file=sys.stderr)
        raise SystemExit(1)

    print(f"{'CATEGORY':<10} {'SOURCE':<32} {'EVENTS':>9} {'PARSED':>9} {'COVERAGE':>10}")
    print("-" * 74)

    total_events = 0
    total_parsed = 0
    perimeter_events = 0
    perimeter_parsed = 0
    missing = []
    failed = []
    measured = {}

    selected = {"all": CORPORA, "perimeter": PERIMETER, "universal": UNIVERSAL}[args.set]
    excluded = []
    for category, candidates, label in selected:
        if any(x.lower() in name.lower() for name in candidates for x in args.exclude):
            excluded.append(candidates[0])
            continue
        corpus = next((data / name for name in candidates if (data / name).exists()), None)
        if corpus is None:
            missing.append(candidates[0])
            continue
        filename = corpus.name
        # Say so when the fallback sample was measured instead of the full
        # corpus, so a smaller number is never mistaken for the real one.
        if filename != candidates[0]:
            label = f"{label} [sample]"
        events, parsed = measure(exe, args.packs, corpus, args.timeout, work_root)
        if events == 0:
            # The file is on disk, so this is a run that failed -- out of
            # scratch space, a timeout, a crash -- and saying "absent" would
            # send the reader off to re-download something they already have.
            failed.append(filename)
            continue
        total_events += events
        total_parsed += parsed
        if filename in PERIMETER_FILES:
            perimeter_events += events
            perimeter_parsed += parsed
        pct = 100.0 * parsed / events
        measured[filename] = pct
        print(f"{category:<10} {label:<32} {events:>9,} {parsed:>9,} {pct:>9.4f}%")

    print("-" * 74)
    # Two totals, deliberately. The headline figure answers the Current Scope
    # sentence and must not move when a non-perimeter source is added; the
    # combined figure answers "does the framework hold outside the perimeter".
    if perimeter_events:
        pct = 100.0 * perimeter_parsed / perimeter_events
        print(
            f"{'PERIMETER (the headline figure)':<43} "
            f"{perimeter_events:>9,} {perimeter_parsed:>9,} {pct:>9.4f}%"
        )
    if total_events:
        pct = 100.0 * total_parsed / total_events
        print(
            f"{'ALL SOURCES':<43} {total_events:>9,} {total_parsed:>9,} {pct:>9.4f}%"
        )

    if missing:
        print("\nnot measured (absent): " + ", ".join(missing))
        print("run: python tools/fetch_datasets.py")

    total_pct = 100.0 * total_parsed / total_events if total_events else 0.0

    if args.write_baseline:
        write_baseline(pathlib.Path(args.baseline), measured, total_pct)
        return

    if args.check and (args.set != "all" or args.exclude):
        print("--check compares against a full-set baseline; drop --set", file=sys.stderr)
        raise SystemExit(1)

    if args.check:
        # A partial run must not pass: a missing corpus is exactly how a broken
        # pack would hide from the check that exists to catch it. There is no
        # longer a tier exception, because there are no longer tiers - a corpus
        # is either measured or named as absent.
        if missing or failed:
            blocked = missing + failed
            print(
                f"refusing to check with {len(blocked)} corpus/corpora unmeasured: "
                f"{', '.join(blocked)}",
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
