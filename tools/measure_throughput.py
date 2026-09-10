#!/usr/bin/env python3
"""Measure sustained ingest rate, and project it to events per day.

The method docs/THROUGHPUT.md describes was previously run by hand: start a
collector, start a replayer, read the last counter line, repeat per rate. Doing
that by hand is how a published table drifts from the machine it claims to
describe, so it lives here instead.

    cargo build --release --locked
    python tools/measure_throughput.py

One host, loopback UDP, sender and collector on the same machine. Each run
sends a fixed number of real records at a fixed offered rate into a fresh vault
and a fresh attestation chain. "Received" is what the collector durably
vaulted, fingerprinted, chained and emitted — not datagrams that touched the
NIC.

The events/day column is a projection from the measured rate, and is labelled
as one everywhere it is printed. It is arithmetic on a measured number
(rate x 86,400), never a claim to have ingested that many records.
"""

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

# The collector prints this to stderr every 1,000 events, as
#   received 1000 . parsed 1000 . coverage 100.0000%
# with a U+00B7 middle dot between the fields. Anything non-numeric matches
# that separator on purpose: read back through a Windows locale codec the
# dot arrives as two characters, not one, and a single "." here silently
# matched nothing and reported every run as total loss.
PROGRESS = re.compile(r"received\s+(\d+)\D+parsed\s+(\d+)")

SECONDS_PER_DAY = 86_400
# One billion events per day, the figure the problem statement names.
TARGET_PER_DAY = 1_000_000_000


def binary() -> pathlib.Path:
    import os

    roots = []
    configured = os.environ.get("CARGO_TARGET_DIR")
    if configured:
        roots.append(pathlib.Path(configured))
    roots.append(pathlib.Path("target"))
    for root in roots:
        for name in ("ulpf.exe", "ulpf"):
            path = root / "release" / name
            if path.exists():
                # Absolute: this is handed to CreateProcess from a temporary
                # working directory on Windows.
                return path.resolve()
    print("no release binary; run: cargo build --release --locked", file=sys.stderr)
    raise SystemExit(1)


def one_rate(
    exe: pathlib.Path,
    packs: str,
    corpus: pathlib.Path,
    port: int,
    eps: int,
    seconds: int,
    work_root: pathlib.Path,
) -> dict:
    """Offer `eps` for `seconds`, and report what the collector kept."""
    # Beside the corpora rather than in the system temp directory: every
    # accepted record is vaulted, and the OS volume is routinely the smallest
    # on the machine.
    work_root.mkdir(parents=True, exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="ulpf-tput-", dir=work_root))
    count = eps * seconds
    try:
        collector = subprocess.Popen(
            [
                str(exe), "listen",
                "--packs", packs,
                "--vault", str(work / "vault"),
                "--integrity-dir", str(work / "integrity"),
                "--bind", f"127.0.0.1:{port}",
                "--output", "nul" if sys.platform == "win32" else "/dev/null",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # The receiver binds before it prints; give it a moment rather than
        # racing the first datagram against the bind.
        time.sleep(3)
        if collector.poll() is not None:
            raise RuntimeError(f"collector exited early: {collector.stderr.read()[:400]}")

        # Read the collector's progress line as it is produced, rather than
        # once at the end. The count has to be watched, not sampled: the run
        # is finished when the collector stops advancing, and there is no
        # other signal for that.
        latest = {"received": 0, "parsed": 0, "at": time.monotonic()}

        def follow(stream) -> None:
            for line in iter(stream.readline, ""):
                match = PROGRESS.search(line)
                if match:
                    latest["received"] = int(match.group(1))
                    latest["parsed"] = int(match.group(2))
                    latest["at"] = time.monotonic()

        reader = threading.Thread(target=follow, args=(collector.stderr,), daemon=True)
        reader.start()

        started = time.monotonic()
        subprocess.run(
            [
                str(exe), "replay",
                "--source", str(corpus),
                "--target", f"127.0.0.1:{port}",
                "--eps", str(eps),
                "--count", str(count),
            ],
            capture_output=True,
            text=True,
            timeout=seconds * 20 + 120,
        )
        send_elapsed = time.monotonic() - started

        # Drain. The socket buffer holds tens of thousands of datagrams at
        # these sizes, so a fixed pause after the sender stops truncates the
        # count and reports the buffer's capacity as though it were the
        # collector's ceiling -- which is exactly what a fixed five-second
        # wait did here: every rate above the ceiling returned an identical
        # 70,000, the 8 MB buffer's worth, and the ladder looked like a wall.
        #
        # Wait until the counter has not moved for QUIET, or until the whole
        # offered batch is accounted for.
        QUIET = 8.0
        deadline = time.monotonic() + seconds * 20 + 180
        while time.monotonic() < deadline:
            if latest["received"] >= count:
                break
            if time.monotonic() - latest["at"] > QUIET:
                break
            time.sleep(0.5)

        collector.terminate()
        try:
            collector.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            collector.kill()
            collector.communicate()

        received, parsed = latest["received"], latest["parsed"]

        return {
            "offered_eps": eps,
            "sent": count,
            "received": received,
            "parsed": parsed,
            "loss_pct": 100.0 * (count - received) / count if count else 0.0,
            "coverage_pct": 100.0 * parsed / received if received else 0.0,
            "send_elapsed_s": round(send_elapsed, 2),
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packs", default="packs")
    parser.add_argument("--data", default="realdata")
    parser.add_argument(
        "--corpus",
        default="iptables.log",
        help="real records to replay (default: iptables.log, Honeynet SotM34)",
    )
    parser.add_argument(
        "--rates",
        default="4000,10000,12000,15000,20000",
        help="offered rates in EPS, comma separated",
    )
    parser.add_argument(
        "--seconds", type=int, default=10, help="seconds of traffic per rate"
    )
    parser.add_argument("--port", type=int, default=5610)
    parser.add_argument(
        "--work-dir",
        default=None,
        help="scratch for each run's vault (default: .measure-work beside --data)",
    )
    parser.add_argument(
        "--json", metavar="PATH", help="also write the measured rows as JSON"
    )
    args = parser.parse_args()

    exe = binary()
    corpus = pathlib.Path(args.data) / args.corpus
    if not corpus.exists():
        print(f"{corpus} not found. Run: python tools/fetch_datasets.py", file=sys.stderr)
        raise SystemExit(1)

    work_root = (
        pathlib.Path(args.work_dir)
        if args.work_dir
        else pathlib.Path(args.data) / ".measure-work"
    )
    rates = [int(r) for r in args.rates.split(",") if r.strip()]
    print(f"corpus: {corpus}  ({corpus.stat().st_size / 1e6:.1f} MB)")
    print(f"{args.seconds}s per rate, loopback UDP, fresh vault and chain each run\n")
    print(f"{'OFFERED':>9} {'SENT':>9} {'RECEIVED':>9} {'LOSS':>7} {'COVERAGE':>9}")
    print("-" * 48)

    rows = []
    for eps in rates:
        row = one_rate(exe, args.packs, corpus, args.port, eps, args.seconds, work_root)
        rows.append(row)
        print(
            f"{row['offered_eps']:>9,} {row['sent']:>9,} {row['received']:>9,} "
            f"{row['loss_pct']:>6.1f}% {row['coverage_pct']:>8.4f}%"
        )

    # The sustained ceiling is the highest offered rate that lost nothing.
    lossless = [r for r in rows if r["received"] >= r["sent"]]
    ceiling = max((r["offered_eps"] for r in lossless), default=0)

    print("-" * 48)
    if ceiling:
        per_day = ceiling * SECONDS_PER_DAY
        print(f"\nSustained lossless ceiling: {ceiling:,} EPS per collector")
        print("\nProjection from that measured rate (arithmetic, not an ingest run):")
        print(f"  {ceiling:,} EPS x {SECONDS_PER_DAY:,} s = {per_day:,} events/day")
        needed = TARGET_PER_DAY / SECONDS_PER_DAY
        print(
            f"  {TARGET_PER_DAY:,}/day needs {needed:,.0f} EPS "
            f"({per_day / TARGET_PER_DAY * 100:.0f}% of target on one collector)"
        )
        collectors = -(-TARGET_PER_DAY // per_day)  # ceiling division
        print(f"  collectors required for {TARGET_PER_DAY:,}/day: {collectors}")
    else:
        print("\nNo rate completed without loss; widen --rates downward.")

    if args.json:
        payload = {
            "corpus": str(corpus),
            "seconds_per_rate": args.seconds,
            "rows": rows,
            "sustained_lossless_eps": ceiling,
            "projected_events_per_day": ceiling * SECONDS_PER_DAY,
        }
        pathlib.Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
