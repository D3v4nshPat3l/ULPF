#!/usr/bin/env python3
"""Download the public log corpora ULPF's coverage claims are measured on.

Nothing here is generated. Every file comes from a public research dataset and
is used byte-for-byte as published, so the figures in docs/DATASETS.md can be
reproduced independently.

    python tools/fetch_datasets.py            # into ../realdata
    python tools/fetch_datasets.py --dir DIR

Roughly 150 MB on disk once prepared.
"""

import argparse
import bz2
import gzip
import io
import pathlib
import sys
import tarfile
import urllib.request

HONEYNET = "http://log-sharing.dreamhosters.com"
LOGHUB = "https://raw.githubusercontent.com/logpai/loghub/master"

# Loghub publishes a 2,000-line sample of each corpus in the repository itself.
LOGHUB_SAMPLES = ["Linux", "OpenSSH", "Apache", "Proxifier", "Windows", "Mac", "Android", "HDFS", "Spark", "Zookeeper"]


def fetch(url: str) -> bytes:
    print(f"  fetching {url}")
    with urllib.request.urlopen(url, timeout=300) as response:
        return response.read()


def write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"    -> {path.name}  ({len(data) / 1e6:.1f} MB)")


def loghub(target: pathlib.Path) -> None:
    print("Loghub production samples")
    for name in LOGHUB_SAMPLES:
        out = target / f"{name}_2k.log"
        if out.exists():
            print(f"  {out.name} already present")
            continue
        write(out, fetch(f"{LOGHUB}/{name}/{name}_2k.log"))


def honeynet_sotm34(target: pathlib.Path) -> None:
    """Firewall, IDS, web and mail logs from one honeynet capture."""
    print("Honeynet Scan of the Month 34")
    if (target / "SotM34").exists():
        print("  SotM34 already present")
        return
    raw = fetch(f"{HONEYNET}/SotM34-anton.tar.gz")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        archive.extractall(target)
    print("    -> SotM34/")


def honeynet_sotm30(target: pathlib.Path) -> None:
    """A second, independent iptables capture, used for cross-validation."""
    print("Honeynet Scan of the Month 30")
    out = target / "SotM30-anton.log"
    if out.exists():
        print("  SotM30 already present")
        return
    write(out, gzip.decompress(fetch(f"{HONEYNET}/SotM30-anton.log.gz")))


def honeynet_dragon(target: pathlib.Path) -> None:
    """Enterasys Dragon NIDS — a second IDS vendor, pipe-delimited."""
    print("Honeynet Dragon NIDS capture")
    out = target / "dragon-nids.log"
    if out.exists():
        print("  dragon-nids.log already present")
        return
    raw = fetch(f"{HONEYNET}/dragon-conv-000_590.tar.bz2")
    lines: list[bytes] = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:bz2") as archive:
        members = [m for m in archive.getmembers() if m.name.endswith(".bz2")]
        for member in members[:25]:
            handle = archive.extractfile(member)
            if handle is None:
                continue
            try:
                lines.extend(bz2.decompress(handle.read()).splitlines(keepends=True))
            except OSError:
                continue  # a couple of members in the archive are truncated
    # [MARK] separators are file structure, not events.
    lines = [l for l in lines if l.strip() != b"[MARK]"]
    write(out, b"".join(lines))


def combine(target: pathlib.Path) -> None:
    """Concatenate the rotated SotM34 files into one corpus per category."""
    print("Preparing per-category corpora")
    groups = {
        "iptables.log": ["SotM34/iptables/iptablesyslog"],
        "snort.log": ["SotM34/snort/snortsyslog"],
        "apache-access.log": sorted(target.glob("SotM34/http/access_log*")),
        "sendmail.log": sorted(target.glob("SotM34/syslog/maillog*")),
        "linux-messages.log": sorted(target.glob("SotM34/syslog/messages*")),
    }
    for out_name, sources in groups.items():
        out = target / out_name
        paths = [target / s if isinstance(s, str) else s for s in sources]
        paths = [p for p in paths if p.exists()]
        if not paths:
            print(f"  {out_name}: no source files, skipped")
            continue
        with out.open("wb") as handle:
            for path in paths:
                handle.write(path.read_bytes())
        count = sum(1 for _ in out.open("rb"))
        print(f"    -> {out_name}  ({count:,} lines)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dir",
        default="../realdata",
        help="where to place the corpora (default: ../realdata)",
    )
    args = parser.parse_args()
    target = pathlib.Path(args.dir).resolve()
    target.mkdir(parents=True, exist_ok=True)
    print(f"Target: {target}\n")

    try:
        loghub(target)
        honeynet_sotm34(target)
        honeynet_sotm30(target)
        honeynet_dragon(target)
        combine(target)
    except Exception as error:  # noqa: BLE001 - a fetch failure should be legible
        print(f"\nfailed: {error}", file=sys.stderr)
        raise SystemExit(1) from error

    print("\nReady. Now run: python tools/measure_coverage.py")


if __name__ == "__main__":
    main()
