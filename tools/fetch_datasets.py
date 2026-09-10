#!/usr/bin/env python3
"""Download the public log corpora ULPF's coverage claims are measured on.

Nothing here is generated. Every file comes from a public research dataset and
is used byte-for-byte as published, so the figures in docs/DATASETS.md can be
reproduced independently.

    python tools/fetch_datasets.py                  # everything
    python tools/fetch_datasets.py --dir D:/corpora # somewhere with room
    python tools/fetch_datasets.py --only Apache    # resume one corpus

**This fetches every corpus, with no tiering and no size gate.** Roughly 6 GB
of archives expanding to roughly 65 GB on disk. Make sure the target volume
has the room before starting.

That is a deliberate change. The previous version defaulted to a ~200 MB
"standard" tier, and the two largest tiers were opt-in — which meant the
command in the README produced a corpus set the published coverage table could
not actually be measured on. Four perimeter sources the headline figure is
measured on (Apache, Linux, Proxifier, OpenSSH) had no full-corpus entry at
all and were only ever scored on their 2,000-line samples, while the complete
corpora sat unused in the same Zenodo deposit.

Every completed file is skipped on a rerun and every partial transfer resumes
with an HTTP Range request, so an interrupted fetch is restarted by running
the same command again.

Nothing here is generated. Every file comes from a public research dataset and
is used byte-for-byte as published.
"""

import argparse
import bz2
import gzip
import io
import pathlib
import shutil
import sys
import tarfile
import time
import urllib.error
import urllib.request

HONEYNET = "http://log-sharing.dreamhosters.com"
LOGHUB = "https://raw.githubusercontent.com/logpai/loghub/master"
SECREPO = "https://www.secrepo.com"

# Loghub publishes a 2,000-line sample of each corpus in the repository itself.
# Only corpora a shipped Source Pack can actually claim. Windows, macOS,
# Android, HDFS, Spark and Zookeeper were fetched and offered in the
# simulator with no pack behind them, so switching one on dropped coverage
# live; they are also outside the problem statement's perimeter-device scope.
LOGHUB_SAMPLES = [
    # Perimeter and edge sources, which the coverage table is measured on.
    "Linux", "OpenSSH", "Apache", "Proxifier",
    # Sources demonstrating that the framework is not perimeter-only. Each has
    # a Source Pack, so switching one on in the simulator no longer drops
    # coverage the way an unbacked corpus did.
    "HDFS", "BGL", "Thunderbird", "Zookeeper", "OpenStack", "Windows",
    "Hadoop", "Spark", "Mac", "HPC", "HealthApp", "Android",
]

ZENODO = "https://zenodo.org/records/8196385/files"
ZENODO_API = "https://zenodo.org/api/records/8196385/files"

# Older official Loghub deposits are useful when Zenodo's current record is
# temporarily returning a gateway timeout. Archive formats may differ, so the
# extraction code below detects ZIP versus tar from the downloaded content.
ZENODO_FALLBACKS = {
    "BGL.zip": [
        "https://zenodo.org/records/1596245/files/BGL.tar.gz?download=1",
    ],
}

# Every corpus published in the official Loghub deposit, Zenodo record
# 8196385. The list was taken from that record's own file listing rather than
# transcribed from the documentation, so it cannot silently fall behind it:
#
#     python -c "import json,urllib.request; \
#       print([e['key'] for e in json.load(urllib.request.urlopen(
#       'https://zenodo.org/api/records/8196385/files'))['entries']])"
#
# There is deliberately no tiering. An earlier version split these into
# `large` and `xl` and defaulted to neither, which meant the default fetch
# silently produced a corpus set the coverage table could not be measured on.
# Worse, four perimeter sources the headline figure is measured on — Apache,
# Linux, Proxifier and OpenSSH — had no full entry here at all, so they were
# only ever measured on their 2,000-line samples while the complete corpora
# sat unused in the same deposit.
#
# (archive name, output stem, extracted size, published line count)
LOGHUB_FULL = [
    # Perimeter and edge sources. These are what the headline is measured on,
    # so they are fetched first and are the ones that must never be missing.
    ("Apache.tar.gz", "Apache", "5 MB", "56,481"),
    ("Linux.tar.gz", "Linux", "3 MB", "25,567"),
    ("SSH.tar.gz", "OpenSSH", "70 MB", "655,146"),
    ("Proxifier.tar.gz", "Proxifier", "2 MB", "21,329"),
    # Everything else in the deposit, smallest first so a slow link makes
    # visible progress before it reaches the multi-gigabyte archives.
    ("Zookeeper.tar.gz", "Zookeeper", "10 MB", "74,380"),
    ("Mac.tar.gz", "Mac", "16 MB", "117,283"),
    ("HealthApp.tar.gz", "HealthApp", "22 MB", "253,395"),
    ("HPC.zip", "HPC", "32 MB", "433,489"),
    ("Hadoop.zip", "Hadoop", "49 MB", "394,308"),
    ("OpenStack.tar.gz", "OpenStack", "59 MB", "207,820"),
    ("Android_v1.zip", "Android_v1", "183 MB", "1,555,005"),
    ("HDFS_v1.zip", "HDFS_v1", "1.5 GB", "11,175,629"),
    ("BGL.zip", "BGL", "709 MB", "4,747,963"),
    ("Android_v2.zip", "Android_v2", "3.4 GB", "30,348,042"),
    ("HDFS_v3_TraceBench.zip", "HDFS_v3", "1.6 GB", "N/A"),
    ("Spark.tar.gz", "Spark", "2.8 GB", "33,236,604"),
    ("HDFS_v2.zip", "HDFS_v2", "16.1 GB", "71,118,073"),
    ("Windows.tar.gz", "Windows", "26.1 GB", "114,608,388"),
    ("Thunderbird.tar.gz", "Thunderbird", "29.6 GB", "211,212,192"),
]


def fetch(url: str) -> bytes:
    print(f"  fetching {url}")
    with urllib.request.urlopen(url, timeout=300) as response:
        return response.read()


def fetch_to_file(urls: list[str], destination: pathlib.Path) -> None:
    """Download a large archive without holding it in RAM.

    A failed transfer is retained as ``.part`` and resumed with an HTTP Range
    request. Each official URL is tried several times before moving to the
    next official endpoint or deposit.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []

    # Rotate endpoints after each failure instead of waiting through three
    # timeouts against one unhealthy Zenodo front door. The first two URLs are
    # the same object; fallback deposits get their own partial file because
    # their compression format may differ.
    for attempt in range(1, 4):
        for url_index, url in enumerate(urls):
            suffix = ".part" if url_index < 2 else f".fallback{url_index - 1}.part"
            partial = destination.with_name(destination.name + suffix)
            existing = partial.stat().st_size if partial.exists() else 0
            headers = {"User-Agent": "ULPF-dataset-fetcher/1.0"}
            if existing:
                headers["Range"] = f"bytes={existing}-"
                print(f"  resuming {destination.name} at {existing / 1e6:.1f} MB")
            else:
                print(f"  fetching {url}")

            request = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=300) as response:
                    status = getattr(response, "status", response.getcode())
                    append = existing > 0 and status == 206
                    mode = "ab" if append else "wb"
                    # What the server says the body is, so a connection that
                    # closes early can be recognised as the truncation it is.
                    declared = response.headers.get("Content-Length")
                    expected = int(declared) + (existing if append else 0) if declared else None
                    with partial.open(mode) as output:
                        shutil.copyfileobj(response, output, length=1024 * 1024)

                # A dropped connection reads as a clean end of stream, so
                # without this check a half-transferred archive is renamed to
                # its final name and only fails later, at extraction -- where
                # it looks like a corrupt upstream file rather than a short
                # read. Two corpora were lost exactly this way when the network
                # changed mid-fetch. Leaving it as .part means the next attempt
                # resumes it instead of starting over.
                got = partial.stat().st_size
                if expected is not None and got < expected:
                    raise OSError(
                        f"truncated: {got:,} of {expected:,} bytes "
                        f"({got / expected * 100:.1f}%); will resume"
                    )
                partial.replace(destination)
                print(
                    f"    -> downloaded {destination.name}  "
                    f"({destination.stat().st_size / 1e6:.1f} MB)"
                )
                return
            except (OSError, urllib.error.URLError) as error:
                errors.append(f"{url}: {error}")
                print(
                    f"    endpoint {url_index + 1}/{len(urls)}, "
                    f"attempt {attempt}/3 failed: {error}"
                )
        if attempt < 3:
            time.sleep(2**attempt)

    detail = errors[-1] if errors else "no download URL was attempted"
    raise RuntimeError(f"all download endpoints failed for {destination.name}: {detail}")


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


def honeynet_proxy(target: pathlib.Path) -> None:
    """Squid proxy logs, from the same Honeynet mirror as the other captures.

    Real proxy traffic is the evidence `squid-proxy-access` was missing: it was
    scored only against fixtures written from vendor documentation, and the
    corpus showed the pattern assumed dotted-quad clients where the capture
    uses reverse-resolved hostnames.

    Blue Coat is fetched separately by `honeynet_bluecoat` in the `large` tier.
    """
    print("Honeynet proxy captures")
    out = target / "squid-access.log"
    if out.exists():
        print("  squid-access.log already present")
    else:
        raw = fetch(f"{HONEYNET}/hnet-hon-var-log-02282006.tgz")
        collected: list[bytes] = []
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                if "squid" not in member.name or "access" not in member.name:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                data = handle.read()
                # The archive holds `access_log` alongside its rotated
                # `access_log.N.gz` siblings. Concatenating those raw put
                # compressed bytes into the corpus: 23,000 of 59,000 "records"
                # were gzip framing, and the pack was scored against them.
                if member.name.endswith(".gz"):
                    try:
                        data = gzip.decompress(data)
                    except OSError:
                        continue
                collected.append(data)
        if collected:
            write(out, b"".join(collected))
        else:
            print("    squid access_log not found in the archive, skipped")



def honeynet_bluecoat(target: pathlib.Path) -> None:
    """Blue Coat ProxySG capture — 8,130,590 records, ~2.6 GB extracted.

    In the `large` tier, not `standard`. It is an order of magnitude bigger
    than every other Honeynet capture combined, and putting it in `standard`
    exhausted the disk on a GitHub-hosted runner: the coverage workflow died
    with "the runner has received a shutdown signal" partway through the fetch.
    A tier documented as ~200 MB should not pull 2.6 GB.

    `tools/measure_coverage.py` lists it and reports it as absent when it is not
    present, so the perimeter total is computed without it rather than failing.
    """
    print("Honeynet Blue Coat ProxySG capture (~2.6 GB)")
    out = target / "bluecoat-proxy.log"
    if out.exists():
        print("  bluecoat-proxy.log already present")
        return
    try:
        raw = fetch(f"{HONEYNET}/bluecoat_proxy_big.zip")
    except Exception as error:  # noqa: BLE001
        print(f"    bluecoat fetch failed ({error}), skipped")
        return
    import zipfile

    collected = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue
            collected.append(archive.read(name))
    if collected:
        # W3C `#Software`/`#Version`/`#Fields` directives are file structure,
        # not events. The archive concatenates many rotated logs, so leaving
        # them in counted 1,620 headers as unparsed records. Same reasoning as
        # the Dragon capture's [MARK] separators.
        body = b"".join(collected)
        lines = [l for l in body.splitlines(keepends=True) if not l.startswith(b"#")]
        write(out, b"".join(lines))



def secrepo_maccdc_zeek_conn(target: pathlib.Path) -> None:
    """Real Zeek/Bro conn.log from the MACCDC 2012 competition capture.

    `zeek-conn` was one of the nine packs the README lists as unverified —
    its column order came from a general description of conn.log, not a real
    capture, and turned out to be wrong: real output puts `missed_bytes`,
    `history` and the packet/byte counts immediately after `conn_state`, with
    a single `local_orig` before that and a trailing `tunnel_parents` set,
    not the `local_orig`/`local_resp` pair the old order assumed there.

    The full file is ~524 MB compressed (~2.6 GB extracted) — the same order
    of magnitude as the Blue Coat capture, so this follows the same fetching
    pattern: a bounded byte-range prefix, not the whole file, sized to match
    the `large` tier it lives in. A truncated gzip stream raises partway
    through decompression; everything decompressed before that point is
    still valid conn.log lines and is kept, with the one torn trailing line
    dropped. `tools/measure_coverage.py` reports this as a prefix, the same
    way it already does for Blue Coat, so no number here is an extrapolation
    to the full file.
    """
    print("SecRepo MACCDC 2012 Zeek conn.log (prefix)")
    out = target / "zeek-conn.log"
    if out.exists():
        print("  zeek-conn.log already present")
        return
    prefix_bytes = 50_000_000
    print(f"  fetching first {prefix_bytes / 1e6:.0f} MB of {SECREPO}/maccdc2012/conn.log.gz")
    request = urllib.request.Request(
        f"{SECREPO}/maccdc2012/conn.log.gz",
        headers={"Range": f"bytes=0-{prefix_bytes - 1}"},
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        compressed = response.read()

    lines: list[bytes] = []
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as handle:
        try:
            for line in handle:
                lines.append(line)
        except (OSError, EOFError):
            pass  # the byte range cut the gzip stream mid-block; keep what decoded
    if lines and not lines[-1].endswith(b"\n"):
        lines.pop()  # the torn line at the cut point, not a real record
    if lines:
        write(out, b"".join(lines))
    else:
        print("    no lines recovered from the prefix, skipped")


def secrepo_maccdc_zeek_conn_full(target: pathlib.Path) -> None:
    """Fetch the complete MACCDC 2012 Zeek conn.log without using Zenodo.

    This is an opt-in expansion because the gzip is roughly 524 MB and expands
    to roughly 2.6 GB. Both download and decompression stream to disk and can
    therefore run on an ordinary laptop without holding the corpus in RAM.
    """
    print("SecRepo MACCDC 2012 Zeek conn.log (full, ~2.6 GB extracted)")
    out = target / "zeek-conn-full.log"
    if out.exists():
        print("  zeek-conn-full.log already present")
        return

    archive = target / ".downloads" / "maccdc2012-conn.log.gz"
    fetch_to_file([f"{SECREPO}/maccdc2012/conn.log.gz"], archive)

    output_part = out.with_name(out.name + ".part")
    line_count = 0
    with gzip.open(archive, "rb") as source, output_part.open("wb") as output:
        while chunk := source.read(1024 * 1024):
            output.write(chunk)
            line_count += chunk.count(b"\n")
    output_part.replace(out)
    print(f"    -> {out.name}  ({out.stat().st_size / 1e9:.2f} GB, {line_count:,} lines)")
    archive.unlink(missing_ok=True)


def loghub_full(
    target: pathlib.Path,
    skipped: set[str] | None = None,
    only: set[str] | None = None,
) -> list[str]:
    """Fetch every complete Loghub corpus in the deposit.

    A corpus already extracted on disk is left alone, so this is safe to rerun
    and is the normal way to resume an interrupted transfer.
    """
    import zipfile

    skipped = skipped or set()
    failures: list[str] = []
    print(f"Loghub full corpora: {len(LOGHUB_FULL)} archives from Zenodo record 8196385")
    for archive_name, stem, size, lines in LOGHUB_FULL:
        if only and archive_name not in only and stem not in only:
            continue
        if archive_name in skipped or stem in skipped:
            print(f"  {archive_name}: skipped by --skip-archive")
            continue
        marker = target / f"{stem}.full.log"
        if marker.exists():
            print(f"  {marker.name} already present")
            continue
        print(f"  {archive_name}  ->  {marker.name}  ({size} extracted, {lines} lines)")
        downloads = target / ".downloads"
        archive_path = downloads / archive_name
        urls = [
            f"{ZENODO}/{archive_name}?download=1",
            f"{ZENODO_API}/{archive_name}/content",
            *ZENODO_FALLBACKS.get(archive_name, []),
        ]
        try:
            if not archive_path.exists():
                fetch_to_file(urls, archive_path)

            output_part = marker.with_name(marker.name + ".part")
            wrote_data = False
            with output_part.open("wb") as output:
                if zipfile.is_zipfile(archive_path):
                    with zipfile.ZipFile(archive_path) as handle:
                        names = [n for n in handle.namelist() if not n.endswith("/")]
                        # Prefer the obvious log extensions, but do not require
                        # them. HDFS_v3_TraceBench and Android_v2 store their
                        # records under other names, and demanding `.log`
                        # produced "contains no .log or .txt files" for two
                        # corpora that are perfectly usable.
                        chosen = [
                            n for n in names if n.endswith((".log", ".txt"))
                        ] or names
                        for name in chosen:
                            with handle.open(name) as stream:
                                shutil.copyfileobj(stream, output, length=1024 * 1024)
                            wrote_data = True
                else:
                    with tarfile.open(archive_path, mode="r:*") as handle:
                        for member in handle.getmembers():
                            if not member.isfile():
                                continue
                            stream = handle.extractfile(member)
                            if stream is not None:
                                with stream:
                                    shutil.copyfileobj(stream, output, length=1024 * 1024)
                                wrote_data = True

            if not wrote_data:
                output_part.unlink(missing_ok=True)
                raise RuntimeError(f"{archive_name} contained no extractable files")
            output_part.replace(marker)
            print(f"    -> {marker.name}  ({marker.stat().st_size / 1e6:.1f} MB)")
            archive_path.unlink(missing_ok=True)
        except Exception as error:  # noqa: BLE001 - continue with other corpora
            failures.append(archive_name)
            print(f"    {archive_name} unavailable for now: {error}")
            # Discard an archive that would not open. Keeping it meant the
            # next run found the file present, skipped the download, and
            # failed on the same unreadable bytes forever -- so a corpus lost
            # to one truncated transfer could never recover on its own.
            if archive_path.exists():
                archive_path.unlink(missing_ok=True)
                print(f"    discarded {archive_name} so a rerun fetches it again")
            print("    continuing with the remaining corpora")

    return failures


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
        default="realdata",
        help="where to place the corpora (default: realdata)",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "fetch only these Loghub corpora, by archive or output name, for "
            "example --only Apache --only HDFS_v2; may be supplied more than "
            "once. Everything else is fetched by default"
        ),
    )
    parser.add_argument(
        "--skip-archive",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "skip one temporarily unavailable full archive, for example "
            "--skip-archive BGL.zip; may be supplied more than once"
        ),
    )
    parser.add_argument(
        "--skip-loghub-full",
        action="store_true",
        help="skip all full Loghub/Zenodo archives while keeping other tier data",
    )
    parser.add_argument(
        "--no-full-zeek",
        action="store_true",
        help=(
            "skip the full ~2.6 GB MACCDC Zeek corpus and keep only the "
            "bounded prefix"
        ),
    )
    args = parser.parse_args()
    target = pathlib.Path(args.dir).resolve()
    target.mkdir(parents=True, exist_ok=True)
    print(f"Target: {target}")
    print("Fetching every corpus: ~6 GB of archives, ~65 GB extracted.")
    print("Completed files are skipped and partial transfers resume.\n")

    try:
        loghub(target)
        honeynet_sotm34(target)
        honeynet_sotm30(target)
        honeynet_dragon(target)
        honeynet_proxy(target)
        combine(target)
        honeynet_bluecoat(target)
        secrepo_maccdc_zeek_conn(target)
        if not args.no_full_zeek:
            secrepo_maccdc_zeek_conn_full(target)
        if args.skip_loghub_full:
            print("Loghub full corpora: skipped by --skip-loghub-full")
            full_failures = []
        else:
            full_failures = loghub_full(
                target,
                set(args.skip_archive),
                set(args.only),
            )
    except Exception as error:  # noqa: BLE001 - a fetch failure should be legible
        print(f"\nfailed: {error}", file=sys.stderr)
        raise SystemExit(1) from error

    if full_failures:
        print("\nAvailable corpora are ready, but these archives need a later retry:")
        for archive_name in full_failures:
            print(f"  - {archive_name}")
        print("Rerun this same command later; completed files will be skipped.")
    else:
        print("\nReady. Now run: python tools/measure_coverage.py")


if __name__ == "__main__":
    main()
