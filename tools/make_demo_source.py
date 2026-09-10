#!/usr/bin/env python3
"""Generate the synthetic 'unknown device' corpus used by the onboarding demo.

**This corpus is synthetic. It is not evidence, and no coverage or throughput
figure in this project is measured on it.** It exists for one purpose: to give
a live demonstration a device ULPF has never seen, so that the Drain
clustering, the pack generator, the operator's edit, and the approve-and-deploy
path can all be shown end to end on a machine with no unknown traffic of its
own.

Every real corpus is already claimed by a shipped Source Pack, which is exactly
the problem: a demonstration of onboarding a *new* device needs a device that
is genuinely new. Inventing one is honest as long as it is labelled, so:

  * The appliance is fictional. "Aperture APX" is not a product.
  * Addresses are RFC 5737 documentation ranges (203.0.113.0/24,
    198.51.100.0/24, 192.0.2.0/24) and RFC 1918 private space, so no line can
    be mistaken for a capture.
  * The simulator labels the source `Synthetic`, and it is excluded from
    `tools/measure_coverage.py`.

The field names are deliberately conventional (`src`, `dst`, `spt`, `dpt`,
`proto`, `user`, `host`) because that is what real appliances use, and it is
what lets the deterministic generator map them onto OCSF attributes without a
model. The point being demonstrated is the onboarding workflow, not the
generator's ability to guess unusual spellings.

    python tools/make_demo_source.py                    # -> realdata/
    python tools/make_demo_source.py --count 50000
"""

import argparse
import pathlib
import random

# A stable tag plus a stable literal. `derive_detectors` keeps tokens that
# appear in every sample, so these are what let the generated pack claim this
# device and nothing else.
TAG = "apx-ngfw"
MARKER = "sessionlog"

INTERNAL = ["10.42.8.", "10.42.9.", "172.20.4.", "192.168.24."]
# RFC 5737 documentation ranges only.
EXTERNAL = ["203.0.113.", "198.51.100.", "192.0.2."]

APPS = ["https", "http", "dns", "ssh", "smtp", "quic", "ntp", "rdp"]
USERS = ["jdoe", "asmith", "rpatel", "mchen", "kowalski", "svc-backup", "-"]
ZONES = [("trust", "untrust"), ("dmz", "untrust"), ("trust", "dmz")]
HOSTS = ["apx-edge-01", "apx-edge-02", "apx-core-01"]

# (verdict, event, severity). Weighted so a demo shows a realistic mix rather
# than an even split across outcomes nobody sees in that proportion.
OUTCOMES = (
    [("allow", "session_end", 1)] * 60
    + [("deny", "session_end", 4)] * 22
    + [("drop", "policy_violation", 5)] * 10
    + [("reset", "session_reset", 3)] * 8
)


def line(rng: random.Random, seq: int) -> str:
    src = rng.choice(INTERNAL) + str(rng.randint(2, 250))
    dst = rng.choice(EXTERNAL) + str(rng.randint(1, 250))
    verdict, event, severity = rng.choice(OUTCOMES)
    app = rng.choice(APPS)
    dpt = {"https": 443, "http": 80, "dns": 53, "ssh": 22,
           "smtp": 25, "quic": 443, "ntp": 123, "rdp": 3389}[app]
    proto = "udp" if app in ("dns", "quic", "ntp") else "tcp"
    szone, dzone = rng.choice(ZONES)

    # An inbound session reverses the direction, so the corpus is not a single
    # shape wearing different values.
    if rng.random() < 0.18:
        src, dst = dst, src
        szone, dzone = dzone, szone

    sent = rng.randint(0, 48000) if verdict == "allow" else rng.randint(0, 1500)
    rcvd = rng.randint(0, 96000) if verdict == "allow" else 0

    stamp = (
        f"2026-03-{rng.randint(10, 28):02d}T"
        f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"
        f".{rng.randint(0, 999):03d}Z"
    )

    return (
        f"{stamp} {TAG} {MARKER} "
        f"evt={event} verdict={verdict} proto={proto} "
        f"src={src} spt={rng.randint(1024, 65535)} dst={dst} dpt={dpt} "
        f"sent={sent} rcvd={rcvd} dur={rng.randint(1, 90000)} "
        f"rule=RL-{rng.randint(1, 400):04d} szone={szone} dzone={dzone} "
        f"user={rng.choice(USERS)} app={app} host={rng.choice(HOSTS)} "
        f"sev={severity} sid={seq:09d}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", default="realdata", help="where to write (default: realdata)")
    parser.add_argument("--count", type=int, default=40000, help="records to generate")
    parser.add_argument("--seed", type=int, default=26156, help="RNG seed, so runs are reproducible")
    args = parser.parse_args()

    target = pathlib.Path(args.dir).resolve()
    target.mkdir(parents=True, exist_ok=True)
    out = target / "apx-ngfw-synthetic.log"

    rng = random.Random(args.seed)
    with out.open("w", encoding="utf-8", newline="\n") as handle:
        for seq in range(1, args.count + 1):
            handle.write(line(rng, seq) + "\n")

    size = out.stat().st_size
    print(f"    -> {out}  ({args.count:,} records, {size / 1e6:.1f} MB)")
    print("       SYNTHETIC. Labelled in the simulator; excluded from coverage.")


if __name__ == "__main__":
    main()
