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

There are now several, because one unknown device demonstrates the mechanism
but not the point. A normalization layer earns its keep when the estate is
heterogeneous, so these deliberately differ in *wire format* and not merely in
field values: key=value, CEF-style pipes, JSON lines, and a fixed-column
embedded format. Each drafts a different decoder chain, which is what makes the
"needs a pack" queue look like an estate rather than a list.

Each device carries a stable vendor tag and a stable event marker. That is not
decoration: `derive_detectors` keeps only tokens present in every sample, so
without them a draft has no literal to claim the source by, and the operator
gets a template of pure wildcards that identifies nothing.

    python tools/make_demo_source.py                    # -> realdata/, all devices
    python tools/make_demo_source.py --only apx-ngfw    # just one
    python tools/make_demo_source.py --count 50000
"""

import argparse
import hashlib
import json
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


# --------------------------------------------------------------------------
# Three more fictional devices, each in a different wire format.
#
# All addresses stay inside RFC 5737 documentation ranges and RFC 1918 private
# space, so no line here can be mistaken for a capture. The vendors do not
# exist. What is real is the *shape*: these are the four ways appliances
# actually write logs, which is what the onboarding path has to cope with.


# Pipe-delimited positional. Deliberately *not* CEF: the first draft of this
# device wore a CEF:0 header and `generic-cef-network` claimed all 6,000
# records, which is correct behaviour and useless as an unknown device. CEF is
# a standard; a vendor's own pipe layout is not, and that is the case the
# onboarding path actually has to handle.
VG_VENDOR, VG_PRODUCT, VG_MARKER = "Meridian", "VaultGate", "VGATE"
VG_EVENTS = (
    [("100", "Secret read", 2)] * 45
    + [("101", "Secret written", 3)] * 20
    + [("200", "Lease expired", 3)] * 15
    + [("403", "Access denied", 7)] * 15
    + [("500", "Seal integrity check failed", 9)] * 5
)
VG_PATHS = ["kv/prod/db", "kv/prod/api", "kv/stage/db", "pki/issue/web",
            "transit/keys/payments", "kv/ci/tokens"]


def vaultgate_line(rng: random.Random, seq: int) -> str:
    code, name, sev = rng.choice(VG_EVENTS)
    stamp = (f"2026-04-{rng.randint(1, 28):02d} "
             f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}")
    src = rng.choice(INTERNAL) + str(rng.randint(2, 250))
    outcome = "SUCCESS" if sev < 5 else "FAILURE"
    # Spaces around the pipes, for the same reason the JSON device is spaced:
    # an unspaced delimiter run is one token to a whitespace tokeniser.
    return (
        f"{VG_MARKER} | {stamp} | {VG_PRODUCT} 3.4 | {code} "
        f"| {name.upper().replace(' ', '_')} | sev {sev} "
        f"| {src} {rng.choice([34935, 41022, 52771])} | {rng.choice(USERS)} "
        f"| {rng.choice(VG_PATHS)} | {outcome} | lease {rng.choice([300, 3600, 86400])} "
        f"| vg-{rng.randint(1, 4):02d}"
    )


# JSON lines. An API gateway is the format most likely to arrive without a
# pack, because every one of them invents its own field names.
CE_SERVICE, CE_MARKER = "corvid-edge", "edge.access"
CE_ROUTES = ["/v1/orders", "/v1/orders/{id}", "/v1/customers", "/v1/auth/token",
             "/v2/search", "/healthz", "/v1/webhooks/stripe"]
CE_METHODS = ["GET"] * 55 + ["POST"] * 30 + ["PUT"] * 8 + ["DELETE"] * 7
CE_STATUS = [200] * 60 + [201] * 10 + [304] * 5 + [401] * 8 + [403] * 5 + [404] * 7 + [502] * 5


def corvid_line(rng: random.Random, seq: int) -> str:
    status = rng.choice(CE_STATUS)
    # Values come from small sets on purpose. Drain buckets by token count and
    # then merges by positional similarity, and a field with thousands of
    # distinct values pushes every pair below the threshold: an earlier draft
    # of this corpus, with a free-running request id and millisecond timings,
    # fragmented 2,500 records into 1,164 clusters -- one device presented as a
    # thousand. Real appliances repeat themselves; corpora that do not are not
    # a fair test of onboarding.
    payload = {
        "ts": (f"2026-04-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:"
               f"{rng.randint(0, 59):02d}:00Z"),
        "svc": CE_SERVICE,
        "kind": CE_MARKER,
        "method": rng.choice(CE_METHODS),
        "route": rng.choice(CE_ROUTES),
        "status": status,
        "ms": rng.choice([12, 48, 130, 420, 1100]),
        "client_ip": rng.choice(EXTERNAL) + str(rng.choice([17, 64, 132, 209])),
        "upstream": f"10.60.{rng.randint(0, 3)}.10",
        "principal": rng.choice(USERS),
        "bytes_out": rng.choice([0, 1024, 8192, 65536]),
    }
    # Spaced separators, not compact. Drain splits on whitespace, so a compact
    # {"a":1,"b":2} line arrives as a single token and every distinct record
    # becomes its own template -- 2,500 records fragmented into 20 clusters
    # that were all the same device. Plenty of gateways emit spaced JSON; this
    # keeps the corpus a fair test of onboarding rather than of tokenisation.
    return json.dumps(payload, separators=(", ", ": "))


# A fixed-column embedded device. No key=value at all: position carries the
# meaning, which is the case a key=value-only onboarding path gets wrong.
# `is_stable_literal` wants punctuation or eight characters, so a bare
# seven-letter "HALYARD" is rejected and the cluster drafts with no literal to
# claim it by. Real devices tag themselves with underscores and colons for
# exactly the same reason a parser needs them.
HR_TAG, HR_MARKER = "HALYARD_RLY", "STATE"
HR_POINTS = ["PUMP-01", "PUMP-02", "VALVE-11", "VALVE-12", "TANK-03", "COMP-07"]
HR_STATES = (
    [("RUN", "OK", 1)] * 55 + [("IDLE", "OK", 1)] * 20
    + [("STOP", "OK", 2)] * 15 + [("FAULT", "OVERTEMP", 7)] * 10
)


def halyard_line(rng: random.Random, seq: int) -> str:
    state, detail, sev = rng.choice(HR_STATES)
    stamp = (f"{rng.randint(1, 28):02d}/04/26 "
             f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}")
    return (
        f"[{stamp}] {HR_TAG} {HR_MARKER} "
        f"{rng.choice(HR_POINTS):<9} {state:<5} {detail:<12} "
        f"{rng.choice([18, 64, 210, 355]):>4}C {rng.choice([12, 110, 230]):>4}V "
        f"SEV{sev}"
    )


# Six more, so the queue looks like an estate rather than a demo. Each is a
# shape a real product actually ships, and each carries a tag long enough or
# punctuated enough for `is_stable_literal` to keep it.

# Bracketed syslog tag with a pid, then key=value. The single most common
# shape a Linux-adjacent appliance emits.
ND_TAG, ND_MARKER = "nimbus-dnsfw", "querylog"
ND_ACTIONS = ["allowed"] * 60 + ["blocked"] * 25 + ["sinkholed"] * 10 + ["throttled"] * 5
ND_CATS = ["malware", "phishing", "adult", "ads", "uncategorised", "newly-seen"]
ND_QNAMES = ["updates.example.net", "cdn.example.org", "login.example.com",
             "telemetry.example.io", "mail.example.net"]


def nimbus_line(rng: random.Random, seq: int) -> str:
    action = rng.choice(ND_ACTIONS)
    return (
        f"{ND_TAG}[{rng.choice([412, 5510, 8807])}]: {ND_MARKER} "
        f"action={action} qtype={rng.choice(['A', 'AAAA', 'TXT', 'MX'])} "
        f"qname={rng.choice(ND_QNAMES)} category={rng.choice(ND_CATS)} "
        f"client={rng.choice(INTERNAL)}{rng.choice([15, 88, 203])} "
        f"rcode={rng.choice(['NOERROR', 'NXDOMAIN', 'REFUSED'])} "
        f"elapsed_ms={rng.choice([1, 4, 19, 62])}"
    )


# Tab-delimited columns with a header vocabulary of its own. Zeek made this
# shape familiar; the field set here is not Zeek's.
TL_TAG = "TIDELOCK_AUDIT"
TL_OPS = ["OPEN", "READ", "WRITE", "DELETE", "CHOWN"]
TL_RESULT = ["OK"] * 70 + ["DENIED"] * 25 + ["QUOTA"] * 5
TL_SHARES = ["/vol/finance", "/vol/hr", "/vol/eng", "/vol/backup"]


def tidelock_line(rng: random.Random, seq: int) -> str:
    cols = [
        TL_TAG,
        f"2026-05-{rng.randint(1, 28):02d}",
        f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:00",
        rng.choice(TL_OPS),
        rng.choice(TL_RESULT),
        rng.choice(USERS),
        rng.choice(TL_SHARES),
        str(rng.choice([0, 4096, 262144])),
        f"node{rng.randint(1, 3)}",
    ]
    return chr(9).join(cols)


# Attribute-value pairs inside angle brackets. Appliances that grew out of an
# XML config format often log like this.
AX_TAG, AX_MARKER = "axiom-wafgw", "httpreq"
AX_RULES = ["SQLI-001", "XSS-014", "RCE-002", "LFI-007", "SCAN-020"]
AX_SEV = ["low"] * 45 + ["medium"] * 30 + ["high"] * 20 + ["critical"] * 5


def axiom_line(rng: random.Random, seq: int) -> str:
    return (
        f"<{AX_MARKER} product={AX_TAG} "
        f"rule={rng.choice(AX_RULES)} severity={rng.choice(AX_SEV)} "
        f"action={rng.choice(['pass', 'block', 'challenge'])} "
        f"src={rng.choice(EXTERNAL)}{rng.choice([9, 77, 145])} "
        f"host=www.example.com method={rng.choice(['GET', 'POST'])} "
        f"status={rng.choice([200, 403, 406, 503])} "
        f"bytes={rng.choice([0, 512, 8192])} />"
    )


# Section markers in square brackets, then a sentence. Embedded and appliance
# firmware writes like this, and it is the shape a key=value parser handles
# worst.
QS_TAG = "QUARRYSTONE"
QS_LEVELS = ["INFO"] * 60 + ["WARN"] * 25 + ["ERROR"] * 15
QS_SUBSYS = ["ups", "hvac", "door", "camera", "genset"]
QS_MSGS = ["battery self test completed", "threshold exceeded",
           "link renegotiated", "firmware image verified",
           "sensor calibration drift detected"]


def quarrystone_line(rng: random.Random, seq: int) -> str:
    return (
        f"[{QS_TAG}] [{rng.choice(QS_LEVELS)}] [{rng.choice(QS_SUBSYS)}] "
        f"[unit-{rng.randint(1, 6):02d}] {rng.choice(QS_MSGS)} "
        f"code={rng.choice(['E100', 'E204', 'W011', 'I000'])}"
    )


# Semicolon-separated key:value. Mainframe and telco gear that predates
# key=value conventions still writes colons and semicolons.
HB_TAG, HB_MARKER = "HOLLOWBRK", "TXNLOG"
HB_STATES = ["settled"] * 55 + ["pending"] * 25 + ["reversed"] * 12 + ["declined"] * 8


def hollowbrook_line(rng: random.Random, seq: int) -> str:
    return (
        f"{HB_TAG};{HB_MARKER};"
        f"chan:{rng.choice(['atm', 'pos', 'web', 'branch'])};"
        f"state:{rng.choice(HB_STATES)};"
        f"amt:{rng.choice([500, 2500, 19999])};"
        f"cur:{rng.choice(['INR', 'USD', 'EUR'])};"
        f"term:{rng.choice(['T0091', 'T0450', 'T1120'])};"
        f"resp:{rng.choice(['00', '05', '51', '91'])};"
        f"node:hb-{rng.randint(1, 3):02d}"
    )


# JSON, but a different vocabulary from the gateway, so two JSON sources have
# to be told apart by their keys rather than by their syntax.
KA_MARKER = "k8s.audit"
KA_VERBS = ["get"] * 45 + ["list"] * 20 + ["create"] * 15 + ["delete"] * 10 + ["patch"] * 10
KA_RES = ["pods", "secrets", "configmaps", "deployments", "nodes"]
KA_NS = ["kube-system", "prod", "staging", "observability"]


def kestrel_line(rng: random.Random, seq: int) -> str:
    payload = {
        "kind": KA_MARKER,
        "stage": "ResponseComplete",
        "verb": rng.choice(KA_VERBS),
        "resource": rng.choice(KA_RES),
        "namespace": rng.choice(KA_NS),
        "user": rng.choice(USERS),
        "decision": rng.choice(["allow", "allow", "allow", "forbid"]),
        "code": rng.choice([200, 201, 403, 404]),
        "cluster": "kestrel-01",
    }
    return json.dumps(payload, separators=(", ", ": "))


# name -> (filename, line builder, seed offset, label)
#
# Each device gets its own RNG stream so adding one never changes another's
# output; the Aperture offset is zero so its corpus stays byte-identical to
# every earlier run of this script.
DEVICES = {
    "apx-ngfw": ("apx-ngfw-synthetic.log", line, 0, "Aperture APX NGFW"),
    "vaultgate": ("meridian-vaultgate-synthetic.log", vaultgate_line, 1, "Meridian VaultGate"),
    "corvid-edge": ("corvid-edge-synthetic.log", corvid_line, 2, "Corvid Edge Gateway"),
    "halyard": ("halyard-relay-synthetic.log", halyard_line, 3, "Halyard SCADA Relay"),
    "nimbus-dns": ("nimbus-dnsfw-synthetic.log", nimbus_line, 4, "Nimbus DNS Firewall"),
    "tidelock": ("tidelock-audit-synthetic.log", tidelock_line, 5, "Tidelock File Audit"),
    "axiom-waf": ("axiom-wafgw-synthetic.log", axiom_line, 6, "Axiom WAF Gateway"),
    "quarrystone": ("quarrystone-bms-synthetic.log", quarrystone_line, 7, "Quarrystone BMS"),
    "hollowbrook": ("hollowbrook-txn-synthetic.log", hollowbrook_line, 8, "Hollowbrook Switch"),
    "kestrel-k8s": ("kestrel-k8s-audit-synthetic.log", kestrel_line, 9, "Kestrel Cluster Audit"),
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", default="realdata", help="where to write (default: realdata)")
    parser.add_argument("--count", type=int, default=50000,
                        help="records per generated device (default: 50000)")
    parser.add_argument(
        "--extra-count", type=int, default=None,
        help="deprecated compatibility override for non-Aperture devices",
    )
    parser.add_argument("--only", choices=sorted(DEVICES),
                        help="generate one device instead of all of them")
    parser.add_argument("--seed", type=int, default=26156, help="RNG seed, so runs are reproducible")
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be greater than zero")
    if args.extra_count is not None and args.extra_count < 1:
        parser.error("--extra-count must be greater than zero")

    target = pathlib.Path(args.dir).resolve()
    target.mkdir(parents=True, exist_ok=True)

    manifest = {
        "classification": "synthetic",
        "purpose": "unknown-source onboarding, parser development, and load testing",
        "coverage_eligible": False,
        "seed": args.seed,
        "datasets": [],
    }

    for name in ([args.only] if args.only else sorted(DEVICES)):
        filename, builder, offset, label = DEVICES[name]
        out = target / filename
        count = (
            args.extra_count
            if offset != 0 and args.extra_count is not None
            else args.count
        )
        # A stream per device, so adding one never shifts another's output.
        rng = random.Random(args.seed + offset)
        temporary = out.with_suffix(out.suffix + ".tmp")
        digest = hashlib.sha256()
        with temporary.open("wb") as handle:
            for seq in range(1, count + 1):
                encoded = (builder(rng, seq) + "\n").encode("utf-8")
                handle.write(encoded)
                digest.update(encoded)
        temporary.replace(out)
        size = out.stat().st_size
        manifest["datasets"].append({
            "device_id": name,
            "label": label,
            "file": filename,
            "records": count,
            "bytes": size,
            "sha256": digest.hexdigest(),
            "seed": args.seed + offset,
        })
        print(f"    -> {out.name}  {label}  ({count:,} records, {size / 1e6:.1f} MB)")

    manifest_path = target / "synthetic-datasets.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"    -> {manifest_path.name}  audit manifest")
    print("       SYNTHETIC. Labelled in the simulator; excluded from coverage.")


if __name__ == "__main__":
    main()
