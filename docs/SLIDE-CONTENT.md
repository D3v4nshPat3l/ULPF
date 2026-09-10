# Technical presentation — 5 slides

SIH 2026 · PS 26156 · NTRO · Universal Log Pre-processing Framework

**Hard limit: 5 slides.** This is the content, not the design. Every number
below is a placeholder marked `[MEASURED]` until it is filled from a run — see
*Where every number comes from* at the end, and never paste a figure that has
not been produced by one of those commands.

Design rules: no stock imagery, no gradient hero, no icon soup. Screenshots
from the running console are the visuals. One idea per slide.

---

## Slide 1 — The problem, in one line of each

**Title:** Forty vendors, forty formats, one question nobody can ask

**Body:** three real log lines, verbatim, monospace, stacked:

```
%ASA-6-302013: Built inbound TCP connection 12345678 for outside:203.0.113.9/49221 to inside:192.0.2.5/443
Feb 25 12:21:33 bastion snort[1885]: [1:483:5] ICMP PING CyberKit [Priority: 3]: {ICMP} 70.81.243.88 -> 11.11.79.100
1756636800.123 152 10.2.4.7 TCP_MISS/200 12345 GET http://example.com/en/index.html
```

**The one sentence under them:**
> Each of these contains a source address. No two call it the same thing, and
> none of them is a field you can query.

**Speaker note:** Do not explain the formats. The point is that the audience
cannot read them at a glance either — and neither can a SIEM.

---

## Slide 2 — What ULPF does

**Title:** Any log in, OCSF out, nothing lost

**Visual:** the pipeline, one row, left to right:

```
receiver → raw vault → identify → decoder chain → OCSF mapping → attest → sinks
              │                                                    │
              └── constant-time retrieval by locator ──────────────┘
```

**Three claims, one line each:**

- **Vault first, parse second.** Original bytes are stored *before* anything
  is interpreted. A record nobody has a parser for is still preserved,
  searchable and retrievable. "Unparsed" is a routing decision, never data loss.
- **Parsers are data, not code.** A new device is a YAML file, hot-reloaded.
  No recompile, no restart, no plugin ABI.
- **Every event is tamper-evident.** A fingerprint over the event's canonical
  form, chained to its predecessor, anchored by Ed25519-signed checkpoints and
  an RFC 6962 Merkle tree.

**Speaker note:** The middle claim is the one that answers "reduced parser
development effort". The third is the one that answers the Blockchain theme
without the word blockchain.

---

## Slide 3 — The comparison

**Title:** The same traffic, twice

**Visual:** two screenshots of the *same* Wazuh Discover view, side by side,
same index, same time range.

| Left — raw to the SIEM | Right — through ULPF |
|---|---|
| `full_log` holds the vendor's own line | `full_log` holds OCSF |
| Three formats, nothing shared | `src_endpoint.ip` across all of them |
| No link to anything | `ulpf_raw_locator` back to the original bytes |
| No integrity | `attestation_list` chained to the previous event |

**The one sentence:**
> One click on the simulator switched the target. Nothing else changed.

**Speaker note:** This is the slide the submission is judged on. If there is
time for only one slide, it is this one.

---

## Slide 4 — Evidence

**Title:** Measured, on real capture data

**Table — coverage** `[MEASURED]`

| Category | Source | Origin | Records | Coverage |
|---|---|---|---:|---:|
| Firewall | iptables | Honeynet SotM34 | `[MEASURED]` | `[MEASURED]` |
| IDS | Snort | Honeynet SotM34 | `[MEASURED]` | `[MEASURED]` |
| Auth | OpenSSH | Loghub | `[MEASURED]` | `[MEASURED]` |
| Proxy | Blue Coat ProxySG | Honeynet | `[MEASURED]` | `[MEASURED]` |
| Network | Zeek conn.log | MACCDC 2012 | `[MEASURED]` | `[MEASURED]` |
| **Perimeter total** | | | **`[MEASURED]`** | **`[MEASURED]`** |

**Table — throughput** `[MEASURED]`

| Sustained lossless | Projected per day | 1B/day needs |
|---:|---:|---:|
| `[MEASURED]` EPS | `[MEASURED]` | 11,574 EPS |

**Three lines that matter more than the numbers:**

- Every figure comes from unmodified public capture data — Honeynet Project,
  Loghub, MACCDC 2012. **No coverage figure in this project is measured on
  synthesized data**, and the one synthetic file in the repository is labelled
  as such and excluded by an assertion in the measurement script.
- The events-per-day figure is **arithmetic on a measured rate**
  (rate × 86,400), labelled as a projection. It is not a claim to have
  ingested that many records.
- Coverage is not 100%, and the misses are enumerated by name rather than
  rounded away.

**Speaker note:** Volunteer the Proxifier and Apache-error gaps before anyone
asks. A judge who finds an unstated gap stops believing the stated ones.

---

## Slide 5 — Requirements, and what is honestly not done

**Title:** Against PS 26156

**Left column — the eleven requirements**, one line each, with the artefact
that proves it:

| | Requirement | Proved by |
|---|---|---|
| a | Preserve raw without loss | `ulpf raw <locator>` returns the exact bytes |
| b | Extract source attributes | 10 decoders, per-pack chains |
| c | Common taxonomy | OCSF 1.9.0, schema vendored in-tree |
| d | Traceability | locator + fingerprint + Merkle inclusion proof |
| e | Plug-and-play onboarding | drop a YAML file in, hot-reloaded |
| f | Unified visibility | embedded console |
| g | SIEM / data lake | NDJSON, Parquet, OpenSearch, Splunk, UDP forward |
| h | AI/ML-ready | 24-column Parquet feature table, versioned contract |
| i | Reduced parser effort | unknown device 0% → 100%, no hand-written parser |
| j | Air-gapped — **shall** | zero runtime network dependency; CI builds `--offline` |
| k | Containerized — *may* | distroless image, one-command compose |

**Right column — stated limits:**

- One collector does not reach one billion events per day. `[MEASURED]` EPS is
  `[MEASURED]`% of the target; reaching it is a second collector, which the
  architecture already allows because chains are per-collector.
- Coverage is `[MEASURED]`, not 100%. The remainder is enumerated.
- Some packs have no real-corpus evidence and are named as unproven.

**Speaker note:** Ending on limits is deliberate. It is the strongest available
signal that the numbers on slide 4 are real, and it pre-empts the question a
judge was going to ask anyway.

---

## Where every number comes from

Fill the `[MEASURED]` placeholders from these, and from nothing else:

```bash
cargo build --release --locked

# coverage table (slide 4, and the coverage line on slide 5)
python tools/measure_coverage.py --set perimeter

# throughput and the events/day projection (slide 4, and the limit on slide 5)
python tools/measure_throughput.py

# pack and fixture counts, if quoted anywhere
./target/release/ulpf test --packs packs
```

If a number cannot be traced to one of those commands, it does not go on a
slide.
