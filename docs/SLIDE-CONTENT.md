# Technical presentation — 5 slides

SIH 2026 · PS 26156 · NTRO · Universal Log Pre-processing Framework

**Hard limit: 5 slides.** This is the content, not the design. Every number
below was produced by a command in *Where every number comes from* at the end.
Re-run those before the deck is final and replace anything that moved — never
paste a figure that has not come out of one of them.

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

**Table — coverage**

| Category | Source | Origin | Records | Coverage |
|---|---|---|---:|---:|
| Firewall | iptables | Honeynet SotM34 | 179,752 | 100.0000% |
| IDS | Snort | Honeynet SotM34 | 69,039 | 99.9986% |
| Auth | OpenSSH | Loghub, full | 655,147 | 100.0000% |
| Proxy | Blue Coat ProxySG | Honeynet | 8,130,590 | 99.8033% |
| Network | Zeek conn.log | MACCDC 2012, full | 22,694,356 | 99.9435% |
| **Perimeter total** | | | **32,414,250** | **99.8834%** |

*Thirteen sources in total; five shown. The full table is in the README.*

**Table — throughput**

| Sustained lossless | Projected per day | 1B/day needs |
|---:|---:|---:|
| 8,000 EPS | 691,200,000 | 11,574 EPS — two collectors |

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
asks. A judge who finds an unstated gap stops believing the stated ones. Note
too that measuring the *full* corpora pushed several figures down — Apache
error went from a clean 100% on a 2,000-line sample to 92.07% on 56,482
records. That direction is the point.

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

- One collector does not reach one billion events per day. 8,000 EPS is 69% of
  the target; reaching it is a second collector, which the architecture already
  allows because chains are per-collector.
- Coverage is 99.8834%, not 100%. The remainder is enumerated by name —
  Proxifier's non-connection lines, and 4,478 Apache lines that carry no
  timestamp at all.
- Five Loghub corpora totalling 375 million records are held on disk and have
  **not** been run. Stated, not hidden.
- Some packs have no real-corpus evidence and are named as unproven.

**Speaker note:** Ending on limits is deliberate. It is the strongest available
signal that the numbers on slide 4 are real, and it pre-empts the question a
judge was going to ask anyway.

---

## Where every number comes from

The figures above were produced by these, and nothing else. Re-run them before
the deck is final — the numbers move as packs and corpora change:

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
