# Technical Presentation — content for 5 slides

SIH 2026 · Problem Statement 26156 · NTRO · Theme: Blockchain & Cybersecurity

This is the *content*, not the deck — write it up in whatever tool once the
numbers are locked (they are, as of this file). Five slides, hard cap, per
the problem statement's own deliverables list. Do not add a sixth "thank
you" or appendix slide; the cap is five, not five-plus.

Every number below matches `README.md` exactly. If a number changes there,
change it here in the same commit — this file exists so the deck is never
the place numbers drift.

---

## Slide 1 — The problem, and what we built

**Headline:** Universal Log Pre-processing Framework (ULPF)

**The problem (one line):** Every perimeter device — firewall, IDS, proxy,
WAF, VPN — speaks its own log format. Security teams spend more effort
writing parsers than analyzing threats.

**The one-sentence answer:** ULPF ingests logs from any perimeter device in
any format, preserves the original bytes losslessly, and normalizes
everything into OCSF — an open, vendor-neutral schema — so a firewall, an
IDS and a proxy describe the same kind of event the same way.

**Visual idea:** a simple before/after — five different raw log lines
(syslog, CEF, JSON, key-value, CSV) on the left, converging into one common
OCSF event shape on the right.

---

## Slide 2 — Architecture, in one diagram

**Flow to draw (left to right):**

```
Raw event  →  Vault (append-only, compressed, fingerprinted)
           →  Decode  →  Pack detection & field extraction
           →  OCSF normalization  →  Integrity chain + signed checkpoints
           →  Console / NDJSON / Parquet / OpenSearch / Splunk HEC
```

**Four things to label on the diagram, because they answer four separate
requirements at once:**

- The **vault** happens *before* parsing — satisfies "preserve raw data
  without loss," even for events the parser doesn't understand yet.
- **Source Packs** are declarative YAML, hot-reloaded — satisfies
  "plug-and-play onboarding," no code, no rebuild.
- **OCSF normalization** — satisfies "common taxonomy," using an existing
  open standard rather than one invented for this submission.
- **Integrity chain + Merkle proofs** — the traceability requirement, made
  provable rather than merely recorded, and the honest bridge to the
  "Blockchain & Cybersecurity" theme.

**One sentence on scale:** ten decoders, 35 Source Packs, one binary, zero
runtime network dependency — the same binary runs air-gapped.

---

## Slide 3 — Evidence, not adjectives

**Table (use exactly these numbers):**

| Claim | Measured |
|---|---|
| Log formats supported | 35 Source Packs, 75/75 fixtures passing, 100% field accuracy |
| Real-world accuracy | 2,964,087 real records (Honeynet + Loghub + a real MACCDC 2012 capture), **99.9679%** parsed |
| Throughput | **10,000 events/sec sustained, zero loss**, per collector — 864M events/day |
| Requirement coverage | **11 / 11** problem-statement requirements (a)–(k), each with cited evidence |

**One line under the table, said out loud in the pitch, not just shown:**
"Every number here is reproducible — `python tools/measure_coverage.py`
against public capture data prints the same figure a judge would get."

**Optional callout box:** "Real bugs, found by real data" — one sentence
naming a specific bug found by testing against genuine device output (e.g.
FortiGate's timestamp field being nanoseconds, not seconds, since FortiOS
6.2 — silently wrong in the original documentation-derived pack). This is a
credibility signal, not a confession — it shows the claims were actually
tested against something other than the team's own fixtures.

---

## Slide 4 — Why "Blockchain & Cybersecurity"

**The honest bridge, stated directly on the slide, not implied:**
"Nothing here is a cryptocurrency. What applies is the part of
distributed-ledger technology that actually solves the traceability
requirement: append-only structures, hash chaining, signed commitments, and
Merkle proofs."

**Three bullets:**
- Every event is fingerprinted and hash-chained to the one before it.
- Collectors periodically sign a checkpoint (Ed25519) over the chain.
- A Merkle tree (RFC 6962 / Certificate Transparency construction) lets one
  event's inclusion be **proven** with a small number of hashes — without
  revealing any other, possibly classified, event in the log.

**One sentence on why this matters to NTRO specifically:** for evidence
drawn from a classified source, this is the difference between something
that can be handed to an investigator or a court, and something that
cannot.

---

## Slide 5 — What's real today, what's next, and the close

**Two honest columns — say the gaps out loud, do not hide them:**

| Done | Open, and why it's not a blocker |
|---|---|
| 11/11 requirements met with evidence | One collector alone is 86% of 1B/day (10,000 of 11,574 EPS needed) — the architecture is per-collector and chains independently, so this is a deployment decision, not a redesign |
| 35 device formats, 32 checked against real traffic | 3 remaining (a generic fallback, one Check Point mode, pfSense) still on documentation-derived fixtures |
| Encrypted vault + signing key, TLS + auth on the console | UDP intake has no backpressure yet — TCP/TLS syslog is next |

**The close (one line, said, not read):** "Onboarding a device this system
has never seen is a YAML file, not a code change — fixture-tested and
hot-reloaded with zero restart. This is a working framework today, not a
plan for one."

**Contact / repo line:** GitHub link, team name. Nothing else — no logo
animation, no extra slide.

---

## Style notes for whoever builds the actual deck

- Five slides means five. A sixth "questions?" slide is not free just
  because it has no content — the deliverable says five.
- Keep every number on every slide byte-identical to `README.md`. A judge
  who has already read the README and finds a different number on the
  slide reads it as sloppiness, not a rounding choice.
- Diagrams over bullet walls wherever a flow exists (slide 2 especially).
- Whatever theme/colors are chosen, keep the "evidence, not adjectives"
  framing literal — a slide with a number is worth three with an adjective.
