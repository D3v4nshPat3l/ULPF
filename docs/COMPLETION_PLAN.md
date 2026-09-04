# Completion plan and competitive landscape

What is left to finish ULPF, where it sits against what already exists, and the
ideas worth building that nothing else in the category does.

Written 3 September 2026, against the tree at 18 packs / 292,608 measured
records / 10,000 EPS sustained.

- [Part 1 — What is remaining](#part-1--what-is-remaining)
- [Part 2 — What already exists](#part-2--what-already-exists)
- [Part 3 — Ideas worth building](#part-3--ideas-worth-building)
- [Build order](#build-order)

---

# Part 1 — What is remaining

Split by whether it blocks the claim "the problem statement is fully met".

## Blocking

### 1. Requirement (h), AI/ML-ready analytics

The only requirement still marked *Partial*. Stable structured JSON exists.
What does not exist is a batched columnar feature table with a **stable column
contract**. Today a model consumer re-derives fields from JSON on every run,
which means the effective schema shifts underneath them whenever a pack
changes.

This is the clearest hole in the requirement table.

### 2. Eight packs have no real-corpus evidence

Cisco ASA, FortiGate, Palo Alto PAN-OS, Check Point, Juniper SRX, Suricata,
ModSecurity and Squid pass fixtures written from vendor documentation. No
public corpus backs them.

Real data has already broken three packs in this project that passed
documentation-derived tests:

- Snort scored **69.3%** — the 31% missed were preprocessor alerts (Spade,
  stream4, http_inspect) carrying neither `[Classification:]` nor
  `[Priority:]`.
- iptables failed on stock kernel logging: a default `LOG` rule with no
  `--log-prefix` emits a printk uptime and no verdict at all.
- Apache missed exploit probes, because a request like
  `"GET /scripts/..%255c../winnt/system32/cmd.exe?/c+dir"` omits the HTTP
  version — precisely the records worth keeping.

Until those eight see real traffic they are unproven. This is the largest
credibility gap in the project and it is not a technical problem.

### 3. Self-assessment documents — resolved

`docs/gap_analysis.md` marked every requirement "Fully Addressed", including
(h), which `README.md` correctly marks *Partial*; a reader who opened both
found the repository contradicting itself. It also described "5 Source Packs
and 7 decoders" against the current 18 and 10.

It was deleted, along with `docs/codebase_analysis.md` and `docs/strategy/`.
The README requirement table is now the single self-assessment, which is the
right outcome: one place to keep honest rather than four to keep in sync.

Nothing further to do here — it is recorded because it was a real problem, not
because it is still open.

### 4. Throughput to one billion events per day

Measured: **10,000 EPS sustained lossless = 864M events/day**, 86% of the
11,574 EPS the target requires. The 12,000 EPS run drops 1.7% of records and
does not count.

Chains are already per-collector and verify independently, so nothing in the
architecture blocks a second node. What is missing is only the deployment
story: a documented two-node configuration and a verifier that consumes
several chains at once. See [THROUGHPUT.md](THROUGHPUT.md).

## Extending

### 5. TCP/TLS syslog (RFC 5425)

UDP has no backpressure. Above the sustained rate the kernel discards and the
sender is never told. For a collector whose premise is "nothing is lost",
transport-level loss is an awkward asterisk. The receive buffer is raised to
8 MB and the granted size is printed at startup, but that only widens the
window.

### 6. Windows Event Log and NetFlow / IPFIX

Neither is text-line shaped, so neither is another YAML pack — both need real
ingestion work. Windows especially: it is the most common enterprise log
source and its absence is conspicuous.

### 7. OCSF schema validation in CI

Already requested by [ROADMAP.md](ROADMAP.md). The schema is vendored at
`schema/ocsf` but no validators are generated from it, so a pack can emit a
class-invalid event and nothing catches it.

### 8. Key custody and rotation

The signing key is created `0600` and the collector refuses to start on loose
permissions. There is no rotation procedure, no documented custody, and no way
to verify a chain that spans a key change. For evidence meant to hold up, this
is the weakest link.

### 9. True air-gapped build

Runtime is clean — no CDN, web font, telemetry or model API. But `cargo build`
still needs crates.io on a fresh machine. `cargo vendor` plus a committed
bundle closes it.

### 10. Release engineering

SBOM, signed release checksums, a service unit, container scan. Cheap, and it
is what separates a hackathon repository from something deployable.

---

# Part 2 — What already exists

The category is crowded. The specific corner ULPF occupies is not.

## Commercial: Security Data Pipeline Platforms

Seven platforms dominate: **Cribl** (market leader), **Abstract Security**,
**DataBahn**, **Axoflow**, **Monad**, **VirtualMetric**, and **Falcon Onum**
(CrowdStrike). All of them do roughly what ULPF's front half does — ingest
heterogeneous telemetry, normalize to a schema, route to a SIEM or lake.

Two weaknesses run through the entire category, and ULPF is strong in both.

**Cloud-only storage.** Cribl Lake and Abstract's storage layer are cloud-only;
organisations with on-premises retention requirements cannot use them.
DataBahn and Monad ship no storage tier at all and must route to Snowflake,
BigQuery or Amazon Security Lake. Only Axoflow offers an on-premises lake.

For an air-gapped national technical agency this rules out most of the market
outright.

**Probabilistic normalization.** Most vendors now put AI/LLM mapping in the
data path — DataBahn markets AI-driven transformation to CIM, OCSF, UDM and
ASIM. The category critique is blunt: probabilistic methods are unsuitable for
detection rules that require 100% accuracy on known sources.

**This is ULPF's argument and it is currently undersold.** The hot path is
entirely deterministic — compiled YAML packs, zero model inference per event.
An LLM only ever drafts a *candidate*, a human approves it, and from that
moment the behaviour is fixed and reproducible. That distinction should be
stated far more loudly than it is.

## Open source

Vector, Fluent Bit, Logstash, Fluentd and OpenTelemetry are the
transport/transform substrate. They are faster than ULPF and far more mature.

**None of them does integrity.** None fingerprints events, chains them, or
lets anyone prove a record was not altered. That is the gap ULPF sits in.

## Schema layer

OCSF is winning. Amazon Security Lake is OCSF-native over Parquet and Iceberg,
and the 2026 drivers — lakehouse security architectures, AI-driven detection,
compliance mandates taking effect this year — all push toward a vendor-neutral
schema. The competitors are Elastic ECS, Splunk CIM, Microsoft ASIM, Google
UDM and Palo Alto XDM, each tied to a vendor.

Choosing **OCSF 1.9 was correct**, for two reasons worth stating in the
README: it is the only genuinely vendor-neutral option, and it defines a
`record_integrity` profile — the hook the entire attestation design hangs on.

## Academic log parsing

Drain, which ULPF uses for dead-letter clustering, is the classic baseline.
The field has moved:

- **LILAC** (FSE'24) pairs an LLM with an *adaptive parsing cache*, beating
  prior state of the art by **69.5% average F1** on template accuracy while
  cutting LLM queries by orders of magnitude.
- **LogBatcher** does demonstration-free parsing using diversity sampling to
  batch lines into a single prompt.

The transferable insight is the cache, not the model. See idea 7.

## Integrity and transparency logs

Certificate Transparency (**RFC 9162**) is the mature prior art. It uses a
Merkle *history tree* — dynamically append-only — supporting inclusion proofs
of size ⌈log₂ n⌉ hashes. That is meaningfully stronger than a linear chain.

## Chain of custody

For evidentiary use, integrity of the data is only half the requirement. Under
US FRE 901 the proponent must authenticate the item; without a documented
chain, authentication rests on operator testimony alone, which is rebuttable.
EU courts may exclude undocumented digital evidence as unreliable.

Practice requires that **every handover, download and export be recorded in a
tamper-evident log capturing who accessed what, when, and for what purpose.**

ULPF has tamper-evidence for the data. It has **no record of who read it.**

---

# Part 3 — Ideas worth building

Ranked by impact and credibility against effort.

## 1. Merkle history tree with inclusion proofs

**Today:** a linear hash chain. Proving event #40,000 is authentic means
replaying 40,000 events.

**Instead:** a Merkle history tree in the CT style. Proving one event's
inclusion takes roughly 17 sibling hashes for a million events — a proof that
fits in a QR code.

What this actually changes is *what can be handed to someone*. Today, proving
one log line means shipping the whole chain. With inclusion proofs a court, an
auditor or a partner agency receives a single event plus a few hundred bytes
and verifies it against a published signed tree head **without ever seeing the
other events** — which also solves the confidentiality problem of sharing
evidence drawn from a classified log.

RFC 8785 canonicalization and Ed25519 signing already exist. The tree is
perhaps 300 lines on top. Highest value per line in the backlog.

## 2. Cross-collector witness co-signing

The attack the current design does not stop: a compromised collector can
rewrite its own history and re-sign the chain. Self-signed integrity cannot
detect a self-consistent forgery.

CT solves this with witnesses and gossip. For ULPF: **each collector
periodically co-signs the other collectors' tree heads.** Rewriting history
then requires compromising every node simultaneously, and any divergence is
detectable by comparing co-signed heads.

A second node is already needed for throughput. This makes it a *security*
argument as well. No commercial SDPP surveyed does this.

Depends on ideas 1 and the two-node deployment.

## 3. Pack content digest and provable reprocessing

**The gap.** Events already record `metadata.log_provider` (the pack id) and
`metadata.product.version` (the pack's *declared* version). That version is a
hand-written string in the YAML. Edit a pack without bumping it and the events
produced before and after are indistinguishable.

**The fix.** Put a content hash of the compiled pack into every event.

**The payoff.** Because raw bytes are vaulted and addressable, a new pack
version can be re-run over historical raw data to emit a *signed diff*: "pack
`snort-nids-alert@a3f9` produced this, `@b71c` produces that, here are the 412
events whose classification changed, and here is the proof both derive from
identical raw bytes."

Nothing else in the category can do this, because nothing else keeps the raw
bytes addressable. It is the strongest argument for the vault-first design and
it is currently unexploited. It also serves NTRO directly: when a parser bug is
found, it becomes possible to prove exactly which historical conclusions were
affected.

## 4. Custody log for evidence retrieval

Every `ulpf raw` retrieval and every console raw-view appends a record — who,
what locator, when, under what case reference — to its own chained,
tamper-evident log.

The research is unambiguous that this is required for admissibility, and there
is none of it today. It is a small change that converts "tamper-evident
storage" into "chain of custody" in the sense the phrase legally carries.

## 5. Source silence detection

**50% of SIEM detection-rule failures in 2025 trace to log collection
problems** — missed sources, misconfigured agents, bad forwarding. Separately,
42% of organisations ingest everything with no plan to analyse it.

ULPF already observes every source's arrival cadence. Learn each source's
normal rate and alert when one goes quiet. A firewall that stops logging is
either broken or being silenced, and nothing in the stack notices today.

Not in the problem statement, which is exactly why it differentiates: it
addresses the failure mode that actually breaks SOCs, and it is a few hundred
lines given the statistics already collected.

## 6. Coverage regression gate in CI

292,608 real records and `tools/measure_coverage.py` already exist. Wire them
into CI so a pack change that drops coverage below its recorded baseline fails
the build.

This would have caught the Snort 69.3% regression automatically. It converts
the dataset work from a one-time measurement into a permanent safety net, for
roughly thirty lines of workflow.

## 7. Adaptive parsing cache for the generator

Taken directly from LILAC. The generator is currently invoked per cluster. Add
a persistent cache keyed by log template so a given shape is analysed **once,
ever** — across sessions and machines, since the cache is a file.

Cuts model calls by orders of magnitude and makes the AI path viable on a
laptop with a small model. It also strengthens the air-gapped story: ship the
cache pre-warmed and a fresh install parses known shapes with no model at all.

Best-evidenced improvement available.

## 8. Confidence-scored field mapping

The category critique is that AI normalization is not trustworthy enough for
detection rules. Turn that into a feature: each mapped field carries a
confidence; high-confidence mappings auto-activate, low-confidence ones queue
for review.

Packs are already scored against fixtures — this exposes that per field rather
than per pack.

---

# Build order

| # | Item | Effort | Why here |
|---|---|---|---|
| 1 | Pack content digest | Afternoon | Small, and unlocks idea 3 |
| 2 | Coverage regression gate | Afternoon | Tiny, permanent value |
| 3 | Merkle tree + inclusion proofs | ~300 lines | The demonstration moment |
| 4 | Custody log | Afternoon | Closes the legal argument |
| 5 | Columnar feature table | Days | Closes requirement (h) |
| 6 | Source silence detection | Days | Differentiator |
| 7 | Two-node deployment doc | Day | Closes the 1B/day gap |
| 8 | Witness co-signing | Days | Novel; needs 3 and 7 first |

Items 1, 2 and 4 are each an afternoon. Item 3 is the one that changes how the
project reads.

---

# Sources

- [Security Data Pipeline Platform comparison 2026 — Axoflow](https://axoflow.com/blog/sdpp-comparison-2026)
- [Amazon Security Lake integration — Cribl Docs](https://docs.cribl.io/stream/usecase-security-lake/)
- [What is OCSF, and why normalize security data now — Databahn](https://www.databahn.ai/blog/what-is-ocsf-and-why-normalize-security-data-now)
- [RFC 9162: Certificate Transparency Version 2.0](https://datatracker.ietf.org/doc/rfc9162/)
- [LILAC: Log Parsing using LLMs with Adaptive Parsing Cache (FSE'24)](https://arxiv.org/pdf/2310.01796)
- [Stronger, Cheaper and Demonstration-Free Log Parsing with LLMs (LogBatcher)](https://arxiv.org/pdf/2406.06156)
- [System Log Parsing with Large Language Models: A Review](https://arxiv.org/html/2504.04877v2)
- [Why SIEM Rules Fail — insights from 160 million attack simulations](https://thehackernews.com/2025/08/why-siem-rules-fail-and-how-to-fix-them.html)
- [Digital Evidence Chain of Custody: Navigating New Realities (SoK)](https://sefcom.asu.edu/publications/CoC-SoK-tps2024.pdf)
- [Chain of Custody for Digital Evidence: Practical Guide](https://truescreen.io/insights/chain-of-custody-digital-evidence-lawyers/)
