# ULPF — Gap Analysis: Build Plan vs. Reality

> **Brutally honest.** No praise games. This document cross-references every item in the [Build Plan](file:///C:/Users/jampa/Downloads/ULPF_BUILD_PLAN.md) against the actual code that exists on `main` today.

---

## Executive Summary

Devansh built an **extremely solid Phase 0 walking skeleton** — and went a fair way into Phase 1 and Phase 2. The core pipeline (receive → vault → identify → extract → normalize → attest) is fully functional and genuinely well-engineered. The integrity system is production-grade.

**But Phase 0 is not complete**, and we are now 2 days past its exit gate (20 Sep was the deadline). Here's where we actually stand:

| Phase | Status | Honest Assessment |
|---|---|---|
| **Phase 0** (Walking Skeleton) | **~85% done** | Pipeline works end-to-end. Missing: synthetic log generator, `build.rs` OCSF codegen |
| **Phase 1** (Production Core) | **~40% done** | 6 of 8 decoders done. 5 of 12+ packs done. Parquet sink done. Missing: hot reload, backpressure, XML/LEEF decoders |
| **Phase 2** (Differentiators) | **~30% done** | Drain clustering done. Generator UI exists. Missing: real LLM integration, review-and-approve flow, docker-compose demo stack |
| **Phase 3** (Scale & Hardening) | **~5% done** | Dockerfile exists. Missing: benchmark harness, fuzzing, air-gap CI, distroless image, SBOM |
| **Phase 4** (Deliverables) | **~10% done** | Architecture doc exists. Missing: 2-page doc, 5 slides, 2-min video, README quickstart |

---

## Requirement-by-Requirement Status

### ✅ DONE — These work and can be demoed

| Req | What the plan says | What exists in code |
|---|---|---|
| **(a)** Preserve raw data | Raw Vault with zstd compression | `ulpf-vault` — append-only segments, `VaultWriter` + `VaultReader`, byte-exact retrieval via `RawRef` locators |
| **(b)** Extract source-specific attributes | Source Pack extraction plans | `ulpf-pack` compiled decoder chains, `ulpf-decode` with 6 decoders (syslog, keyvalue, csv, cef, json, regex) |
| **(c)** Normalize to OCSF 1.9 | Typed OCSF events | `ulpf-ocsf` with `EventBuilder` enforcing all required base attributes, schema version `"1.9.0"` |
| **(d)** Traceability to originals | `record_integrity` profile | `integrity.rs` — hash chaining, Ed25519 signed checkpoints, `verify_event()`, `verify_chain()`. **This is excellent work.** |
| **(f)** Unified visibility | Operator console | `server.rs` + `index.html` — live metrics, event table, pack browser, raw proof retrieval, tamper-and-verify demo |

### ⚠️ PARTIALLY DONE — These exist but are incomplete

| Req | What the plan says | What's missing |
|---|---|---|
| **(b)** Extract attributes | "All six built-in decoders" | **XML decoder** and **LEEF decoder** are missing. Only 6 of the 8 planned decoders exist. |
| **(e)** Plug-and-play onboarding | "Hot reload from watched directory" | Packs load at startup from `packs/` dir. **No hot reload / file watcher** — requires restart to pick up new packs. |
| **(g)** SIEM integration | "Sinks for Parquet, OpenSearch, Splunk HEC, Kafka, OTLP, syslog forward" | **Parquet, OpenSearch, Splunk HEC** sinks exist and work. **Kafka, OTLP, syslog forward** sinks are **missing**. |
| **(i)** Reduced parser effort | "LLM drafts a pack with tests" | Drain clustering works. Scorer works. **LLM integration is entirely mocked** — `llm.rs` returns a hard-coded template. No actual `llama.cpp` call. The review-and-approve flow in the UI is **skeletal** (just a "Generate Pack" button that returns mock YAML). |

### ❌ NOT DONE — These are missing entirely

| Req | What the plan says | Status |
|---|---|---|
| **(c)** OCSF types | "`build.rs` codegen from OCSF JSON schema" | **Not done.** Types are hand-written in `types.rs`. The plan specifically says to generate types from the vendored `schema/ocsf` JSON. |
| **(h)** AI/ML-ready analytics | "Stable partitioned Parquet + derived features + anomaly-detection script" | Parquet sink writes 4 columns. **No partitioning by date/event class.** No derived features. No anomaly-detection script. |
| **(j)** Air-gapped deployment | "Vendored offline build, zero egress, CI job in network namespace" | **Not done.** No vendored deps (`cargo vendor` not run). No air-gap CI job. No network namespace test. |
| **(k)** Container-packaged | "Distroless image, `docker save` tarball" | Dockerfile exists but uses `debian:bookworm-slim`, **not distroless**. No `docker save` tarball. No image size on any slide. |

---

## Phase 0 Exit Gate Check

> *"A judge can pipe a FortiGate log file in and see OCSF JSON out, then retrieve any original line byte-exact."*

| Gate Item | Status | Notes |
|---|---|---|
| Cargo workspace + CI | ✅ | Workspace works. GitHub Actions CI exists. |
| End-to-end slice: syslog → vault → pack → OCSF → NDJSON | ✅ | `ulpf run` command does exactly this. |
| Raw Vault with `ulpf raw get <event_id>` | ✅ | Works. |
| OCSF 1.9 type generation in `build.rs` | ❌ | Types are hand-written, not generated. |
| Three packs (FortiGate, PAN-OS, Cisco ASA) | ⚠️ | FortiGate ✅, PAN-OS ✅, **Cisco ASA ❌** (missing). Have iptables and Snort instead. |
| Synthetic log generator | ❌ | Our `simulate_traffic.ps1` is a hack. The plan calls for a proper synthetic generator with configurable rates, burst patterns, and realistic multi-vendor output. `tools/gen_bench.py` exists but is for benchmarking, not synthetic generation. |
| Idea submission doc | ⚠️ | `docs/ARCHITECTURE.md` exists but it's not the idea submission format. |

---

## Phase 1 Exit Gate Check

> *"Twelve sources at 50k EPS sustained on a laptop, zero unbounded memory growth over a one-hour soak, Parquet readable by DataFusion."*

| Gate Item | Status |
|---|---|
| All 6 built-in decoders | ⚠️ Missing XML, LEEF |
| Full pack format with fixtures and `ulpf pack test` | ✅ Works. |
| Hot reload from watched directory | ❌ |
| Identification layer with prefilters and peer-binding cache | ⚠️ Identification works but no peer-binding cache |
| Arrow batching | ❌ No `arrow-rs` dependency at all |
| Parquet sink partitioned by date and event class | ⚠️ Parquet exists, not partitioned |
| Backpressure and bounded queues | ❌ |
| Pack library to 12 sources | ❌ Only 5 packs |
| 50k EPS sustained | ❌ Never benchmarked |

---

## Phase 2 Exit Gate Check

> *"An unseen log source goes from unparsed to a running, tested, approved pack in under five minutes, entirely offline."*

| Gate Item | Status |
|---|---|
| Drain clustering over dead-letter stream | ✅ Works. |
| Pack generator with GBNF-constrained drafting | ❌ LLM is mocked. No GBNF grammar. |
| Automatic scoring against held-out samples | ⚠️ `Scorer` exists but only runs fixtures, not held-out samples |
| Review-and-approve flow in console | ❌ UI button exists but no real review flow |
| `record_integrity` attestation and chaining | ✅ **Excellent implementation.** |
| `ulpf verify` command | ✅ Works. |
| Operator console | ✅ Beautiful and functional. |
| Sinks for OpenSearch, Splunk HEC, OTLP | ⚠️ OpenSearch ✅, Splunk HEC ✅, OTLP ❌ |
| docker-compose demo environment | ⚠️ compose.yaml exists for ULPF only. No OpenSearch/Wazuh in the stack. |
| 5-minute unseen-to-running timed demo | ❌ Cannot do this — LLM is mocked |

---

## What's Actually Strong (Give Devansh Credit)

1. **The integrity system** (`integrity.rs`) is genuinely impressive — 800 lines of hash chaining, signed checkpoints, 12 unit tests covering every attack vector. This is demo-ready and will impress judges.
2. **The decoder architecture** is clean and correct — the `Decoder` trait, the chain composition, and the tolerance for malformed input are all exactly right.
3. **The OCSF model** enforces required attributes at the type level and handles dotted paths correctly.
4. **The operator console** is genuinely beautiful and shows the pipeline internals, not just results.
5. **The sinks implementation** (Parquet, OpenSearch, Splunk HEC) uses raw TCP sockets to avoid heavy dependencies — a smart choice for the air-gap story.

---

## What to Do Next — Priority Order

> [!IMPORTANT]
> The hackathon deadline is December. Today is September 2. We have ~13 weeks. The build plan says the idea deadline is September 20 — **18 days away.**

### Immediate (This Week)

1. **Write the Cisco ASA pack** — the plan specifically names it as one of three Phase 0 packs. Should take 1-2 hours.
2. **Write a proper synthetic log generator** — a Python/Rust script that emits realistic FortiGate, PAN-OS, ASA, Snort, and CEF traffic with configurable rates. This unlocks all benchmarking and demo rehearsal.
3. **Fix the `simulate_traffic` script** — our current one works but the `/api/ingest` endpoint expects JSON `{"lines": "..."}`, not raw `text/plain`. It's probably failing silently with `x` marks.

### Next 2 Weeks (Phase 0 Exit Gate by Sep 20)

4. **Add 7 more packs** to reach 12: Cisco ASA, Squid Proxy, Cisco VPN, Juniper SRX, Check Point, Suricata, a WAF (ModSecurity or AWS WAF).
5. **Add XML and LEEF decoders** — needed for Check Point and IBM QRadar sources.
6. **Implement pack hot reload** — use `notify` crate to watch the packs directory.
7. **Build the `build.rs` OCSF codegen** — or decide to defend hand-written types under Q&A.

### Weeks 3–6 (Phase 1 + Phase 2 core)

8. **Integrate a real LLM** — download a Phi-4-mini or Qwen3-4B GGUF, set up `llama.cpp` as a sidecar, implement the real HTTP call in `llm.rs`.
9. **Add GBNF grammar** to constrain LLM output to valid pack YAML.
10. **Build the review-and-approve flow** in the console UI.
11. **Add the docker-compose demo stack** with OpenSearch (or Wazuh).
12. **Add Arrow batching and partitioned Parquet**.

### Weeks 7–10 (Phase 3)

13. **Benchmark harness** — the plan is specific: sustained EPS per format per core, p50/p99/p99.9 latency, RSS at steady state.
14. **Air-gap CI job**.
15. **Distroless Docker image + `docker save` tarball**.
16. **Fuzzing on all decoders**.

### Final 3 Weeks (Phase 4)

17. **Two-page architecture doc**.
18. **Five slides**.
19. **Two-minute video** — storyboarded in the plan, section 09.
20. **README quickstart tested on a clean machine**.
21. **Q&A drill on every rejected alternative in section 05**.

---

## Bottom Line

Devansh built the hard parts right. The pipeline architecture, the integrity system, and the decoder framework are all strong. But the project is **not Phase 0 complete**, and we've been wasting time on Git branch gymnastics and traffic simulator scripts instead of writing packs and building the synthetic generator.

The single most important thing right now is: **stop fiddling with infrastructure and start writing the packs and the synthetic generator that unlock everything else.**
