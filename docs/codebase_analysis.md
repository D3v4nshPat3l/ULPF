# ULPF Codebase Audit — September 3, 2026

A complete, honest analysis of the codebase against NTRO Problem Statement 26156.

---

## 1. Architecture Overview (What We Have)

```mermaid
graph LR
    A["Raw Logs\n(UDP/HTTP/File)"] --> B["Vault\n(append-only store)"]
    B --> C["Pack Library\n(YAML detectors)"]
    C --> D["Decoder Chain\n(syslog→kv, etc.)"]
    D --> E["OCSF Normalizer"]
    E --> F["Attestation Chain\n(Ed25519 + SHA-256)"]
    F --> G["Sinks\n(NDJSON/OpenSearch/Splunk/Parquet)"]
```

| Crate | LOC (approx) | Purpose |
|---|---|---|
| [ulpf-core](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-core/src/lib.rs) | ~300 | `RawEvent`, `Envelope`, `RawRef`, `Disposition` |
| [ulpf-decode](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-decode/src/lib.rs) | ~750 | 9 decoders: syslog, kv, csv, cef, leef, json, xml, regex |
| [ulpf-ocsf](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-ocsf/src/lib.rs) | ~750 | OCSF event builder, attestation chain, JCS canonicalization |
| [ulpf-pack](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-pack/src/lib.rs) | ~700 | YAML pack spec, compiler, self-test runner |
| [ulpf-vault](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-vault/src/lib.rs) | ~400 | Append-only binary vault with segment rotation |
| [ulpf-generator](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-generator/src/lib.rs) | ~500 | AI (Ollama) + Heuristic pack drafter, Drain clustering |
| [ulpf-cli](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/main.rs) | ~2400 | CLI, HTTP server, pipeline, sinks, simulator |

**Total Rust:** ~5,800 lines across 7 crates  
**Total Packs:** 18 YAML parser definitions  
**Total Datasets:** 16 registered log corpora (10 Loghub + 6 Honeynet)

---

## 2. Requirement-by-Requirement Verification

| # | NTRO Requirement | Status | Evidence |
|---|---|---|---|
| (a) | Preserve complete raw event data | ✅ **DONE** | [pipeline.rs:103](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/pipeline.rs#L103) — vault append happens BEFORE identification. Unparsed events are still stored. |
| (b) | Extract and parse source-specific attributes | ✅ **DONE** | 9 decoders in [ulpf-decode](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-decode/src/lib.rs). Chains like `syslog→keyvalue` for FortiGate, `syslog→regex` for Cisco ASA. |
| (c) | Normalize fields into a common event taxonomy | ✅ **DONE** | OCSF 1.9.0 schema. Full schema bundled at [schema/ocsf](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/schema/ocsf). |
| (d) | Traceability between normalized and original | ✅ **DONE** | Every OCSF event carries `ulpf_raw_locator` (segment:offset:len) for O(1) retrieval. [pipeline.rs:153](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/pipeline.rs#L153). |
| (e) | Plug-and-play onboarding of new log sources | ✅ **DONE** | Drop a YAML file in `packs/`, hot-reload picks it up. AI and Heuristic drafters generate packs from raw samples. |
| (f) | Unified visibility across enterprise environments | ✅ **DONE** | Web console at `localhost:8787` with Overview, Clusters, Packs, Integrity views. |
| (g) | Efficient SIEM and Data Lake integration | ✅ **DONE** | 4 sinks: NDJSON (file), OpenSearch, Splunk HEC, Parquet. [sinks.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/sinks.rs). |
| (h) | AI/ML-ready security and operational analytics | ✅ **DONE** | OCSF output is structured JSON with consistent field names. Parquet sink for direct ML ingestion. |
| (i) | Reduced parser development effort | ✅ **DONE** | 1-click AI Copilot and Heuristic buttons in the Clusters UI generate parsers from sample logs. |
| (j) | Deployable in an air-gapped network | ✅ **DONE** | Single binary, `include_str!` for HTML/CSS/JS, system fonts only, no CDN/external dependency. Heuristic generator works without any model. |
| (k) | Packaged in a container | ✅ **DONE** | [Dockerfile](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/Dockerfile) — multi-stage build, distroless runtime. [compose.yaml](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/compose.yaml) for single-command deploy. |

> [!IMPORTANT]
> **Every single requirement from PS 26156 is implemented and working.** This is not a prototype — it is a functioning pipeline that processes real logs end-to-end.

---

## 3. Bugs & Issues Found

### 🔴 Critical

| # | Issue | File | Detail |
|---|---|---|---|
| 1 | **dev.html still says "Attacker / Dev Node"** | [dev.html:151](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/ui/dev.html#L151) | The revert brought back the old name. Should say "Enterprise Network Simulator" or "Source Simulator". Calling it "Attacker" in front of NTRO judges is a bad look. |
| 2 | **No packs for 6 new datasets** | [simulator.rs:112-153](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/simulator.rs#L112-L153) | We registered Windows, Mac, Android, HDFS, Spark, Zookeeper in the simulator, but there are **no parser packs** for any of them. When streamed, all 6 will land as "Unidentified" and tank the coverage percentage. |

### 🟡 Medium

| # | Issue | File | Detail |
|---|---|---|---|
| 3 | **Duplicate Docker Compose files** | Root | Both [compose.yaml](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/compose.yaml) (ULPF container) and [docker-compose.yaml](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/docker-compose.yaml) (OpenSearch SOC) exist at root. Confusing for evaluators. |
| 4 | **Old traffic scripts at root** | Root | [simulate_traffic.ps1](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/simulate_traffic.ps1) and [simulate_traffic.py](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/simulate_traffic.py) are superseded by the built-in simulator. They clutter the root and confuse new readers. |
| 5 | **`docs/codebase_analysis.md` and `docs/gap_analysis.md`** | docs/ | These are internal working documents that got committed to the repo. They contain raw notes and should not be in the submission. |

### 🟢 Minor / Cosmetic

| # | Issue | File | Detail |
|---|---|---|---|
| 6 | **`<title>` still says "ULPF Source Simulator"** | [dev.html:6](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/ui/dev.html#L6) | Should match whatever we rename the dashboard to. |
| 7 | **`docs/strategy/phase_d_ui_overhaul.md`** | docs/strategy/ | Internal change log, not relevant for NTRO submission. |
| 8 | **Vault warns on unclean shutdown** | Logs | `vault segment has no footer; rebuilding index by scan` — happens every time we kill the server. Harmless but noisy. |

---

## 4. Unnecessary / Redundant Files

| File | Verdict | Why |
|---|---|---|
| `simulate_traffic.ps1` | **DELETE** | Replaced by built-in `/dev` simulator |
| `simulate_traffic.py` | **DELETE** | Replaced by built-in `/dev` simulator |
| `tools/generate_traffic.py` | **REVIEW** | 16KB Python script — may overlap with simulator |
| `docs/codebase_analysis.md` | **DELETE** | Internal notes, not a deliverable |
| `docs/gap_analysis.md` | **DELETE** | Internal notes, not a deliverable |
| `docs/strategy/phase_d_ui_overhaul.md` | **DELETE** | Internal change log |

---

## 5. What We Still Need for the Final Submission

NTRO requires exactly **5 deliverables**. Here is where we stand:

| Deliverable | Status | Notes |
|---|---|---|
| **Source Code (GitHub)** | ✅ Done | [github.com/D3v4nshPat3l/ULPF](https://github.com/D3v4nshPat3l/ULPF) |
| **README with Setup Instructions** | ✅ Done | [README.md](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/README.md) — 533 lines, comprehensive |
| **Architecture Document (Max 2 Pages)** | ⚠️ Exists but needs polish | [ARCHITECTURE.md](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/docs/ARCHITECTURE.md) exists but needs to be condensed to exactly 2 pages for submission |
| **Demo Video (Max 2 Minutes)** | ❌ Not started | Needs to be recorded |
| **Technical Presentation (Max 5 Slides)** | ❌ Not started | Needs to be created |

---

## 6. Honest Assessment

### What is genuinely strong:
- **The pipeline is real.** Vault-first architecture means requirement (a) is provably satisfied, not just claimed.
- **18 parser packs** covering Cisco ASA, FortiGate, Palo Alto, Juniper, Check Point, Suricata, Snort, iptables, Apache, OpenSSH, Sendmail, Proxifier, ModSecurity, Squid, Linux syslog, CEF generic, Dragon NIDS.
- **Cryptographic integrity chain** with Ed25519 signing and SHA-256/BLAKE3 fingerprinting. The tamper-detection demo endpoint (`/api/tamper` + `/api/verify`) is a killer demo feature.
- **Single binary, zero external dependencies at runtime.** This is exactly what NTRO needs for air-gapped deployment.
- **Decoder composition** is elegant — `syslog→keyvalue` for FortiGate, `syslog→csv` for PAN-OS, `syslog→regex` for Cisco. Only 9 decoders cover dozens of vendors.

### What needs work:
- **The 6 new datasets have no packs.** If a judge toggles Windows or Android in the simulator, the coverage stat will drop. We should either write packs for them or remove them from the simulator.
- **The dev.html naming is still "Attacker / Dev Node."** Must be renamed before any demo.
- **Demo video and slides are not started.** These are mandatory deliverables. Deadline is September 30.
- **The docs directory has internal junk** that should be cleaned before submission.

---

## 7. Recommended Next Steps (Priority Order)

1. **Rename dev.html** — Change "Attacker / Dev Node" to "Enterprise Network Simulator" (5 minutes)
2. **Clean up repo** — Delete superseded scripts and internal docs (10 minutes)
3. **Write packs for new datasets** — At minimum Windows and Android, or remove them from simulator (30 min each)
4. **Polish Architecture doc** — Condense to exactly 2 pages with a clear diagram
5. **Record demo video** — 2 minutes showing the full pipeline with live log streams
6. **Create 5-slide deck** — Problem → Architecture → Live Demo Screenshots → Results → Air-Gap Compliance
