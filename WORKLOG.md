# ULPF — Judge-Readiness Work Log

Working document for the cleanup/verification pass. Tracks every decision and
every change, phase by phase. **This file is temporary**: its outcome is folded
into `CHANGELOG.md` in the final phase and the file itself is removed, because a
work log is exactly the kind of internal artifact this pass exists to delete.

Branch: `main` (pushed at the end of every phase).

---

## Baseline — measured 2026-09-10, before any change

Established by actually running the toolchain, not by reading the README.

| Check | Command | Result |
|---|---|---|
| Debug build | `cargo build --workspace --locked` | **clean** |
| Release build | `cargo build --release --locked` | **clean** |
| Formatting | `cargo fmt --all --check` | **clean** |
| Lints | `cargo clippy --workspace --all-targets --locked -- -D warnings` | **clean, 0 warnings** |
| Unit/integration tests | `cargo test --workspace --locked` | **390 passed, 0 failed** |
| Pack fixtures | `ulpf test --packs packs` | **35 packs · 75/75 fixtures · 100.0% field accuracy** |

Toolchain present: rustc 1.98.1, cargo 1.98.1 (MSRV declared 1.85), Python
3.12.10, git 2.54.0.

**There are no build, lint, format or test errors in the tree as cloned.**
"Fix all errors" therefore means the defects that a green build does not catch:
factual drift between documentation and behaviour, stale numbers, dead
cross-references, and content that assumes hardware we are not going to use.

### Errors actually found in the baseline

| # | Defect | Where | Class |
|---|---|---|---|
| E1 | `/readyz` sample response claims `"packs_loaded":34`; the tree ships 35 packs and `ulpf test` reports 35 | `README.md` | stale doc |
| E2 | Prose says "Ten decoders ship in the box" then lists 10 names, while `packs/` and the decoder registry need re-confirming against `ulpf decoders` | `README.md` | unverified claim |
| E3 | Coverage/throughput headline figures appear in 13 files; none re-verified on this machine | `README.md`, `docs/*`, `docs/*.html` | unverified claim |
| E4 | Repo root carries `one.json` and `proof.json` — CLI output from a past run committed as if source | repo root | clutter |
| E5 | Six documents and three scripts describe a three-laptop demonstration that will not be used | `docs/`, `tools/` | wrong target |
| E6 | Two stale PDFs and two stale HTML guides carry headline numbers, are linked from nothing, and cannot be regenerated from the tree | `docs/` | contradiction risk |
| E7 | Dataset fetcher is capped by a four-tier system, a 50 MB byte-range prefix on the Zeek corpus, and opt-in flags on the two largest corpora | `tools/fetch_datasets.py` | not wanted |

---

## Disk budget

| Volume | Free | Role |
|---|---|---|
| `E:` | 78 GB | repo + `realdata/` corpora |
| `C:` | 59 GB | `tempfile.mkdtemp` scratch used by `measure_coverage.py` |

Full published corpus set is roughly **81 GB extracted**. The agreed target is
about **60%**, so the budget is **~48 GB on E:**, chosen corpus by corpus with a
live `df` check before each fetch. Thunderbird (29.6 GB extracted) is the single
largest item and is the first candidate to drop. Whatever is not fetched is
reported as **not measured**, never estimated.

---

## Phases

### Phase 0 — Analysis and plan  ·  status: **done**
Deep read of the tree, baseline measured, defects enumerated, budget set.
Deliverable: this file. Push.

### Phase 1 — Dataset fetcher: remove every guardrail  ·  status: pending
- Delete the four-tier system; the script fetches **everything** by default.
- Replace the Zeek 50 MB byte-range prefix with the full corpus fetch.
- Remove the "large tier only" gate on Blue Coat and the `--full-zeek` opt-in.
- Keep only *operational* controls that are not caps on the data: `--dir`,
  resume-on-failure, and a `--skip` escape hatch for a corpus whose host is
  down. These do not limit what a default run downloads.
- Stream to disk and delete each archive after extraction so peak usage is one
  archive plus one extracted corpus, never the whole set twice.
- Update `tools/measure_coverage.py` so nothing is special-cased as
  "legitimately absent by tier"; a corpus is either measured or reported
  missing by name.
- Push.

### Phase 2 — Repo cleanup  ·  status: pending
Removals (git history retains everything):

| Path | Reason |
|---|---|
| `docs/3-LAPTOP-DEMO.md` | single-laptop target |
| `docs/DEPLOYMENT-3-LAPTOP.md` | single-laptop target |
| `docs/demo-machine-a.md`, `-b.md`, `-c.md` | single-laptop target |
| `tools/demo-switch.ps1`, `tools/switch-to-ulpf.bat`, `tools/switch-to-wazuh.bat` | three-laptop demo-day traffic switch |
| `docs/COMPLETION_PLAN.md` | internal roadmap and competitive analysis |
| `docs/UI-UPGRADE-BRIEF.md` | internal work brief |
| `docs/DATASET-EXPANSION-BRIEF.md` | internal work brief |
| `docs/SLIDE-CONTENT.md`, `docs/DEMO-VIDEO-SCRIPT.md` | submission-prep, not product documentation |
| `animation/` | Manim video-production scenes; needs its own venv, builds nothing |
| `docs/ULPF-Complete-Guide.pdf`, `docs/ULPF-Faculty-Brief.pdf` | stale numbers, unlinked, not regenerable from the tree |
| `docs/faculty-brief.html`, `docs/study-guide.html` | same, and duplicate the README |
| `one.json`, `proof.json` | stray CLI output at repo root |

Kept deliberately: `schema/ocsf/` (the air-gap claim depends on it),
`docs/screenshots/`, `testdata/mixed.log` (labelled synthetic quick start),
`deploy/` (all three compose files are single-host), `.github/`, and the
governance files.

Then: purge every dangling reference to a removed path, and fix the
`tls.rs` comment that points at `docs/3-LAPTOP-DEMO.md`. Push.

### Phase 3 — Single-laptop demo path  ·  status: pending
Write `docs/DEMO.md`: one machine, one binary, start to finish — build, fetch,
serve, simulate, inspect, tamper, verify, prove. Every command executed on this
machine before it is written down. Push.

### Phase 4 — Fetch and measure for real  ·  status: pending
Run the un-guardrailed fetcher inside the disk budget, then
`tools/measure_coverage.py`, then the throughput measurement. Record what was
actually fetched, what was skipped and why, and the exact figures produced.
Push the recorded evidence.

### Phase 5 — Documentation rewrite against measured reality  ·  status: pending
Rewrite `README.md` and every surviving doc so that each number is one measured
in Phase 4 on this machine, each link resolves, and no text assumes hardware or
files that no longer exist. Anything not re-measured is labelled as such. Push.

### Phase 6 — Final verification  ·  status: pending
Re-run the complete baseline suite plus a link check over the tree, fold this
log into `CHANGELOG.md`, delete this file, push.

---

## Change log

### Phase 0
- Cloned the repository and measured the baseline above.
- No source changes.
