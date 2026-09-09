# UI upgrade — brief

For whoever owns the console UI this hackathon. Two work-streams: upgrade
the console's visual design, and grow the real-data corpus other teammates
are measuring packs against. They're bundled here because both feed the
same demo moment — a UI that looks considered, showing real numbers from
real data, is what "not a prototype" actually looks like on screen.

---

## Part 1 — The UI

### What exists right now, and why it looks the way it does

Two pages, both plain HTML/CSS/vanilla JS (no framework), compiled directly
into the binary:

- `crates/ulpf-cli/src/ui/index.html` (~1,700 lines) — the operator console.
  Six views behind a left nav rail: **Overview**, **Event inspector**,
  **Records needing a pack** (cluster browser), **Source Packs**,
  **Integrity**, **Assistant**.
- `crates/ulpf-cli/src/ui/dev.html` (~400 lines) — the traffic simulator
  used in the multi-machine demo (flip real corpora on/off, watch EPS).

**Read the CSS comment at the top of `index.html` before changing the
palette** — the light-only theme is a deliberate decision, not an
oversight:

> Light only, deliberately: this is an operator console that has to look
> the same on every machine in the room, and match the SIEM beside it.

Current tokens: `Inter` for UI text, `JetBrains Mono` for anything
tabular/numeric (locators, hashes, ports, timestamps), a blue primary
(`#006BB4`), and semantic success/warning/danger colors already wired
through the whole page. Reasonable questions to bring to the team before
changing this: does a *judge's* room actually need to match a real SOC's
lighting conditions, or is that constraint specific to an operational
deployment and safe to relax for a demo? Either answer is fine — just make
it a decision, not a default.

### How to actually iterate on it

The HTML is embedded at compile time via `include_str!` — there is **no
hot reload**. A pure layout/CSS pass is much faster done by opening
`crates/ulpf-cli/src/ui/index.html` directly in a browser (it'll complain
about missing data, but layout and style are visible immediately); once a
change needs real data wired up, `cargo build --release` (or a debug build,
faster to compile, slower to run) and restart `ulpf serve`.

### Concrete gaps worth targeting, ranked by demo impact

1. **The Merkle proof has no visual at all today** — `ulpf prove` /
   `verify-proof` are terminal-only (see the Integrity view and
   [docs/3-LAPTOP-DEMO.md](3-LAPTOP-DEMO.md)'s "Tamper evidence" section
   for what it currently does and says). This is the single most
   differentiating feature in the whole project and a judge sees it as
   scrolling JSON. A small hash-chain / Merkle-path diagram — even a
   simple one, a row of hash boxes with the proof path highlighted — would
   make the strongest technical claim in the pitch land visually instead
   of needing to be explained.
2. **Coverage and scale have no on-console visual** — the numbers driving
   the whole pitch (2,964,087 real records, 99.9679%, 10,000 EPS) live only
   in README tables today. A small persistent panel or a dedicated view
   showing these, ideally live during the multi-machine demo (EPS ticking
   up as multiple collectors run), turns a spoken number into something a
   judge watches happen.
3. **Two recently-added signals have no dedicated visual treatment yet** —
   worth checking what's already wired before designing from scratch:
   - `Cluster::specificity()` (in `crates/ulpf-generator/src/drain.rs`) —
     already surfaced as a plain pill in **Records needing a pack**, per
     `grep -n "specificity" crates/ulpf-cli/src/ui/index.html`. Worth a
     clearer visual (a small bar/gauge?) since it's the answer to "how do
     you know a draft pack will generalize."
   - `unknown_ocsf_paths` (in `crates/ulpf-generator/src/ocsf_paths.rs`) —
     surfaced as a warning pill (`rev-ocsf-warning` in the same file) when
     a generated pack targets a schema path neither generator was taught.
     Worth checking it reads clearly to someone who's never seen the code.
4. **If the custody-log feature lands** (another teammate's task —
   check the shared task board) **it needs a view of its own** — who
   retrieved what raw event, when. This is the feature that turns
   "tamper-evident" into "chain of custody" in the legal sense, and it's
   currently unbuilt *and* unvisualized.

### Style research — concrete places to look, not just "make it nicer"

This is a security operations console, not a consumer product — the
research should be domain-specific:

- **Real SIEM/SOC dashboards**, for information density and alert-list
  conventions: Elastic Security app, Splunk Enterprise Security, Wazuh's
  own dashboard (a teammate already has one running on Ubuntu — screenshot
  it), Grafana, OpenSearch Dashboards. Look specifically at how they use
  severity color (a fixed vocabulary — info/low/medium/high/critical —
  distinct from a brand accent color) and how dense a data table gets
  before it becomes unreadable.
- **Blockchain explorers**, for the integrity/proof visual specifically —
  Etherscan-style block-chain-of-blocks diagrams, a highlighted
  inclusion path, a "verified ✓" state. The project's own pitch leans on
  Certificate Transparency's Merkle-tree construction; a visual metaphor
  from that world (or from CT log explorers like crt.sh) fits the actual
  cryptography being shown, rather than inventing an unrelated one.
- **This project's own War Room artifact** (ask for the link if you don't
  have it) uses a different, more editorial palette (IBM Plex Sans/Mono,
  teal accent, dark-console feel) — deliberately not the same as the
  console, since it's a team reference doc, not the operator product. It's
  a reasonable example of *considered, non-templated* choices for this
  same subject matter, worth a look for the thinking even where the
  console's own constraints (light-only, match-the-SIEM-beside-it) point
  to different answers.

Whatever direction comes out of this, **bring 2–3 real screenshots and a
one-line rationale for each choice to the team before implementing** — a
palette swap that isn't grounded in "here's the SOC tool it's benchmarked
against" is exactly the generic-redesign trap the rest of this project
works hard to avoid (see how deliberately the coverage numbers and pack
evidence are sourced — the UI deserves the same discipline).

---

## Part 2 — Finding more real data

### Why this matters and what "real" means here

This project's whole credibility argument is that every number is measured
against genuine, independent data — not logs generated to match its own
parser. Read [docs/CAPTURING-LOGS.md](CAPTURING-LOGS.md) in full before
starting; it lays out four evidence classes (production capture >
tool-generated-from-public-capture > structure-verified-against-real-output
> lab-generated) and **why blending them into one percentage is exactly the
mistake to avoid**. Whatever is found needs to be filed under the correct
class, not the most flattering one.

### Sources already in use — know these before looking for new ones

- **Honeynet Project — Scan of the Month** (`honeynet.onofri.org/scans`) —
  genuine attack traffic from a live honeynet. Already backs iptables,
  Snort, Dragon, Squid, Apache, Linux syslog, Sendmail.
- **Loghub** (`github.com/logpai/loghub`) — curated production system logs.
  Already backs 12 non-perimeter corpora (HDFS, Spark, Android, etc.) plus
  a few perimeter ones.
- **secrepo.com** — already the source for a real MACCDC 2012 Zeek
  `conn.log` prefix.
- **`elastic/integrations`** (GitHub, Elastic License 2.0) — real captured
  device output shipped as Elastic's own pipeline test fixtures. Already
  used, **structure-reference only, never redistributed verbatim** — see
  the "Elastic License 2.0" discussion in
  [CAPTURING-LOGS.md](CAPTURING-LOGS.md#the-commercial-appliances) before
  using this source again; the same caution (check a repo's actual license
  for the *data* files, not just assume) applies to any new source.

### Where to look next — targeted at the packs still unproven

Three packs currently have zero real-traffic evidence (see README's "Known
limitations"): a generic CEF fallback, Check Point's *CEF* configuration
specifically (its native-syslog mode is already checked), and pfSense.
Also worth strengthening: anywhere the existing evidence is a small prefix
rather than a full corpus.

- **netresec.com → "PCAP files"** — a curated, actively maintained index of
  public packet captures, including malware traffic and CTF competition
  data. Good for any pack that needs a raw capture to replay through a real
  tool (the way Suricata's evidence was built this session), not
  pre-parsed logs.
- **Other MACCDC years** (the 2012 capture is already in use) — Western
  Regional CCDC archives at `archive.wrccdc.org/pcaps/` go back further and
  forward; a different year's capture would be an independent
  cross-validation of the Zeek/iptables/Snort packs, the same way this
  project already cross-validates iptables against two unrelated captures
  (SotM30 and SotM34).
- **pfSense specifically** — no public corpus is known to exist for
  `filterlog`. The realistic path is running actual pfSense (a free
  FreeBSD-based firewall OS) in a VM and pointing its syslog at a ULPF
  collector — genuine device output, lab-generated evidence class, same
  honesty standard as the ModSecurity pack's evidence this session. Needs
  a machine that can run a FreeBSD-based VM; check what's available in the
  team's hardware before committing time to this.
- **Check Point's CEF mode** — Log Exporter can be configured to emit CEF
  instead of its native syslog format (already checked). Check
  `elastic/integrations`' `checkpoint` package again for a CEF-format test
  fixture specifically, or Check Point's own CEF configuration
  documentation for a structure reference, following the exact discipline
  in [CAPTURING-LOGS.md](CAPTURING-LOGS.md) either way.

### How to actually add a corpus once found

Follow the existing recipe exactly — it's written down because skipping a
step here is how a real regression slipped through before (see
"The check that catches shadowing" in CAPTURING-LOGS.md):

1. Fetch it via `tools/fetch_datasets.py`, in the right tier (`standard` vs
   `large` — anything multi-hundred-MB goes in `large`).
2. Register it in `tools/measure_coverage.py`'s `PERIMETER` or `UNIVERSAL`
   list.
3. Measure coverage **before** touching any pack, and write the number
   down — the gap between that first number and the final one is the
   evidence a new source actually taught the project something.
4. After any pack change: `python tools/measure_coverage.py --data <dir>
   --check` — this specifically catches a new/changed pack silently
   stealing records from an unrelated corpus and then failing to parse
   them (it happened once already, to a Thunderbird pack colliding with
   ordinary Linux syslog).
5. Record the corpus, its evidence class, and what was found in
   [docs/DATASETS.md](DATASETS.md).

---

## Before pushing anything

- `cargo fmt --all`, `cargo clippy --workspace --all-targets --locked -- -D
  warnings`, `cargo test --workspace`, and `ulpf test --packs packs` — the
  same four gates every other change in this repo goes through, UI changes
  included.
- If a pack changed as part of the dataset work: re-run
  `measure_coverage.py --check` (above) before committing.
- Update README's coverage table and "Known limitations" section if the
  measured numbers moved — this repo has already shipped one stale-number
  bug this session (a coverage table that didn't get updated after a new
  corpus was added); don't repeat it.
