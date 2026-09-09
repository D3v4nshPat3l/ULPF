# Dataset expansion — brief

For whoever owns growing the real-data evidence this hackathon. One other
teammate is also touching datasets as a *secondary* task (pfSense
specifically, alongside her UI work — see `docs/UI-UPGRADE-BRIEF.md`).
**Check with her before starting on pfSense so the same work doesn't
happen twice.** Everything else below is yours.

Read [docs/CAPTURING-LOGS.md](CAPTURING-LOGS.md) in full before starting —
this brief assumes it. The short version: this project's whole credibility
argument is that every number comes from genuine, independent data, never
logs generated to match this project's own parser, and there are four
evidence classes (production capture > tool-generated-from-public-capture
> structure-verified-against-real-output > lab-generated) that must never
be blended into one percentage. Whatever is found this hackathon needs to
be filed under the correct class, not the most flattering one.

---

## What's already done — so nothing here gets duplicated

As of right now: 32 of 35 Source Packs have real-data evidence of some
kind. This session alone fixed real bugs by testing FortiGate, Cisco ASA,
Juniper SRX and Check Point's native-syslog mode against genuine captured
device output, confirmed PAN-OS clean with no changes needed, and
corrected real column-order/regex bugs in zeek-conn and modsecurity-waf-alert
using an actual MACCDC 2012 capture and a real ModSecurity/CRS container
run. Suricata was checked against a real 2016 exploit-kit capture replayed
through the real Emerging Threats ruleset. Full detail and exact commit
hashes: `git log --oneline` and the README's "Known limitations" section,
which is kept current — read that section fresh before assuming a pack is
still unverified, it may have changed since this brief was written.

---

## Target 1 — the cheapest, highest-value win: finish measuring Blue Coat

A Blue Coat ProxySG capture (8,130,590 records, genuine Honeynet traffic)
is already identified and its fetcher already exists
(`honeynet_bluecoat()` in `tools/fetch_datasets.py`) — it downloads the
**entire** file, not a prefix. What's incomplete is the *measurement*:
README and `docs/DATASETS.md` currently only quote a 398,380-record prefix
at 99.0148%, from an earlier, partial run. Running the full file is
mechanical, not new engineering:

```bash
python tools/fetch_datasets.py --tier large
python tools/measure_coverage.py --data realdata
```

This alone could roughly triple the single largest number in the whole
evidence table (838K → potentially ~8.1M additional real records) for the
cost of running two commands and updating a few numbers in README and
DATASETS.md. Two things to actually check, not assume:

- Does the full-file score hold up, or does scale surface something a
  398K-record sample didn't? If coverage drops on the full run, that's a
  real finding — investigate it the way this project's other real bugs
  were found (read a handful of the actual failing lines, don't guess),
  and fix the pack if the cause is genuine, not an artifact of measurement.
- `python tools/measure_coverage.py --data realdata --check` afterward, to
  confirm nothing else regressed.

Update README's coverage table, the "Known limitations" bullet, and
`docs/DATASETS.md`'s Blue Coat note with the real full-file number either
way — including if it's *lower* than the prefix suggested. A number that
moves down when measured more completely is exactly the kind of honesty
this project's docs already model (see the zeek-conn and Snort stories in
`docs/DATASETS.md` and `docs/COMPLETION_PLAN.md`).

## Target 2 — generic-cef-network pack

This is the one currently-unverified pack with the least specificity:
a fallback for any perimeter appliance emitting plain CEF with no
dedicated pack of its own. Read `packs/generic-cef-network.yaml` first —
its fixtures are almost certainly hand-typed from the CEF specification
(ArcSight's public *Common Event Format* guide), not real device output.

Real CEF output exists all over `elastic/integrations` (Elastic License
2.0 — structure-reference only, per the same discipline used for
FortiGate/ASA/Juniper this session; see
[CAPTURING-LOGS.md](CAPTURING-LOGS.md#the-commercial-appliances) for
exactly how that was handled and what to avoid). Search that repo for any
package whose test fixtures are CEF-formatted (`CEF:0|...`) rather than
vendor-native syslog — several products support CEF as an *alternate*
output mode, which is exactly what this generic pack needs evidence
against, since it isn't tied to one vendor's native format by design.

## Target 3 — Check Point's CEF configuration specifically

Check Point's Log Exporter native-syslog mode is already checked (this
session). Its **CEF** mode — a real, supported, different configuration —
still backs `packs/checkpoint-firewall.yaml` with documentation-derived
fixtures only. Same `elastic/integrations` `checkpoint` package likely has
a CEF-format test fixture alongside the native-syslog one already used;
check its `_dev/test/pipeline/` directory for a file that starts with
`CEF:0|Check Point|...` rather than the semicolon-bracket format the
native-syslog pack now handles.

## Target 4 — one genuinely new perimeter device (stretch, if time allows)

Growing *breadth* rather than just hardening what exists — but stay
inside the problem statement's actual scope. Read
[docs/PROBLEM-STATEMENT.md](PROBLEM-STATEMENT.md), section 2, before
picking a target: the Current Scope sentence is "perimeter network
device," and Windows Event Log, container logs, IoT telemetry and the
like are explicitly *not* what the demonstration is scored against, even
though the architecture is general enough to handle them eventually. A
new pack for something exotic reads worse to a judge than one more
well-evidenced perimeter pack — see `docs/PROBLEM-STATEMENT.md`'s own
argument for why. Reasonable candidates that stay in scope and don't
already have a pack: a VPN concentrator's connection log (distinct from
the firewall packs already covered), or a second, independent IDS/IPS
product beyond Snort/Suricata/Dragon.

If a real candidate and real data are both found, follow
[docs/PACK_GENERATOR.md](PACK_GENERATOR.md) — the heuristic/LLM-assisted
generator can draft a starting pack from real sample lines, which is
faster and less error-prone than writing detect/extract/map by hand.

## Target 5 — independent second-corpus cross-validation (stretch)

The single strongest piece of evidence this project already has is that
the **iptables** pack was written against one capture (SotM30) and then
scores near-100% on a completely different one (SotM34) it was never
tuned on — genuine cross-validation, not just a coverage number. Repeating
that pattern for another already-strong pack (Suricata, Snort, or Squid
are the best candidates — all three already have solid single-corpus
evidence) by finding a second, independent capture would be a
meaningfully stronger claim than the coverage percentage alone. `netresec.com`'s
PCAP index and other years of MACCDC (`archive.wrccdc.org/pcaps/`) are the
places to look — see `docs/CAPTURING-LOGS.md`'s PCAP sources table.

---

## The recipe — identical for every target above

Do not skip a step here; each one exists because skipping it let a real
bug through once already (see "The check that catches shadowing" in
CAPTURING-LOGS.md):

1. **Fetch** it via `tools/fetch_datasets.py`, in the right tier
   (`standard` for anything under ~200 MB, `large` for anything bigger —
   putting a big corpus in `standard` has previously exhausted a CI
   runner's disk mid-fetch).
2. **Register** it in `tools/measure_coverage.py`'s `PERIMETER` or
   `UNIVERSAL` list, and in `OPTIONAL_CORPORA` if it's large enough that a
   fresh clone shouldn't be forced to have it present.
3. **Measure before touching any pack**, and write the number down. The
   gap between that first number and the final one is the actual evidence
   that the corpus taught the project something — without it, there's no
   way to tell a real fix from a coincidence.
4. **Fix what the data actually shows**, not what the vendor manual says —
   read a handful of the real failing lines directly (`grep`, don't
   assume) before changing a pack.
5. **`python tools/measure_coverage.py --data <dir> --check`** — fails the
   run if any corpus (including ones unrelated to what changed) drops
   below its recorded baseline. Run this before committing, always.
6. **Record it honestly** in `docs/DATASETS.md` under the right evidence
   class, and update README's coverage table and "Known limitations" bullet
   if the headline numbers moved.

---

## Before pushing anything

- `cargo fmt --all`, `cargo clippy --workspace --all-targets --locked -- -D
  warnings`, `cargo test --workspace`, and `ulpf test --packs packs` —
  same four gates as every other change in this repo, dataset work
  included, since a pack fix touches real Rust-parsed YAML.
- Re-run `measure_coverage.py --check` (step 5 above) one more time
  immediately before committing, in case something changed since.
- If a headline number moved (record count, coverage percentage, pack
  count), grep the whole repo for the old number before committing —
  README, `docs/DATASETS.md`, `docs/DEMO-VIDEO-SCRIPT.md` and
  `docs/SLIDE-CONTENT.md` all quote these figures, and this project has
  already shipped one stale-number bug this session from a number that
  changed in one file and not the others. Don't repeat it.
