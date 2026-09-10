# Real dataset protocol

Coverage claims must come from authentic, unmodified telemetry. Synthetic logs
are useful only for repeatable load testing and are never presented as coverage
evidence.

Every figure in this document was produced by running the commands below
against files downloaded from the public sources named. Nothing was cleaned,
filtered, reordered or regenerated.

## Sources

Two public collections, both freely redistributable for research:

**Honeynet Project — Scan of the Month.** Captures from a live honeynet, so the
traffic is genuine attack traffic rather than lab noise.
<https://honeynet.onofri.org/scans/index.html> ·
mirror <http://log-sharing.dreamhosters.com/>

**Loghub.** A curated collection of production system logs maintained for log
analysis research. <https://github.com/logpai/loghub>

## Corpus and measured coverage

Measured with 35 source packs, reproducible with
`python tools/measure_coverage.py`.

Two tables, deliberately. The first answers the problem statement's Current
Scope sentence and is the figure quoted in the README; the second answers
"does the framework hold outside the perimeter", which the word *universal*
in its name invites a reviewer to ask. Blending them would let a
non-perimeter source move the headline number.

### Perimeter and edge sources — the headline figure

| Category | Source file | Origin | Records | Coverage |
|---|---|---|---:|---:|
| Firewall | `iptables.log` | Honeynet SotM34 | 179,752 | 100.0000% |
| IDS | `snort.log` | Honeynet SotM34 | 69,039 | 99.9986% |
| IDS | `dragon-nids.log` | Honeynet Dragon | 42,899 | 100.0000% |
| Proxy | `squid-access.log` | Honeynet | 533,197 | 99.9771% |
| Proxy | `bluecoat-proxy.log` | Honeynet, full capture | 8,130,590 | 99.8033% |
| Network | `zeek-conn.log` | SecRepo (MACCDC 2012) | 2,125,308 | 99.9861% |
| Web | `apache-access.log` | Honeynet SotM34 | 3,554 | 99.9719% |
| Web | `Apache_2k.log` | Loghub | 2,000 | 100.0000% |
| Auth | `OpenSSH_2k.log` | Loghub | 2,000 | 100.0000% |
| Host | `linux-messages.log` | Honeynet SotM34 | 1,166 | 99.8285% |
| Host | `Linux_2k.log` | Loghub | 2,000 | 99.9500% |
| Mail | `sendmail.log` | Honeynet SotM34 | 1,172 | 100.0000% |
| Proxy | `Proxifier_2k.log` | Loghub | 2,000 | 100.0000% |
| **Total** | | | **11,094,677** | **re-measure pending** |

The per-corpus figures above are each measured. The aggregate is not restated
here because the Proxifier fix changed one of its inputs and the full sweep has
not been re-run since — Blue Coat alone exceeds the 30-minute cap. It was
99.8485% before that fix and can only have risen; quoting a number we have not
measured, in a table whose whole purpose is that every number was measured,
would be the wrong trade.

`zeek-conn.log` is counted in the total above — it has been fetched and
measured, unlike Blue Coat, which has not (see note). Both are `OPTIONAL_CORPORA`
in `tools/measure_coverage.py`: counted when present, silently excluded from
the denominator when absent, so the total above is exactly what
`python tools/measure_coverage.py` prints right now, not a fixed constant.

**Blue Coat note.** The ProxySG capture is 8,130,590 records and ~2.6 GB
extracted, so it sits in the `large` tier rather than `standard`: putting it in
`standard` exhausted the disk on a GitHub-hosted runner and the coverage
workflow died mid-fetch. Fetch it with
`python tools/fetch_datasets.py --tier large`.

The full file has now been run end to end: **8,130,590 records at 99.8033%**,
and it is in the table above rather than in a footnote. Earlier revisions of
this document quoted a 398,380-record prefix at 99.0148% and excluded the
corpus from the total, because quoting a prefix as if it were the whole file
would have been an extrapolation.

Folding it in moves the perimeter aggregate from 99.9679% down to 99.8485%.
That is the correct direction and worth stating plainly: the older, higher
figure was the average of a set that left out the largest and hardest corpus
in it. `measure_coverage.py` still reports the corpus as absent and computes
the total without it on a machine where it has not been fetched.

**Zeek conn.log note.** `zeek-conn` was one of the nine packs the README used
to list as unverified — its column order came from a general description of
`conn.log`, not a real capture, and turned out to be wrong: real Zeek/Bro
output puts `missed_bytes`, `history` and the packet/byte counts immediately
after `conn_state`, with one `local_orig` before that and a trailing
`tunnel_parents` set, not the `local_orig`/`local_resp` pair the old order
assumed there. `src_endpoint`, `dst_endpoint`, `connection_info.protocol_name`,
the byte counts and `conn_state` all sat before that split and were never
wrong; what the old order got wrong was `history` and both packet counts,
silently reading one column over from where real data puts them — the exact
"coverage stays high while specific fields are quietly wrong" failure mode
this project has hit before (Apache/Squid method IDs).

The full MACCDC 2012 `conn.log` is ~524 MB compressed (~2.6 GB extracted),
the same order of magnitude as Blue Coat, so `fetch_datasets.py` fetches a
bounded byte-range prefix in the `large` tier rather than the whole file — a
**2,125,308-record prefix scores 99.9861%** with the corrected column order.
Like Blue Coat, this is not extrapolated to the full file, and
`measure_coverage.py` reports the corpus as absent rather than failing when
it has not been fetched.

### Sources outside the Current Scope sentence

Measured on the Loghub 2,000-line excerpts. Full corpora — up to 211 million
lines — are fetched with `--tier large` or `--tier xl`.

| Category | Source | Records | Coverage |
|---|---|---:|---:|
| Big data | HDFS | 2,000 | 86.8500% |
| Big data | Hadoop YARN | 2,000 | 99.8000% |
| Big data | Spark | 2,000 | 98.0500% |
| Big data | ZooKeeper | 2,000 | 77.9500% |
| HPC | Blue Gene/L RAS | 2,000 | 96.3500% |
| HPC | Thunderbird | 2,000 | 100.0000% |
| HPC | HPC node state | 2,000 | 96.9000% |
| Cloud | OpenStack Nova | 2,000 | 87.4500% |
| Host | Windows CBS | 2,000 | 98.9500% |
| Host | macOS system | 2,000 | 96.0500% |
| Mobile | Android logcat | 2,000 | 99.8500% |
| Mobile | HealthApp | 2,000 | 93.8000% |
| **Combined, all sources** | | **11,118,677** | **99.8366%** |

A separate 307,524-record iptables capture (`SotM30-anton.log`) is used for
pack development. The SotM34 iptables figure above is therefore genuine
cross-validation: that pack was written against SotM30 and never tuned on
SotM34.

### What real data changed

Every pack in the second table was written against lines printed from the
corpus itself, and each was measured immediately afterwards. The gap between
the two numbers is the reason this document exists:

| Pack | Own fixtures | First real-corpus run | After correction |
|---|---:|---:|---:|
| HPC node state | 100% | 5.25% | 96.90% |
| Spark | 100% | 28.65% | 98.05% |
| Android logcat | 100% | 36.95% | 99.85% |
| Thunderbird | 100% | 35.80% | 97.80% |
| Squid (rewritten) | 100% | 57.23% | 99.98% |
| Blue Coat (rewritten) | 100% | 0% | 99.01% |

In every case the pack passed its own fixtures completely and then failed on
real traffic, because a fixture proves only that a pack parses a line its
author chose. The Blue Coat pack is the clearest: its field order came from
the vendor manual, and the corpus's own `#Fields:` header showed the manual
was wrong in two places, so the documentation-derived pattern matched none of
the 8.1 million records.

## Held on disk, not yet run end to end

Fetching every corpus is not the same as having measured every corpus, and
this section exists so the difference is stated rather than left for a reader
to discover.

`tools/fetch_datasets.py` retrieves all nineteen archives in the Loghub
deposit. Five of them are far larger than anything in the coverage tables
above, and they have **not** been run through the pipeline. They are on disk,
they are real, and they are available to anyone who wants to reproduce a run
over them — but no figure in this project is measured on them.

| Corpus | What it is | Records | On disk | Estimated run |
|---|---|---:|---:|---:|
| Thunderbird | HPC cluster syslog | 211,212,192 | 31.8 GB | ~4.4 h |
| Windows | Windows CBS servicing | 114,608,388 | 28.0 GB | ~2.4 h |
| Spark | Spark executor | 33,236,604 | 2.9 GB | ~0.7 h |
| HDFS v1 | HDFS DataNode | 11,175,629 | 1.6 GB | ~0.2 h |
| Blue Gene/L | Supercomputer RAS | 4,747,963 | 0.7 GB | ~0.1 h |
| **Total** | | **374,980,776** | **65.1 GB** | **~7.8 h** |

Record counts are the figures the Loghub deposit publishes for each corpus.

**The estimated run column is arithmetic, not a measurement.** It is the
record count divided by 13,290 events/sec, which is the rate measured on this
machine over the Blue Coat capture — 8,130,590 real records, the largest
corpus that *has* been run end to end. It is offered so a reader can see what
reproducing these would cost, and for no other purpose. It is not a coverage
claim, and no coverage number anywhere in this project is derived from it.

Running any of them is one command:

```bash
python tools/measure_coverage.py --set universal
```

Two notes on doing that. The scratch space each run needs is a fraction of the
corpus but still gigabytes at this scale, so `--work-dir` should point at a
volume with room. And the per-corpus timeout defaults to ten hours precisely
because Thunderbird needs most of an afternoon.

## What the remaining misses are

They are named rather than rounded away.

- **Proxifier — was 18.9%, now none.** This entry used to explain the shortfall
  as non-connection lines the pack deliberately ignored. That explanation was
  wrong, and worth recording as wrong: the 378 missing records were connection
  closes, which the pack was always meant to claim and whose extraction
  patterns already handled them correctly. The detector was matching the
  literal `.exe - `, and Proxifier writes `chrome.exe *64 - host:443 close`
  when the process carries an architecture suffix, so that run of text never
  occurs and every such line was handed to the unknown-log path. Widening the
  detector to the shape of the line takes the corpus from 81.1000% to
  100.0000%. A design decision and an unnoticed bug read identically from the
  outside, which is why the shortfall survived this long.
- **Loghub Linux, 1 record of 2,000** and **Honeynet syslog, 2 of 1,166** — a
  long tail of daemon messages from programs with no pack. Each is still
  vaulted, fingerprinted and emitted as a schema-valid record. (The 3.6% and
  5.7% quoted here previously predated the syslog-tag detector and the
  repeated-message pack, and were never re-measured after either landed.)
- **Snort, 1 record of 69,039** — a genuinely corrupt line in the source data:
  `213.158.110.22.-> 11.11.79.73`, a stray dot where a space belongs.
- **Apache access, 1 record of 3,554** — a truncated request line.

Nothing is discarded. An unparsed record still enters the vault, receives a
fingerprint, joins the attestation chain, and is emitted as valid OCSF carrying
its raw text. "Unparsed" is a routing decision, never data loss.

## Reproducing this

```bash
python tools/fetch_datasets.py          # downloads and prepares realdata
cargo build --release --locked
python tools/measure_coverage.py        # prints the table above
```

The corpora are not committed to this repository. They total roughly 150 MB,
they are independently available from the sources above, and vendoring them
would silently relicense third-party data.

## Why real data, not documentation samples

Writing a pack from a vendor manual produces a pack that handles the manual.
Three concrete examples from this corpus, each of which a documentation-derived
test would have passed while the pack failed in production:

- The first Snort pack scored **69.3%**. The 31% it missed were preprocessor
  alerts — Spade, stream4, http_inspect — which emit neither the
  `[Classification:]` nor `[Priority:]` block the detector keyed on.
- The first iptables pack failed on stock kernel logging. A default
  `iptables LOG` rule with no `--log-prefix` emits a printk uptime and no
  verdict at all, while every pattern required one.
- The first Apache pack missed exploit probes, because a request such as
  `"GET /scripts/..%255c../winnt/system32/cmd.exe?/c+dir"` omits the HTTP
  version entirely — and those are precisely the records worth keeping.

Real data also exposed three gaps in the engine itself: no CLF timestamp
format (Apache, nginx, every reverse proxy), no RFC 3164 timestamp format
(carries no year), and enum lookups that only matched strings, so any pack
branching on a numeric code silently fell through to its default.
