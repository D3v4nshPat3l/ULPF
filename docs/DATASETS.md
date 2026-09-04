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

Measured 4 September 2026 with 18 source packs, reproducible with
`python tools/measure_coverage.py`.

> An earlier revision of this table recorded the Dragon corpus at 29,925
> records against a total of 292,608. That count predated a re-fetch and
> understated the corpus: `tools/fetch_datasets.py` produces 42,899 Dragon
> records, all of which parse. The corrected total is larger and the
> weighted coverage marginally higher.

| Category | Source file | Origin | Records | Coverage |
|---|---|---|---:|---:|
| Firewall | `SotM34/iptables/iptablesyslog` | Honeynet SotM34 | 179,752 | 100.0000% |
| IDS | `SotM34/snort/snortsyslog` | Honeynet SotM34 | 69,039 | 99.9986% |
| IDS | `dragon-nids.log` | Honeynet Dragon capture | 42,899 | 100.0000% |
| Web | `SotM34/http/access_log*` | Honeynet SotM34 | 3,554 | 99.9719% |
| Web | `Apache_2k.log` | Loghub Apache | 2,000 | 100.0000% |
| Auth | `OpenSSH_2k.log` | Loghub OpenSSH | 2,000 | 100.0000% |
| Host | `SotM34/syslog/messages*` | Honeynet SotM34 | 1,166 | 94.2539% |
| Host | `Linux_2k.log` | Loghub Linux | 2,000 | 96.4500% |
| Mail | `SotM34/syslog/maillog*` | Honeynet SotM34 | 1,172 | 98.7201% |
| Proxy | `Proxifier_2k.log` | Loghub Proxifier | 2,000 | 81.1000% |
| **Total** | | | **305,582** | **99.8256%** |

A separate 307,524-record iptables capture (`SotM30-anton.log`) is used for
pack development. The SotM34 iptables figure above is therefore genuine
cross-validation: that pack was written against SotM30 and never tuned on
SotM34.

## What the remaining misses are

They are named rather than rounded away.

- **Proxifier, 18.9%** — the corpus contains many non-connection lines
  (lifetime summaries, DNS resolution notices, program start banners) that are
  not network events. The pack claims connection records only.
- **Loghub Linux, 3.6%** and **Honeynet syslog, 5.7%** — a long tail of daemon
  messages from programs with no pack. Each is still vaulted, fingerprinted and
  emitted as a schema-valid record.
- **Snort, 1 record of 69,039** — a genuinely corrupt line in the source data:
  `213.158.110.22.-> 11.11.79.73`, a stray dot where a space belongs.
- **Apache access, 1 record of 3,554** — a truncated request line.

Nothing is discarded. An unparsed record still enters the vault, receives a
fingerprint, joins the attestation chain, and is emitted as valid OCSF carrying
its raw text. "Unparsed" is a routing decision, never data loss.

## Reproducing this

```bash
python tools/fetch_datasets.py          # downloads and prepares ../realdata
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
