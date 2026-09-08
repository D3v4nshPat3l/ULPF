# Capturing real logs

Nine of the thirty-four Source Packs pass fixtures written from vendor
documentation and have never seen real traffic. This document is how to fix
that, and why it is worth the effort.

## Why documentation is not evidence

Three times in this project a pack scored 100% on its own fixtures and then
failed on real data:

| Pack | Own fixtures | First real corpus | Cause |
|---|---:|---:|---|
| HPC node state | 100% | 5.25% | detector keyed on two of six subsystems |
| Spark | 100% | 28.65% | detector enumerated seven of a long tail of classes |
| Android logcat | 100% | 36.95% | detector enumerated nine of ~40 tags |
| Squid | 100% | 57.23% | assumed dotted-quad clients; the corpus uses hostnames |
| **Blue Coat** | **100%** | **0%** | **the vendor manual's field order is wrong** |

The Blue Coat case is the one to remember. Its pattern came from the ProxySG
documentation's description of the `main` log format. The corpus's own
`#Fields:` header — written by the device — disagrees in two places, and the
documentation-derived pattern matched **none** of 8,139,422 records.

A fixture proves a pack parses a line its author chose. Nothing more.

## The cheapest real data: run the software yourself

Four of the ten unproven packs are for **open-source** software. You do not
need to find someone else's logs; run the real program and it writes real logs.
That output is genuine vendor output — it came from the program that writes
that format, not from a manual.

### Suricata — done

```bash
sudo apt install suricata          # or: brew install suricata, or docker pull jasonish/suricata
suricata-update                    # fetches the real ~68,600-rule Emerging Threats Open ruleset
suricata -r capture.pcap -l ./out -S ./rules/suricata.rules  # produces out/eve.json
```

`eve.json` is exactly what the `suricata-eve-alert` pack expects. Any public
capture works; see the PCAP sources below.

Done, via `jasonish/suricata` in Docker against
`chrissanders/packets`' `ek_to_cryptowall4.pcapng` (real 2016 exploit-kit
traffic, github.com/chrissanders/packets) with a real `suricata-update`
ruleset. Two named PCAPs from that same small, individually-downloadable
repository are worth remembering as a source for other packs needing a raw
capture rather than pre-parsed logs: most files there are named for what
they contain (`synscan.pcapng`, `http_dvwa_sqlinjection.pcapng`,
`aurora.pcapng`, `ratinfected.pcapng`, ...), and are small enough (KB to
low tens of MB) to not need the byte-range-prefix treatment Blue Coat and
`zeek-conn.log` need. Note that a scan-only capture (`synscan.pcapng`)
produced *zero* alerts against the real ruleset — ET Open is much more
weighted toward payload/malware signatures than bare port-scan detection —
so pick a capture with real attack/malware payload content, not just
anomalous connection patterns, when looking for a pack that needs alert
output specifically.

### Zeek

```bash
zeek -r capture.pcap
```

Writes `conn.log`, `http.log`, `dns.log` and others into the working directory.
`conn.log` is what `zeek-conn` reads. Zeek's default output is TSV with `#`
header lines — strip those, as `fetch_datasets.py` does for Blue Coat.

### Squid

```bash
squid -N -d1                       # writes /var/log/squid/access_log
curl -x http://127.0.0.1:3128 http://example.com/
```

Or skip it: the Honeynet mirror already publishes 533,197 real Squid records,
and `fetch_datasets.py --tier standard` retrieves them. (Blue Coat is in
`--tier large`: it is 2.6 GB.)

### ModSecurity and nginx

```bash
docker run -p 8080:8080 owasp/modsecurity-crs:nginx
curl "http://127.0.0.1:8080/?q=%27%20OR%201=1--"   # trips a CRS rule
```

The container writes both an nginx access log and a ModSecurity audit log, so
one command exercises two packs. Any obviously hostile request will do — the
point is a real rule firing, not a real attack.

### pfSense

The `filterlog` format is produced by `pf`, which ships with FreeBSD and macOS.
A pfSense VM under VirtualBox writes it directly; point its syslog at ULPF.

## PCAP sources for the above

| Source | Notes |
|---|---|
| <https://archive.wrccdc.org/pcaps/> | Over 1 TB from the Western Regional CCDC. Realistic topology, genuine attack traffic. |
| <https://www.netresec.com/?page=PcapFiles> | Curated index of public captures, including malware traffic and CTF data. |
| <https://www.secrepo.com/> | Security data samples: Zeek output, Squid logs, malware sets. |

## The commercial appliances

**Cisco ASA, FortiGate, PAN-OS, Check Point, Juniper SRX.** No public corpus was
found for any of these. Two honest options:

**Vendor evaluation VMs.** FortiGate VM, PAN-OS VM and Cisco ASAv all have free
trial images. Boot one, point its syslog at a ULPF collector, generate traffic
through it, and the logs are real device output. A few hours per vendor.

**Splunk Boss of the SOC.** [BOTS v3](https://github.com/splunk/botsv3) is CC0
public domain and carries `fgt_traffic` / `fgt_utm` (FortiGate) and
`pan:traffic` / `pan:threat` (Palo Alto) sourcetypes. The catch: it ships only
as pre-indexed Splunk buckets, so extracting raw events means standing up
Splunk Free and exporting. Roughly half a day per vendor.

If neither is done, say so. The README already lists those packs as unproven,
and that is a better position than an unqualified claim.

## Two evidence classes, kept apart

Logs you generate yourself are real output but **your** traffic. They are not
independent the way a third-party capture is: you chose the requests, so a pack
tuned on them has seen its own test set.

Record them as a distinct class in [DATASETS.md](DATASETS.md):

- **third-party production capture** — Honeynet, Loghub. Strongest evidence.
- **tool-generated from public PCAP** — you ran Suricata over someone else's
  traffic. Real output, independent input.
- **lab-generated** — you produced the traffic too. Weakest; useful for
  throughput and for exercising a decoder, not for a coverage claim.

Do not blend the three into one percentage.

## Adding a corpus to the measured set

1. Fetch it in `tools/fetch_datasets.py`, in the right tier. Strip anything
   that is file structure rather than an event — Blue Coat's `#` directives,
   Dragon's `[MARK]` separators — or it is counted as an unparsed record.
2. Add it to `PERIMETER` or `UNIVERSAL` in `tools/measure_coverage.py`. The two
   totals are reported separately so a non-perimeter source cannot move the
   headline figure.
3. Measure before writing or changing any pack, and write the number down.
   The gap between that first number and the final one is the evidence that
   the corpus taught you something.
4. Re-run `python tools/measure_coverage.py --write-baseline`, and check the
   perimeter total did not move for the wrong reason.

## The check that catches shadowing

Adding a pack can *lower* coverage on a corpus it has nothing to do with, by
claiming records that belonged to another pack and then failing to extract
them. This happened here: a new Thunderbird pack keyed on `(pam_unix)`, which
ordinary Linux syslog also contains, and Linux coverage fell from 94% to 19%.

So after adding any pack:

```bash
python tools/measure_coverage.py --data <dir> --check
```

`--check` fails when any corpus, or the total, drops below the recorded
baseline. Run it before committing, not after.
