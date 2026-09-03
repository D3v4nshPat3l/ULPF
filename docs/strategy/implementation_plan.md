# ULPF Phase 2: Production Hardening Plan

## The Vision (3-Laptop Demo)

```
┌─────────────────────┐       syslog UDP/TCP        ┌──────────────────────┐       OCSF NDJSON/Bulk       ┌─────────────────────┐
│  LAPTOP 1            │ ─────────────────────────→ │  LAPTOP 2             │ ─────────────────────────→ │  LAPTOP 3            │
│  Source Simulator    │                            │  ULPF Engine          │                            │  SIEM                │
│                      │                            │                       │                            │                      │
│  Developer Dashboard │  Real logs from 15+        │  Analyst Console      │  Normalized OCSF events    │  Wazuh / OpenSearch  │
│  (/dev on :8787)     │  device types, replayed    │  (/ on :8787)         │  forwarded in real-time    │  receives clean data │
│                      │  with live timestamps      │                       │                            │                      │
│  Toggle devices      │  over standard syslog      │  Raw Vault            │  Also: Parquet archive     │  Proves req (g):     │
│  on/off per source   │  exactly like real world   │  Pack Library         │  on local disk             │  SIEM integration    │
│                      │                            │  Integrity Chain      │                            │                      │
└─────────────────────┘                            └──────────────────────┘                            └─────────────────────┘
```

This is the demo that wins. Three machines, zero internet, real log formats, one clean schema coming out the other end. No faking.

---

## Part 1: Real Log Dataset Library

We need real log samples for every device type our packs support, plus a few "unknown" sources to demonstrate the generator. Here's the complete sourcing plan:

### Tier 1: Perimeter Devices (We Already Have Packs)

| # | Device | Pack ID | Log Format | Source of Real Samples |
|---|---|---|---|---|
| 1 | **Fortinet FortiGate** | `fortinet-fortigate-traffic` | syslog + key-value | Elastic Filebeat repo `x-pack/filebeat/module/fortinet/firewall/test/` + FortiOS Log Reference manual |
| 2 | **Palo Alto PAN-OS** | `paloalto-panos-traffic` | syslog + CSV | Elastic Filebeat `x-pack/filebeat/module/panw/panos/test/` + PAN-OS Admin Guide Appendix |
| 3 | **Cisco ASA** | `cisco-asa-network` | syslog (RFC 3164 + `%ASA-` messages) | Elastic Filebeat `x-pack/filebeat/module/cisco/asa/test/sample.log` — hundreds of real ASA messages |
| 4 | **Snort** | `snort-nids-alert` | Snort fast/full alert text | Run Snort 2 against public PCAPs from CICIDS 2017/2018 to generate real alerts |
| 5 | **Suricata** | `suricata-eve-alert` | EVE JSON | GitHub: `FrankHassanabad/suricata-sample-data` — real EVE JSON generated from PCAPs |
| 6 | **Check Point** | `checkpoint-firewall` | syslog + CEF | Check Point Log Exporter documentation has full examples; CEF format is standardized |
| 7 | **Linux iptables** | `linux-iptables-firewall` | kernel printk syslog | Any Linux server with iptables logging enabled; trivial to generate on any team member's machine |
| 8 | **Squid Proxy** | `squid-proxy-access` | Squid native access log | Squid documentation `access.log` format; SecRepo has public Squid datasets |
| 9 | **ModSecurity WAF** | `modsecurity-waf-alert` | ModSec audit log format | OWASP ModSecurity CRS has test suites that generate real audit logs |
| 10 | **Juniper SRX** | `juniper-srx-traffic` | syslog + structured syslog (RFC 5424) | Elastic Filebeat `x-pack/filebeat/module/juniper/` + Juniper TechLibrary |
| 11 | **Generic CEF** | `generic-cef-network` | CEF over syslog | Any CEF-compliant source; ArcSight documentation has canonical examples |

### Tier 2: New Packs to Write (Expands Coverage)

| # | Device | Why | Log Format | Source |
|---|---|---|---|---|
| 12 | **Cisco Firepower/FTD** | Very common next-gen firewall | syslog + Firepower-specific | Elastic Filebeat `cisco/ftd/test/` |
| 13 | **Windows Event Log** | Required for endpoint visibility | XML (EVTX exported as syslog) | LogHub `Windows/` dataset on Zenodo |
| 14 | **SSH auth logs** | Universal Linux server log | syslog (RFC 3164) | LogHub `SSH/` dataset — 600K+ real lines |
| 15 | **Apache HTTP** | Web server access/error | Combined Log Format (CLF) | LogHub `Apache/` dataset |
| 16 | **OpenVPN** | VPN concentrator logs | syslog text | Public OpenVPN server log samples |

### Tier 3: "Unknown" Sources for Generator Demo

These are sources we deliberately do NOT write packs for. They land in the "Unparsed Clusters" queue and demonstrate the generator or manual pack authoring flow.

| # | Source | Why "unknown" |
|---|---|---|
| U1 | **Custom application server logs** (e.g., `[INFO] [AppServer] User login...`) | Proprietary format no SIEM supports |
| U2 | **IoT device heartbeats** (e.g., `SENSOR:T=23.5:H=67:BAT=89:ID=SN-0042`) | Completely bespoke format |
| U3 | **Legacy mainframe syslog** | Fixed-width positional columns, no delimiter |

### How Samples Are Organized

```
testdata/
  real/
    fortinet-fortigate/
      traffic.log        # 500+ real lines
      utm.log            # if available
      README.md          # source, license, notes
    cisco-asa/
      sample.log
    paloalto-panos/
      traffic.log
    ...
  unknown/
    custom-appserver.log
    iot-heartbeat.log
    legacy-mainframe.log
```

Each file:
- Contains **real** log lines from the stated source (not hand-written)
- Has a README documenting provenance (where downloaded, license, date)
- Timestamps may be rewritten by the replay tool at playback time

---

## Part 2: Developer Dashboard Overhaul

The `/dev` dashboard becomes a **multi-source traffic generator** that replays real logs over syslog.

### New UI Layout

```
┌────────────────────────────────────────────────────────────┐
│  SIMULATION NODE / SOURCE CONTROL                          │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Device Sources                                            │
│  ┌──────────────────┬────────┬──────────┬────────────────┐ │
│  │ Device           │ Format │ EPS      │ Status         │ │
│  ├──────────────────┼────────┼──────────┼────────────────┤ │
│  │ ● FortiGate FGT  │ KV     │ ~50/s    │ [Start] [Stop]│ │
│  │ ○ Cisco ASA      │ Syslog │ ~30/s    │ [Start] [Stop]│ │
│  │ ● Palo Alto PAN  │ CSV    │ ~40/s    │ [Start] [Stop]│ │
│  │ ○ Suricata EVE   │ JSON   │ ~20/s    │ [Start] [Stop]│ │
│  │ ○ Linux iptables │ Syslog │ ~60/s    │ [Start] [Stop]│ │
│  │ ...              │        │          │                │ │
│  │ ○ Unknown App    │ ???    │ ~10/s    │ [Start] [Stop]│ │
│  └──────────────────┴────────┴──────────┴────────────────┘ │
│                                                            │
│  Target: [  192.168.1.100  ] Port: [ 5514 ] Protocol: UDP  │
│                                                            │
│  [▶ Start All Known]  [▶ Start Unknown Only]  [■ Stop All] │
│                                                            │
│  Live Stats                                                │
│  Total Sent: 4,521   |  Rate: ~200 EPS  |  Uptime: 2m 15s │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### How Replay Works

Each "device" is a goroutine/thread that:
1. Reads lines from `testdata/real/<device>/*.log`
2. Rewrites the timestamp field to `now()` using format-aware replacement
3. Sends the line as a UDP syslog datagram (or TCP) to the configured target IP:port
4. Sleeps for `1000 / configured_eps` milliseconds between sends
5. Loops back to the beginning when the file is exhausted

> [!IMPORTANT]
> **The traffic travels over the network.** This is not an HTTP POST to localhost. The dev dashboard sends real syslog UDP datagrams to a remote IP — exactly like a real FortiGate would. The ULPF engine on Laptop 2 receives them via `ulpf listen --bind 0.0.0.0:5514`.

### Implementation: Rust, Not JavaScript

The current `/dev` page sends HTTP POSTs from the browser. That's fake.

The real replay engine should be a Rust binary (or a new CLI subcommand like `ulpf replay`) that:
- Reads real log files from `testdata/real/`
- Sends them as proper syslog UDP datagrams
- Is configurable via the `/dev` dashboard API

This way the Developer Dashboard is just a control panel for the Rust replay engine running on the same machine.

---

## Part 3: Deterministic Pack Generator (No AI, No GPU)

> [!IMPORTANT]
> NTRO's air-gapped network likely has no GPU. The pack generator MUST work without any AI model. The LLM-based generator becomes an **optional enhancement**, not the default.

### The Heuristic Approach

When a cluster of unparsed logs is selected, the deterministic generator analyzes the samples and drafts a pack using pure pattern matching:

#### Step 1: Format Detection
```
Input: "[INFO] [AppServer] User login successful - UserID: 1045, IP: 192.168.1.55"

Heuristics applied (in order):
1. Starts with '{' or '[{' → JSON decoder
2. Starts with '<' and contains xmlns → XML decoder  
3. Contains 'CEF:' → CEF decoder
4. Contains 'LEEF:' → LEEF decoder
5. Contains '<PRI>' header → syslog envelope + recurse on body
6. Has consistent delimiters (CSV detection via column count stability)
7. Has key=value or key="value" patterns → keyvalue decoder
8. Fallback: regex with named capture groups from Drain template
```

#### Step 2: Field Name Extraction
For key-value formats, field names come directly from the keys in the log.
For positional formats, the Drain template tokens become placeholder names.

#### Step 3: OCSF Mapping Suggestion
A lookup table maps common field names to OCSF paths:

```rust
// Built-in heuristic mappings
"srcip" | "src_ip" | "source_ip" | "SRC" | "src_addr" → "src_endpoint.ip"
"dstip" | "dst_ip" | "dest_ip" | "DST" | "dst_addr"  → "dst_endpoint.ip"
"srcport" | "src_port" | "sport" | "SPT"              → "src_endpoint.port"
"dstport" | "dst_port" | "dport" | "DPT"              → "dst_endpoint.port"
"action" | "act" | "verdict"                           → "activity_id" (with enum)
"proto" | "protocol" | "PROTO"                         → "connection_info.protocol_num"
"user" | "username" | "usr" | "uname"                  → "actor.user.name"
"hostname" | "host" | "devname" | "device_name"        → "device.hostname"
```

#### Step 4: Fixture Generation
Sample lines from the cluster become fixtures with `expect: {}` (analyst fills in expected values during review).

### Result: Two Generator Modes

| Mode | Requires | Speed | Quality | When to Use |
|---|---|---|---|---|
| **Heuristic** (default) | Nothing. Pure Rust. | Instant | Good for structured formats (KV, CSV, JSON). Weaker for unstructured text. | Always available. Air-gap safe. |
| **LLM-assisted** (optional) | Ollama + a model + CPU (no GPU needed for small models) | 10-30 seconds | Better at naming and identifying vendor/product | When available and operator wants it |

In the UI, this becomes two buttons on the Unparsed Clusters page:
- **"Draft Pack (Heuristic)"** — always works, instant
- **"Draft Pack (AI-Assisted)"** — greyed out with tooltip "Requires Ollama" if model isn't reachable

---

## Part 4: Production Hardening

### 4a. Bundle Fonts (Kill CDN Dependency)

Download IBM Plex Sans and JetBrains Mono WOFF2 files. Embed them in the binary via `include_bytes!` alongside the HTML. Serve them from `/fonts/` routes. Remove all Google Fonts CDN links.

**Time: 1 hour.**

### 4b. Multi-Listener Support

The `ulpf serve` command should accept syslog on at least:
- UDP `:5514` (unprivileged syslog)
- TCP `:5514`

Both feed into the same pipeline. This is how real devices send logs.

Currently `ulpf listen` does this standalone. Wire it into `ulpf serve` so the console and the syslog receiver run together.

**Time: 1-2 days.**

### 4c. SIEM Forwarding from `serve`

The `ulpf run` command already has `--opensearch`, `--splunk-hec`, and `--parquet` sink flags. Wire these into the `serve` command too, so the console mode can forward to a real SIEM on Laptop 3.

**Time: Half day.**

### 4d. Graceful Shutdown

Catch SIGTERM/SIGINT (or Windows Ctrl+C). Flush the vault, write a signed checkpoint, close sinks cleanly. On restart, resume the chain from the last checkpoint.

**Time: Half day.**

### 4e. Configuration File

A single `ulpf.toml` that replaces all CLI flags:

```toml
[packs]
dir = "packs"

[vault]
dir = "data/vault"
block_size = "1MiB"
segment_size = "256MiB"

[integrity]
dir = "data/integrity"
chain = "production"
algorithm = "blake3"  # or "sha256"

[listeners]
  [listeners.syslog-udp]
  bind = "0.0.0.0:5514"
  transport = "syslog-udp"

  [listeners.syslog-tcp]
  bind = "0.0.0.0:5514"
  transport = "syslog-tcp"

[sinks]
  [sinks.parquet]
  path = "data/output"
  
  [sinks.opensearch]
  url = "http://192.168.1.200:9200"
  index = "ulpf-events"

[console]
bind = "0.0.0.0:8787"
```

**Time: 1-2 days.**

---

## Part 5: Three-Laptop Demo Wiring

### Network Setup
All three laptops on the same LAN (WiFi hotspot or Ethernet switch). No internet.

### Laptop 1: Source Simulator
```bash
# Runs the ULPF binary in replay mode
ulpf replay --target 192.168.1.100:5514 --sources fortinet,cisco-asa,paloalto
# Also serves the Developer Dashboard for controlling sources
ulpf dev-console --port 8787
```

### Laptop 2: ULPF Engine
```bash
# Single command, configured via ulpf.toml
ulpf serve --config ulpf.toml
# Listens on :5514 for syslog
# Serves Analyst Console on :8787
# Forwards OCSF to OpenSearch on Laptop 3
```

### Laptop 3: SIEM
```bash
# Wazuh single-node or plain OpenSearch
docker compose up -d
# Receives OCSF events via OpenSearch bulk API
# Analysts can search normalized events in Kibana/Wazuh dashboard
```

---

## Execution Priority

| Priority | Task | Time | Impact |
|---|---|---|---|
| **P0** | Bundle fonts (kill CDN) | 1 hour | Fixes air-gap compliance |
| **P0** | Collect real log datasets into `testdata/real/` | 1-2 days | Foundation for everything |
| **P0** | Wire syslog listeners into `serve` command | 1-2 days | Makes the 3-laptop demo possible |
| **P1** | Build `ulpf replay` subcommand | 1-2 days | Replays real logs over syslog |
| **P1** | Overhaul `/dev` dashboard as replay controller | 1 day | Controls which sources are active |
| **P1** | Wire SIEM sinks into `serve` | Half day | Forwards to Laptop 3 |
| **P1** | Build heuristic pack generator | 2-3 days | Works without AI/GPU |
| **P2** | Configuration file (`ulpf.toml`) | 1-2 days | Production deployability |
| **P2** | Graceful shutdown + chain resume | Half day | Reliability |
| **P2** | Write 4 new packs (Firepower, Windows, SSH, Apache) | 2 days | Expands coverage to 15+ |
| **P2** | Benchmark harness | 1 day | Proves throughput claims |
| **P3** | Validate all packs against real dataset samples | 2 days | Ensures packs actually work |
| **P3** | Docker `save` tarball for air-gap install | Half day | Deliverable |

> [!IMPORTANT]
> **Total estimated time: ~2-3 weeks of focused work across the team.** This transforms ULPF from "impressive hackathon demo" into "NTRO can deploy this today." The core engine is already real — these tasks build the deployment surface around it.

## Open Questions for You

1. **Which SIEM for Laptop 3?** Wazuh (includes OpenSearch + dashboards, free) or plain OpenSearch? Wazuh is more impressive for judges but heavier to set up.

2. **Do your teammates have access to any real devices?** Even one FortiGate or Cisco router generating real syslog would be invaluable for validation. If not, public datasets are sufficient.

3. **Team split:** Should the replay engine + dataset collection be one person's lane while the heuristic generator is another's? The tasks are independent.
