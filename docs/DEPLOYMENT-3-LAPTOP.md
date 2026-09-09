# ULPF 3-Laptop Deployment — Quick Reference

> **Purpose:** Step-by-step commands to get all 3 laptops running for the live
> demo. This is the "just tell me what to type" version — no narrative, no
> rationale, just the exact commands in the exact order.
>
> Wazuh is already installed on Machine C at **10.60.197.6**. That does not
> change.

---

## Network Layout

```
  LAPTOP A                         LAPTOP B                         LAPTOP C
  Dev Dashboard                    Main Dashboard                   Wazuh
  (Traffic Simulator)              (ULPF Collector)                 (Comparison SIEM)
  ─────────────────                ─────────────────                ─────────────────
  IP: 10.60.197.72                 IP: <<MACHINE_B_IP>>             IP: 10.60.197.6

     │                                │                                │
     │  Phase 1: UDP 514 ────────────►│────── (nothing) ──────────────►│  Wazuh receives
     │  (sim-target = Wazuh)          │                                │  raw logs directly
     │                                │                                │
     │  Phase 2: UDP 5514 ───────────►│  ULPF normalizes to OCSF      │
     │  (sim-target = ULPF)           │  serves main console :8787    │  Wazuh shows
     │                                │  forwards to OpenSearch :9200 │  "before" state
     │                                │                                │
     │  localhost:8788/dev            │  <<IP>>:8787  ← Judges watch  │  https://10.60.197.6
     │  localhost:8789/dev            │  <<IP>>:5601  ← OpenSearch UI │  Wazuh Dashboard
```

---

## Prerequisites (do this BEFORE demo day, with internet)

### On Laptop A and Laptop B (both Windows)

```powershell
git clone https://github.com/D3v4nshPat3l/ULPF.git
cd ULPF
cargo build --release --locked
cargo test --workspace --release --locked
.\target\release\ulpf.exe test --packs packs
```

Expect: `35 packs · 75/75 fixtures passed · 100.0% field accuracy`

Then fetch datasets (both machines need this):

```powershell
python tools/fetch_datasets.py
dir realdata
```

Confirm `iptables.log`, `snort.log`, `apache-access.log` etc. exist.

### On Laptop B only — pull OpenSearch Docker images

```powershell
docker compose -f deploy/opensearch-compose.yaml pull
```

### On Laptop C (10.60.197.6) — configure Wazuh

See [demo-machine-c.md](demo-machine-c.md) steps 3–5. The key change is
adding the `<remote>` syslog listener block to `/var/ossec/etc/ossec.conf`
and restarting the manager.

---

## Demo Day — Step by Step

### Step 1: Start Machine C (Wazuh — 10.60.197.6)

Nothing to start — Wazuh is already running. Just confirm:

```bash
sudo ss -ulnp | grep 514
```

Should show UDP 514 listening. Open `https://10.60.197.6` in a browser and log in.

---

### Step 2: Start Machine B (Main Dashboard — the one judges watch)

**Open PowerShell, navigate to the ULPF folder.**

Start OpenSearch:

```powershell
docker compose -f deploy/opensearch-compose.yaml up -d
```

Wait for it:

```powershell
curl http://localhost:9200
```

Open firewall:

```powershell
New-NetFirewallRule -DisplayName "ULPF syslog" -Direction Inbound -Protocol UDP -LocalPort 5514 -Action Allow
New-NetFirewallRule -DisplayName "ULPF console" -Direction Inbound -Protocol TCP -LocalPort 8787 -Action Allow
```

Start the ULPF collector (replace `<<MACHINE_B_IP>>` with this laptop's actual IP):

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\vault --integrity-dir data\integrity --chain demo --host 0.0.0.0 --port 8787 --syslog-bind 0.0.0.0:5514 --datasets realdata --opensearch http://<<MACHINE_B_IP>>:9200 --opensearch-index ulpf-events
```

**Note the console token it prints.** Open in browser:
- **Main Dashboard:** `http://<<MACHINE_B_IP>>:8787` — paste the token when prompted
- **OpenSearch:** `http://<<MACHINE_B_IP>>:5601` — create index pattern `ulpf-events*`

This is the screen judges will watch.

---

### Step 3: Start Machine A (Dev Dashboard — Traffic Simulator)

**Terminal 1 — Simulator pointed at Wazuh (Phase 1: "Before")**

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\simvault --integrity-dir data\simintegrity --port 8788 --syslog-bind 127.0.0.1:5515 --datasets realdata --sim-target 10.60.197.6:514 --no-auth
```

Open `http://localhost:8788/dev` in browser. Turn on 2-3 sources (e.g. iptables, snort, apache).
Watch them appear in Wazuh's dashboard on Machine C. This is the **"before" shot** — raw logs going directly to Wazuh.

**Terminal 2 — Simulator pointed at ULPF (Phase 2: "After")**

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\simvault2 --integrity-dir data\simintegrity2 --port 8789 --syslog-bind 127.0.0.1:5516 --datasets realdata --sim-target <<MACHINE_B_IP>>:5514 --no-auth
```

Open `http://localhost:8789/dev` in browser. Leave sources OFF for now.

---

### Step 4: The Live Switch

**Phase 1 (Before):** Sources are running on Terminal 1 (port 8788), sending to Wazuh.
Show judges the Wazuh dashboard — partial parsing, no unified schema.

**Phase 2 (After):** Use the switch script:

```powershell
.\tools\demo-switch.ps1 -ToUlpf
```

Or manually: go to `localhost:8788/dev`, turn OFF all sources. Then go to `localhost:8789/dev`, turn ON the same sources.

Now the same real traffic flows through ULPF on Machine B instead. Show judges:
- **Machine B main dashboard** (`<<MACHINE_B_IP>>:8787`) — events normalized to OCSF, coverage stats, integrity chain
- **OpenSearch** (`<<MACHINE_B_IP>>:5601`) — same events searchable with unified field names

To switch back: `.\tools\demo-switch.ps1 -ToWazuh`

---

## What Each Dashboard Shows

| Dashboard | URL | What It Shows | Who Sees It |
|---|---|---|---|
| **Dev Dashboard (Wazuh sim)** | `localhost:8788/dev` | Simulator control — sources sending to Wazuh | Only Machine A operator |
| **Dev Dashboard (ULPF sim)** | `localhost:8789/dev` | Simulator control — sources sending to ULPF | Only Machine A operator |
| **Main Dashboard** | `<<MACHINE_B_IP>>:8787` | ULPF operator console — events, packs, clusters, integrity, copilot | **Judges watch this** |
| **OpenSearch Dashboards** | `<<MACHINE_B_IP>>:5601` | SIEM search across all normalized OCSF events | **Judges watch this** |
| **Wazuh Dashboard** | `https://10.60.197.6` | Raw logs as Wazuh sees them — the "before" comparison | **Judges see this first** |

---

## The Demo Story (in 2 minutes)

1. **"Here's what NTRO deals with today"** — Show Wazuh receiving raw logs from 3 different devices. Point out: different formats, partial field extraction, no common schema, no tamper evidence.

2. **"Now watch the same traffic through ULPF"** — Switch traffic to ULPF. Same bytes, same devices, but now:
   - Every event normalized to OCSF 1.9
   - 99.83% coverage across 10 device types
   - One search query finds results across ALL devices
   - Every event has a SHA-256 fingerprint chain
   - Original bytes preserved in the vault

3. **"Prove one record without exposing the log"** — On Machine B, run the `prove` + `verify-proof` commands. Show that 448 bytes proves membership in the entire log.

4. **"And it runs air-gapped"** — Point out: single binary, no internet, no CDN, no cloud APIs.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Machine B console shows no events | Machine A hasn't switched traffic yet, or firewall blocking UDP 5514 on Machine B |
| `/dev` page shows "absent" for all sources | `realdata` folder doesn't exist — run `python tools/fetch_datasets.py` |
| `serve` exits immediately with an error | Read the error — usually port already in use or wrong path |
| Can't reach Machine B from Machine A | `ping <<MACHINE_B_IP>>` — if it fails, it's a network problem |
| Wazuh shows nothing | Check `sudo ss -ulnp | grep 514` on Machine C, and `allowed-ips` in ossec.conf |
| OpenSearch not ready | `docker ps` — container might still be starting. Wait 30 seconds and retry `curl localhost:9200` |
