# ULPF Phase 2: Execution Tasks

- [x] **Phase A: Core Hardening & Demo Setup**
  - [x] Bundle fonts (kill Google Fonts CDN dependency)
  - [x] Wire syslog listeners (UDP/TCP) into the `serve` command
  - [x] Create detailed 3-Laptop Demo Setup Documentation (`docs/3-LAPTOP-DEMO.md`)
- [x] **Phase B: Real Datasets & Simulator**
  - [x] Collect real log datasets for 10+ device types into `testdata/real/`
  - [x] Build `ulpf replay` subcommand to stream real logs over UDP
  - [x] Overhaul Developer Dashboard (`/dev`) to control the replay engine
- [x] **Phase C: Production Features**
  - [x] Wire SIEM sinks (OpenSearch/Wazuh) into the `serve` command
  - [x] Build deterministic (heuristic) pack generator (no AI/GPU required)
  - [ ] Implement TOML configuration file parsing (`ulpf.toml`)
  - [ ] Implement graceful shutdown and attestation chain resumption
- [ ] **Phase D: Expansion & Validation**
  - [ ] Write 4 new packs (Firepower, Windows, SSH, Apache)
  - [ ] Validate all packs against real dataset samples
  - [ ] Create benchmark harness
  - [ ] Update README with final instructions
