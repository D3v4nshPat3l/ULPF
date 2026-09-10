# ULPF `/dev` to Wazuh: complete Windows setup

This guide builds the local demonstration below from a clean Windows system:

```text
real public log corpora
        |
        v
ULPF simulator: http://127.0.0.1:8787/dev
        |
        | select Wazuh (UDP 127.0.0.1:514)
        v
Docker Desktop -> Wazuh manager -> archives.json -> Filebeat
                                                      |
                                                      v
                          Wazuh indexer -> Discover: wazuh-archives-*
```

`wazuh-archives-*` shows every event Wazuh receives, including events that do
not trigger a security rule. `wazuh-alerts-*` contains only events that match a
Wazuh rule at or above its configured alert level.

The Wazuh button is a comparison route. It sends original corpus records from
ULPF's simulator directly to Wazuh. Select **ULPF** to send those same records
to ULPF's normalization pipeline on UDP 5514. Select **Wazuh** to send them to
Wazuh on UDP 514. The Wazuh route does not contain ULPF-normalized OCSF output.

## Tested configuration

| Component | Tested value |
|---|---|
| Host | Windows 11 with WSL 2 |
| Runtime | Docker Desktop using Linux containers |
| Wazuh | `4.14.7`, single-node Docker deployment |
| Wazuh dashboard | `https://127.0.0.1` |
| Wazuh syslog input | `127.0.0.1:514/UDP` |
| ULPF console | `http://127.0.0.1:8787` |
| ULPF simulator | `http://127.0.0.1:8787/dev` |
| ULPF syslog input | `127.0.0.1:5514/UDP` |

Use Wazuh 4.14.7 for this direct-syslog demonstration. Wazuh 5 removed direct
raw-syslog input from the manager and requires an external syslog collector.
Do not clone the unversioned Wazuh `main` branch for this procedure.

## Requirements

Provide Docker Desktop with at least 8 GB of memory, four CPU cores, and about
50 GB of free disk. Archive indexing stores every received record, so a
high-rate test consumes disk quickly.

Install Git for Windows, Python 3.9 or newer, Rust through `rustup`, and Docker
Desktop with the WSL 2 backend. Every command below is PowerShell. Copy only the
text inside code blocks; Markdown labels such as ````powershell` are not part
of a command.

## 1. Install WSL 2 and Docker Desktop

Open **PowerShell as Administrator**:

```powershell
wsl --install
```

Restart Windows if requested. Verify WSL:

```powershell
wsl --status
wsl --list --verbose
```

Install Docker Desktop:

```powershell
winget install --exact --id Docker.DockerDesktop
```

Restart Windows, open Docker Desktop from Start, select the WSL 2 backend if
prompted, and wait until the status reads **Engine running**.

To store Docker data on E:, use **Docker Desktop -> Settings -> Resources ->
Advanced -> Disk image location**. Docker may create `ext4.vhdx` there. It is
Docker's managed Linux disk; do not edit, mount, rename, or delete it manually.
Its location does not change any localhost address in this guide.

Open a new normal PowerShell and verify client and server:

```powershell
docker context use desktop-linux
docker version
docker info
```

`docker info` must have a populated `Server:` section. This error means the CLI
is installed but the engine is stopped:

```text
failed to connect to the docker API at
npipe:////./pipe/dockerDesktopLinuxEngine
```

Start the engine:

```powershell
docker desktop start
```

If that subcommand is unavailable:

```powershell
Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
```

Wait for **Engine running**, open a fresh PowerShell, and repeat `docker info`.
If startup still fails, run the next two commands as administrator, restart
Windows, and open Docker Desktop again:

```powershell
wsl --update
wsl --shutdown
```

## 2. Deploy the bundled Wazuh 4.14.7 stack

Clone ULPF into an ordinary project directory. Do not use Docker Desktop's data
directory. The repository contains a ready single-node Wazuh deployment with
the UDP listener and archive pipeline already configured.

```powershell
Set-Location "E:\"
git clone https://github.com/D3v4nshPat3l/ULPF.git ULPF
Set-Location "E:\ULPF\deploy\wazuh"
```

If ULPF is already cloned, use only:

```powershell
Set-Location "E:\ULPF\deploy\wazuh"
```

Generate certificates:

```powershell
docker compose -f generate-indexer-certs.yml run --rm generator
```

A final `find: command not found` can appear after certificates were generated
and moved. Confirm that files exist:

```powershell
Get-ChildItem ".\config\wazuh_indexer_ssl_certs" | Select-Object Name,Length
```

Start the stack and inspect it:

```powershell
docker compose up -d
docker compose ps
```

Wait several minutes on the first start. The manager, indexer, and dashboard
must be running. The manager must publish `514->514/udp`, the indexer port 9200,
and the dashboard port 443.

If `docker compose ps` is empty, verify that PowerShell is in the Compose
project directory:

```powershell
Get-Location
Test-Path ".\docker-compose.yml"
docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
```

If a service restarts, inspect it:

```powershell
docker compose logs --tail 150 wazuh.indexer
docker compose logs --tail 150 wazuh.manager
docker compose logs --tail 150 wazuh.dashboard
```

If the indexer reports a low `vm.max_map_count`, run:

```powershell
wsl -d docker-desktop -u root sysctl -w vm.max_map_count=262144
docker compose restart
```

## 3. Verify the UDP 514 listener

The bundled `config\wazuh_cluster\wazuh_manager.conf` already includes the
syslog listener. Verify the live container first:

```powershell
docker port single-node-wazuh.manager-1 514/udp
docker exec single-node-wazuh.manager-1 sh -c "grep -n -A7 -B2 '<connection>syslog</connection>' /var/ossec/etc/ossec.conf"
```

If both commands show port 514 and the `syslog` block, continue to section 4.
For an older or separately cloned upstream stack where that block is missing,
back up and open the persistent manager configuration:

```powershell
Copy-Item ".\config\wazuh_cluster\wazuh_manager.conf" ".\config\wazuh_cluster\wazuh_manager.conf.backup"
notepad ".\config\wazuh_cluster\wazuh_manager.conf"
```

Keep the existing secure listener. Immediately after it, inside the outer
`<ossec_config>` element, add:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>172.16.0.0/12</allowed-ips>
  <allowed-ips>192.168.0.0/16</allowed-ips>
  <allowed-ips>127.0.0.1</allowed-ips>
</remote>
```

The Docker host appeared as `172.18.0.1` in the tested setup and is covered by
`172.16.0.0/12`. Use narrower networks outside a local lab.

Save the file, recreate only the manager, and verify it:

```powershell
docker compose up -d --force-recreate wazuh.manager
docker exec single-node-wazuh.manager-1 sh -c "grep -n -A7 -B2 '<connection>syslog</connection>' /var/ossec/etc/ossec.conf"
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
docker port single-node-wazuh.manager-1 514/udp
```

`wazuh-remoted`, `wazuh-analysisd`, and `wazuh-logcollector` must run. It is
normal for cluster, mail, and agentless services to be stopped in this lab.

## 4. Prove UDP reception

Send an event that matches Wazuh's built-in SSH rules:

```powershell
$udpClient = [System.Net.Sockets.UdpClient]::new()
$testLog = "<134>Sep 10 14:45:00 ulpf-demo sshd[1234]: Failed password for invalid user admin from 192.0.2.10 port 55221 ssh2"
$testBytes = [System.Text.Encoding]::UTF8.GetBytes($testLog)
[void]$udpClient.Send($testBytes,$testBytes.Length,"127.0.0.1",514)
$udpClient.Dispose()
```

Wait and locate the alert:

```powershell
Start-Sleep -Seconds 5
docker exec single-node-wazuh.manager-1 sh -c "grep '192.0.2.10' /var/ossec/logs/alerts/alerts.json | tail -n 5"
```

A successful record contains rule `5710`, decoder `sshd`, source IP
`192.0.2.10`, and a location similar to `172.18.0.1`.

If the UDP send finishes but the alert is absent, inspect the live listener and
manager log:

```powershell
docker exec single-node-wazuh.manager-1 sh -c "grep -n -A10 -B2 '<remote>' /var/ossec/etc/ossec.conf"
docker exec single-node-wazuh.manager-1 sh -c "tail -n 100 /var/ossec/logs/ossec.log"
```

The PowerShell send completing proves only that Windows accepted the datagram.
The alert proves that Wazuh received, decoded, and analyzed it.

## 5. Verify every event reaches `wazuh-archives-*`

The bundled deployment enables both required settings:

1. `logall_json=yes` writes every received event to `archives.json`.
2. `archives.enabled=true` tells Filebeat to index `archives.json`.

Check the running container:

```powershell
docker exec single-node-wazuh.manager-1 sh -c "grep -n 'logall_json' /var/ossec/etc/ossec.conf; grep -n -A2 'archives:' /etc/filebeat/filebeat.yml"
```

If the output shows `yes` and `true`, skip to section 5.3. If either value is
disabled because this is an older or separately installed stack, apply the
corresponding subsection below.

### 5.1 Manager archive storage

Open the persistent configuration:

```powershell
notepad ".\config\wazuh_cluster\wazuh_manager.conf"
```

In `<global>`, change:

```xml
<logall_json>no</logall_json>
```

to:

```xml
<logall_json>yes</logall_json>
```

`logall_json` is required for dashboard indexing. The separate `<logall>`
plain-text option may remain `no`.

Apply and verify:

```powershell
docker compose up -d --force-recreate wazuh.manager
docker exec single-node-wazuh.manager-1 sh -c "grep -n 'logall_json' /var/ossec/etc/ossec.conf"
```

### 5.2 Filebeat archive forwarding

The Compose deployment stores `/etc/filebeat` in its `filebeat_etc` named
volume. Copy the current file out and preserve a backup:

```powershell
docker cp single-node-wazuh.manager-1:/etc/filebeat/filebeat.yml ".\filebeat-archives.yml"
Copy-Item ".\filebeat-archives.yml" ".\filebeat-archives.yml.backup"
notepad ".\filebeat-archives.yml"
```

Change only:

```yaml
    archives:
      enabled: false
```

to:

```yaml
    archives:
      enabled: true
```

Keep indentation unchanged. Copy it back, validate, and restart:

```powershell
docker cp ".\filebeat-archives.yml" single-node-wazuh.manager-1:/etc/filebeat/filebeat.yml
docker exec single-node-wazuh.manager-1 filebeat test config -c /etc/filebeat/filebeat.yml
docker restart single-node-wazuh.manager-1
```

Verify both settings and the Filebeat connection:

```powershell
Start-Sleep -Seconds 20
docker exec single-node-wazuh.manager-1 sh -c "grep -n 'logall_json' /var/ossec/etc/ossec.conf; grep -n -A2 'archives:' /etc/filebeat/filebeat.yml"
docker exec single-node-wazuh.manager-1 filebeat test output -c /etc/filebeat/filebeat.yml
```

Expected values are `<logall_json>yes</logall_json>` and `enabled: true` under
`archives:`.

### 5.3 Prove archive storage and indexing

Send a distinctive record:

```powershell
$udpClient = [System.Net.Sockets.UdpClient]::new()
$archiveLog = "<134>Sep 10 15:30:00 ulpf-archive ULPF-ARCHIVE-TEST event_id=ULPF-DEMO-9001 status=received"
$archiveBytes = [System.Text.Encoding]::UTF8.GetBytes($archiveLog)
[void]$udpClient.Send($archiveBytes,$archiveBytes.Length,"127.0.0.1",514)
$udpClient.Dispose()
Start-Sleep -Seconds 5
docker exec single-node-wazuh.manager-1 sh -c "grep 'ULPF-DEMO-9001' /var/ossec/logs/archives/archives.json | tail -n 3"
```

Prompt for the indexer password once, then inspect archive indices without
storing that password in this repository:

```powershell
$WazuhAdminPassword = Read-Host "Enter the Wazuh indexer admin password"
docker exec single-node-wazuh.indexer-1 curl -ks -u "admin:$WazuhAdminPassword" "https://localhost:9200/_cat/indices/wazuh-archives-*?v"
docker exec single-node-wazuh.indexer-1 curl -ks -u "admin:$WazuhAdminPassword" "https://localhost:9200/wazuh-archives-*/_count?pretty"
Remove-Variable WazuhAdminPassword
```

If `archives.json` has the record but no archive index exists, run:

```powershell
docker exec single-node-wazuh.manager-1 filebeat test output -c /etc/filebeat/filebeat.yml
docker exec single-node-wazuh.manager-1 sh -c "tail -n 100 /var/log/filebeat/filebeat | grep -i -E 'error|archive'"
```

## 6. Create and use the archive index pattern

Open Wazuh:

```powershell
Start-Process "https://127.0.0.1"
```

Continue past the local certificate warning. Sign in with the credentials set
in the Wazuh deployment. Change default credentials before exposing the stack
beyond a private lab.

In the dashboard:

1. Open the upper-left menu.
2. Go to **Dashboard management -> Dashboard Management -> Index patterns**.
3. Select **Create index pattern**.
4. Enter `wazuh-archives-*`.
5. Select **timestamp** as the time field. Do not select `@timestamp`.
6. Create the pattern.
7. Open **Explore -> Discover**.
8. Select `wazuh-archives-*`.
9. Choose **Last 15 minutes** and refresh.
10. Sort `timestamp` descending.

Add `timestamp`, `full_log`, `decoder.name`, `location`, and `data.srcip` as
columns. Find the manual test with:

```text
full_log:"ULPF-DEMO-9001"
```

If Discover is empty, clear the query, select **Last 24 hours**, refresh the
pattern's field list, and confirm the PowerShell index count. Use `timestamp`
as the time field even when an `@timestamp` field is also listed.

## 7. Install and run ULPF

Install Git and Python if required:

```powershell
winget install --exact --id Git.Git
winget install --exact --id Python.Python.3.12
```

Install Rust from `https://rustup.rs`. Open a new PowerShell and select the GNU
Windows toolchain:

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
```

ULPF was cloned in section 2. Enter its root directory:

```powershell
Set-Location "E:\ULPF"
```

Fetch the demonstration corpora and build:

```powershell
python tools\fetch_datasets.py
cargo build --release --locked
```

If `python` is unavailable, use:

```powershell
py -3 tools\fetch_datasets.py
```

If Cargo reports that `target\release\ulpf.exe` cannot be removed because
access is denied, stop the running server and rebuild:

```powershell
Get-Process ulpf -ErrorAction SilentlyContinue | Stop-Process
cargo build --release --locked
```

Start the local demonstration server and keep its terminal open:

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\vault --integrity-dir data\integrity --datasets realdata --forward-udp 127.0.0.1:514 --no-auth
```

`--no-auth` is intended for a local demonstration. Omit it for normal use; ULPF
then prints and stores a console token.

## 8. Route `/dev` traffic into the Wazuh UI

Open the simulator:

```powershell
Start-Process "http://127.0.0.1:8787/dev"
```

On `/dev`:

1. Select **Wazuh**.
2. Confirm **Collector target** reads `127.0.0.1:514`.
3. Set one present source to `20` EPS.
4. Turn on that source for 15 to 30 seconds.
5. In Wazuh Discover, select `wazuh-archives-*`, choose **Last 15 minutes**,
   and refresh.
6. Enable automatic refresh every five seconds for a live demonstration.

Start with one low-rate source. **Start all** starts every available source and
can create thousands of events per second. Archive mode indexes every record,
so a high rate increases CPU, memory, and disk use quickly.

Confirm the live path in PowerShell:

```powershell
docker exec single-node-wazuh.manager-1 sh -c "tail -n 5 /var/ossec/logs/archives/archives.json"
$WazuhAdminPassword = Read-Host "Enter the Wazuh indexer admin password"
docker exec single-node-wazuh.indexer-1 curl -ks -u "admin:$WazuhAdminPassword" "https://localhost:9200/wazuh-archives-*/_count?pretty"
Remove-Variable WazuhAdminPassword
```

Clear Discover filters to show every record. To limit the view to events that
entered through the tested Docker gateway, try:

```text
location:"172.18.0.1"
```

The gateway may differ on another computer. Read `location` from a known event
before using the filter. Other useful searches are:

```text
full_log:sshd
```

```text
decoder.name:web-accesslog
```

Select **ULPF** on `/dev` to route subsequent records to
`127.0.0.1:5514`, where ULPF vaults, identifies, normalizes, and signs them.
Because the server was started with `--forward-udp 127.0.0.1:514`, each
normalized OCSF event is then forwarded into the same Wazuh archive view. This
produces the intended comparison: **Wazuh** shows raw vendor records, while
**ULPF** shows normalized OCSF records in `full_log`. Changing target restarts
active simulator streams against the new destination.

## 9. Start and stop the demo later

After restarting Windows, open Docker Desktop and wait for **Engine running**.
Start Wazuh:

```powershell
Set-Location "E:\ULPF\deploy\wazuh"
docker compose up -d
docker compose ps
```

Start ULPF in a second PowerShell:

```powershell
Set-Location "E:\ULPF"
.\target\release\ulpf.exe serve --packs packs --vault data\vault --integrity-dir data\integrity --datasets realdata --forward-udp 127.0.0.1:514 --no-auth
```

Open both pages:

```powershell
Start-Process "http://127.0.0.1:8787/dev"
Start-Process "https://127.0.0.1"
```

Use **Stop all** in ULPF before ending the demo. Stop Wazuh without deleting
indexed data:

```powershell
Set-Location "E:\ULPF\deploy\wazuh"
docker compose stop
```

Resume with `docker compose start` or `docker compose up -d`. Do not run
`docker compose down -v` unless you deliberately intend to delete Wazuh's named
volumes and all indexed data.

## Troubleshooting by symptom

### Docker API pipe is missing

Start Docker Desktop, wait for **Engine running**, open a fresh PowerShell, run
`docker context use desktop-linux`, and verify `docker info`.

### Compose reports no containers

```powershell
Set-Location "E:\ULPF\deploy\wazuh"
Test-Path ".\docker-compose.yml"
docker compose ps
docker ps -a
```

### Port 514 is published, but Wazuh receives nothing

```powershell
docker port single-node-wazuh.manager-1 514/udp
docker exec single-node-wazuh.manager-1 sh -c "grep -n -A7 -B2 '<connection>syslog</connection>' /var/ossec/etc/ossec.conf"
```

The live configuration must include the `syslog` remote block.

### Alerts work, but archives are empty

```powershell
docker exec single-node-wazuh.manager-1 sh -c "grep -n 'logall_json' /var/ossec/etc/ossec.conf; grep -n -A2 'archives:' /etc/filebeat/filebeat.yml"
```

The values must be `yes` and `true`.

### `archives.json` works, but Discover is empty

Check Filebeat output and the index:

```powershell
docker exec single-node-wazuh.manager-1 filebeat test output -c /etc/filebeat/filebeat.yml
$WazuhAdminPassword = Read-Host "Enter the Wazuh indexer admin password"
docker exec single-node-wazuh.indexer-1 curl -ks -u "admin:$WazuhAdminPassword" "https://localhost:9200/_cat/indices/wazuh-archives-*?v"
Remove-Variable WazuhAdminPassword
```

Then confirm the pattern is exactly `wazuh-archives-*`, its time field is
`timestamp`, and the time picker covers the event time.

### The archive pattern cannot be created

Generate a test event and wait until `_cat/indices` shows a matching index.
OpenSearch may refuse a pattern when no matching index exists yet.

### A ULPF source says `absent`

```powershell
Set-Location "E:\ULPF"
python tools\fetch_datasets.py
```

Restart ULPF with `--datasets realdata`.

### Wazuh is selected, but no new records arrive

Confirm `127.0.0.1:514`, an enabled source, and an increasing **Sent** count.
Repeat the manual SSH test. If it works, inspect the ULPF server terminal and
browser console. If it fails, repair the Wazuh listener first.

### Wazuh becomes slow or disk use grows rapidly

Stop all simulator streams, use 20 EPS, and enable only one or two sources.
Inspect resource and disk use:

```powershell
docker stats --no-stream
docker system df -v
```

For long-running environments, configure index retention. To return to
alert-only operation, set `logall_json` to `no`, set Filebeat archive forwarding
to `false`, and restart the manager. Existing indices remain until removed by
the deployment's retention policy.

## Pre-demo verification

```powershell
docker info
docker compose -f "E:\ULPF\deploy\wazuh\docker-compose.yml" ps
docker port single-node-wazuh.manager-1 514/udp
docker exec single-node-wazuh.manager-1 sh -c "grep -n 'logall_json' /var/ossec/etc/ossec.conf; grep -n -A2 'archives:' /etc/filebeat/filebeat.yml"
```

Then open `/dev`, select Wazuh, start one real corpus at 20 EPS, and show the
newest `wazuh-archives-*` records sorted by `timestamp`.

## References

- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Wazuh event logging and archives](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
- [Wazuh indexer indices](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
- [Wazuh 4.x to 5.x syslog migration](https://github.com/wazuh/wazuh/blob/main/docs/guide/migration/syslog-input-4x-to-5x.md)