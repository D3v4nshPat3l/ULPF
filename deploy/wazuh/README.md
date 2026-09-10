# Wazuh on one machine, next to ULPF

A single-node Wazuh stack for the side-by-side demo: the `/dev` traffic
simulator can point at **ULPF** or at **Wazuh**, and this is the Wazuh half.

For a clean Windows installation beginning with WSL 2 and Docker Desktop, use
[the complete ULPF-to-Wazuh setup guide](../../docs/WAZUH_INTEGRATION.md).

Everything here is Wazuh 4.14.7 official images. The only changes from the
upstream `single-node` sample are the two that make raw events visible in the
dashboard — both are called out below, because both are easy to get wrong and
neither fails loudly.

---

## What "it works" means here

The simulator sends real captured logs to **UDP 514**. Wazuh must then:

1. accept them on its syslog listener,
2. write **every** event — not only the ones a rule matched — to
   `/var/ossec/logs/archives/archives.json`,
3. ship that file to the indexer as `wazuh-archives-4.x-<date>`,
4. show them in the dashboard under that index pattern.

Step 2 and step 3 are off by default. Wazuh indexes **alerts**, and a log that
no rule matches produces no alert and therefore leaves no trace. For a
normalisation demo that is exactly backwards: the whole point is what happens
to ordinary traffic.

---

## First run, from nothing

You need Docker Desktop (or Docker Engine) running. Nothing else.

**1. Generate the certificates.** Once per machine. They are not in git —
they are per-installation secrets.

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

**2. Start the stack.**

```bash
docker compose up -d
```

**3. Wait for it.** The indexer takes a minute or two before the dashboard
will answer.

```bash
docker compose ps
```

All three services should read `running`. If `wazuh.indexer` is restarting,
see *Troubleshooting*.

**4. Open the dashboard.**

<https://localhost>

Username `admin`, password `SecretPassword`. The certificate is self-signed,
so the browser will warn — that is expected on a demo box.

---

## Point the simulator at Wazuh

With ULPF running, open <http://127.0.0.1:8787/dev>, and press **Wazuh** in
the target switch. The simulator's target becomes `127.0.0.1:514` and every
enabled source now sends there instead of to ULPF.

Or send a fixed burst by hand, which is the quickest way to prove the path:

```bash
./target/release/ulpf replay --source realdata/snort.log --target 127.0.0.1:514 --eps 500 --count 2000
```

---

## See the events in the dashboard

The archives index pattern does not exist until you create it, and this is
where most people conclude "nothing arrived" when everything did.

1. Dashboard → **☰ → Dashboards Management → Index patterns → Create index
   pattern**
2. Name it `wazuh-archives-*`
3. Time field: `timestamp`
4. Create.

Then **☰ → Discover**, choose `wazuh-archives-*` in the index selector, and
set the time picker to *Last 15 minutes*.

Raw traffic appears under `full_log`.

---

## Checking the path when nothing shows up

Work along the chain in order. The first step that is empty is the broken one.

**Is the manager receiving anything?**

```bash
docker exec single-node-wazuh.manager-1 sh -c 'ls -l /var/ossec/logs/archives/archives.json'
```

The file should exist and its size should grow while traffic is flowing. If
it is missing or frozen, archives are off — check `logall_json` below.

**Did our specific records land?**

```bash
docker exec single-node-wazuh.manager-1 sh -c 'grep -c snort /var/ossec/logs/archives/archives.json'
```

**Is the indexer storing them?**

```bash
docker exec single-node-wazuh.indexer-1 sh -c 'curl -sk -u admin:SecretPassword "https://localhost:9200/_cat/indices/wazuh-archives*?h=index,docs.count"'
```

You want a row for today's date with a rising count. A row for an older date
only means archives worked once and stopped.

---

## The two settings that matter, and why they bite

### 1. `logall_json` — off by default

`config/wazuh_cluster/wazuh_manager.conf`:

```xml
<logall>no</logall>
<logall_json>yes</logall_json>
```

`logall_json` writes every received event to `archives.json` as JSON.
`logall` writes the same thing as plain text and is left off because nothing
downstream reads it and it doubles the disk cost.

**The trap:** `/var/ossec/etc` is a named Docker volume. The manager copies
`/wazuh-config-mount/etc/ossec.conf` into it, and once that volume exists,
editing the file on your host and running `docker compose restart` **does not
apply the change**. The container keeps the config it was first built with.

To make a config edit take effect, recreate the volumes:

```bash
docker compose down -v
docker compose up -d
```

`down -v` **deletes indexed data as well** — every alert and archive already
stored. On a demo box that is usually fine and gives a clean start. If you
need to keep the data, edit the file inside the running container instead and
restart just the manager:

```bash
docker exec single-node-wazuh.manager-1 sh -c "sed -i 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' /var/ossec/etc/ossec.conf"
docker restart single-node-wazuh.manager-1
```

### 2. The Filebeat archives module — off by default

`filebeat-archives.yml`:

```yaml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: true
```

Even with `archives.json` filling up, nothing reaches the indexer unless
Filebeat is told to ship it.

**The trap:** the compose file mounts `filebeat_etc:/etc/filebeat` as a named
volume, which hides anything you put at that path. The bind mount must come
**after** it in the list, so it wins:

```yaml
- filebeat_etc:/etc/filebeat
- ./filebeat-archives.yml:/etc/filebeat/filebeat.yml
```

That single line is the difference between a working archives pipeline and a
silent one. Upstream's sample does not include it.

---

## Everyday commands

```bash
docker compose ps                      # what is running
docker compose logs -f wazuh.manager   # follow manager logs
docker compose restart wazuh.manager   # restart one service
docker compose stop                    # stop, keep data
docker compose start                   # start again
docker compose down                    # remove containers, keep data
docker compose down -v                 # remove containers AND all data
```

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `wazuh.indexer` restarts in a loop | Host `vm.max_map_count` too low. On Docker Desktop, restart Docker; on Linux, `sudo sysctl -w vm.max_map_count=262144` |
| Dashboard shows "Wazuh API not reachable" | The manager is still starting. Give it two minutes, then `docker compose logs wazuh.manager` |
| `archives.json` never appears | `logall_json` is `no` in the *running* config — see the named-volume trap above |
| `archives.json` grows but no index appears | Filebeat is not shipping archives — the mount line above is missing |
| Index exists but Discover is empty | Wrong index pattern (`wazuh-alerts-*` instead of `wazuh-archives-*`), or the time picker is outside the traffic window |
| Port 514 already in use | Something else holds it. On Windows, `netstat -ano \| findstr :514` |

---

## What this is not

It is not a production Wazuh deployment. Passwords are the upstream defaults,
the certificates are self-signed, everything binds to all interfaces and there
is one node with no replicas. It exists to stand next to ULPF on one laptop
and show the same traffic through both.
