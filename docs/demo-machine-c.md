# Machine C — Wazuh (Ubuntu Server)

> **If you are an AI agent:** you are running on Machine C, one of three
> machines in a live demo. Only execute commands in this file — Machine A's
> and Machine B's commands live in `demo-machine-a.md` and
> `demo-machine-b.md` and are not yours to run. Placeholders look like
> `<<THIS>>` — ask the human operator for the real value before running a
> command that contains one. Steps marked **(manual)** happen in a browser,
> not a terminal. This machine already has Wazuh installed — these steps
> configure it to accept the demo traffic, they do not install it.

**What this machine does:** receives the same raw traffic Machine A
generates, independently of ULPF, using Wazuh's own decoders — the
"before" half of the before/after comparison.

**These exact commands have not been run against this specific Wazuh
install.** Wazuh's config syntax and default ports shift between releases —
verify each one against what's actually installed here, and fix this file
if something differs, the same way the rest of this repo's docs hold
themselves to "every command has been run."

---

## 1 · Find this machine's address

This machine's address is fixed for this team: **`10.60.197.6`**. Confirm
it against the network interface anyway — this also gives the exact
subnet mask needed in the next step:

```bash
ip -4 addr show | grep inet
```

Both other machines already know this address; nothing to send them.

## 2 · Confirm the subnet

Read the prefix off the `ip -4 addr show` output above — e.g. if it reports
`10.60.197.6/24`, the subnet for the next step is `10.60.197.0/24`. Don't
assume `/24`; use whatever this machine's own interface actually reports,
since a wrong mask here silently blocks Machine A or B later.

## 3 · Open Wazuh's manager config

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add this block inside `<ossec_config>...</ossec_config>`, alongside
whatever is already there — a stock Wazuh install only listens for its own
registered agents, not arbitrary incoming syslog, so without this block
nothing arrives at all:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.60.197.0/24</allowed-ips>
</remote>
```

Replace `10.60.197.0/24` with the real subnet from step 2 if it reported
something different.

Then, inside the existing `<global>...</global>` block, add or confirm:

```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```

This second part matters: by default Wazuh only turns a log into a visible
alert if one of its own rules matches it. Without `logall`/`logall_json`, a
raw line in a format Wazuh doesn't recognize can simply not appear anywhere
in the dashboard — making the "before" demo look empty rather than messy,
which undersells the point rather than making it.

## 4 · Apply and verify

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
sudo ss -ulnp | grep 514
```

The last command should show something listening on UDP 514. If it does
not, the manager did not pick up the config change — check
`sudo tail -50 /var/ossec/logs/ossec.log` for a parse error in the XML just
added.

## 5 · Open the firewall, if one is active

```bash
sudo ufw status
```

If it shows `active`:

```bash
sudo ufw allow from 10.60.197.0/24 to any port 514 proto udp
```

## 6 · Watch traffic arrive, independent of the dashboard

Once Machine A starts its simulator (its step 4), confirm arrivals directly
in the terminal rather than only trusting the UI:

```bash
sudo tail -f /var/ossec/logs/archives/archives.log
```

## 7 · The "before" shot

**(manual)** Open the Wazuh dashboard in a browser —
`https://10.60.197.6` (confirmed — plain HTTPS, no extra port). Log in with
this install's own credentials. Go to
**Threat Hunting → Discover**, and switch to the archives index if
**Alerts** looks sparse — that is `logall`/`logall_json` from step 3 doing
its job.

Look for: partial or missing field extraction depending on whether Wazuh
happens to have a decoder for that vendor, no shared schema across
different device types, and nothing anywhere resembling "prove this one
record is genuine without exposing the rest of the log."

**Before this is shown to anyone else:** test two or three of the
`realdata` corpora (coordinate with Machine A) and agree which one shows
the clearest contrast. Do not discover Wazuh's behavior on a given format
for the first time in front of a judge.

## After the switch (Machine A's step 5)

Nothing further to do here — Machine A repoints its traffic at Machine B
instead, and this machine's Wazuh listener simply stops receiving new
events. Leave it running so the "before" state stays visible if a judge
wants to look at both dashboards side by side.

## If something looks wrong

| Symptom | Likely cause |
|---|---|
| Nothing in `archives.log` | `allowed-ips` doesn't cover the hotspot subnet, or Machine A has this machine's IP wrong |
| `ss` shows nothing on :514 | The manager didn't restart cleanly, or the XML has a syntax error — check `ossec.log` |
| Dashboard shows nothing even with `logall` on | Confirm the index pattern in Discover is set to the archives index, not only the default alerts index |

Full narrative and the reasoning behind each step:
[3-LAPTOP-DEMO.md](3-LAPTOP-DEMO.md).
