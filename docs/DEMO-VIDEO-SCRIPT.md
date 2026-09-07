# Two-minute demo video — shot list and narration

The submission asks for two minutes. That is roughly 300 spoken words, which is
less than it sounds: it buys about six shots. Everything below has been run on
the release binary, so nothing here needs discovering on the day.

**Rule for the whole recording: never show a slide.** The deck is a separate
deliverable. This video is the running system, and the one thing it must
establish is that the claims are real.

## Before you record

```bash
git pull
cargo build --release --locked
```

`cargo test` does **not** refresh `target/release/ulpf`. A stale binary presents
as missing features, which on camera looks like a broken project.

Start clean so the counters read plausibly and the chain is short:

```bash
rm -rf data/vault data/integrity events.ndjson
./target/release/ulpf serve --packs packs --vault data/vault --integrity-dir data/integrity --chain demo --datasets realdata
```

Set the terminal to a light background and at least 16pt — a dark terminal
recorded at 1080p and played on a projector is unreadable. Record at 1920×1080.
Close every other window; a notification popping up mid-take costs you a retake.

Have a second terminal already `cd`-ed into the repo, and `event.json` /
`proof.json` prepared in the working directory so no shot waits on typing.

---

## The six shots

### 1 · Cold open — the problem (0:00–0:12)

**Screen.** The `/dev` traffic simulator with four sources enabled, then the
console's event table filling.

> "Four devices, four formats, one screen. A firewall, an intrusion sensor, a
> web server and a mail server — none of them agree on how to describe an
> event. ULPF makes them agree, without touching what they actually sent."

### 2 · One schema (0:12–0:30)

**Screen.** Click one event. The detail panel opens: the plain sentence at the
top, then the OCSF fields with their names beside the numbers.

> "Every record is now OCSF 1.9.0. Class, activity, severity — each number
> carries the name the vendored schema gives it. Across three hundred thousand
> real records from public captures, ninety-nine point eight percent normalize.
> The remainder is listed, not rounded away."

### 3 · Nothing is discarded (0:30–0:45)

**Screen.** In the same panel, scroll to the raw bytes retrieved from the
vault. Put the original line and the normalized event side by side.

> "The original bytes were archived before anything tried to parse them. This
> is not a reconstruction — it is what the device sent, byte for byte, fetched
> back out of the vault by the locator every event carries."

### 4 · Tamper evidence (0:45–1:05)

**Screen.** Integrity → **Run verification** → passes. Then **Tamper test** →
**Alter this event**, showing the before and after value. Verify again.

> "Verification passes. Now change one field on one event out of hundreds."

*(let the failure land on screen before speaking again)*

> "Caught immediately. The vault is untouched, so the original is still there
> and still provably different from the altered record."

### 5 · Prove one record — the differentiator (1:05–1:40)

This is the shot worth the most. Give it the time.

**Screen.** Terminal.

```bash
./target/release/ulpf prove --integrity-dir data/integrity --chain demo --event event.json > proof.json
```

> "Challenged on a single record, the usual answer is to hand over the whole
> log so it can be replayed from the beginning. For a sensitive source that is
> not permitted at all."

**Screen.** `wc -c proof.json`, then:

```bash
./target/release/ulpf verify-proof --proof proof.json --public-key data/integrity/ed25519-signing.pub
```

> "A few hundred bytes. Verifying reads the proof and a public key — no vault,
> no chain, no other event. Certificate Transparency's Merkle construction,
> RFC 6962. A million events would need twenty hashes."

**Screen.** Change one character in `proof.json` and re-run. Let `Error:` show.

> "Change one character and it is rejected."

### 6 · Air-gapped, and close (1:40–2:00)

**Screen.** Disable the network adapter on camera. Return to the console and
click through a couple of views. Everything still works.

> "No CDN, no web font, no telemetry, no model on the hot path — the console is
> compiled into the binary. It ships as a container with a read-only root
> filesystem. Eleven of eleven requirements, and every number you have seen was
> measured, not estimated."

---

## What to cut if you overrun

In this order:

1. Shot 6's network-disable business — say the sentence over the console
   instead. Saves ~8s.
2. Shot 3 — the vault retrieval also appears inside shot 4's tamper result.
   Saves ~15s.

**Never cut shot 5.** It is the only thing in the video that no already-deployed
tool does.

## What not to do

- **Do not narrate the architecture.** Nobody watching a two-minute video
  retains a component diagram. Show the system answering questions.
- **Do not claim one billion events per day.** One collector sustains ten
  thousand a second, which is 864 million. If throughput comes up, say that
  figure and that the rest is a second machine.
- **Do not speed up footage.** If a step is slow, cut to the result instead —
  sped-up video reads as hiding something.
- **Do not use the simulator above 20 events/sec per source.** Seven sources at
  2,000 each is 14,000/sec, past the measured lossless ceiling, so it would
  drop records on camera while you claim nothing is lost.

## Checks before you submit the file

- Under two minutes.
- Every number spoken matches [README.md](../README.md): 838,779 perimeter
  records, 99.9219%, 10,000 EPS per collector, 34 packs, 64/64 fixtures,
  11 of 11 requirements.
- No slide, no logo animation, no stock music over the terminal audio.
- Readable when played at half size — check on a phone before submitting.
