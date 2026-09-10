# Demo video script — 3 minutes

SIH 2026 · PS 26156 · NTRO · Universal Log Pre-processing Framework

**Target: 180 seconds.** The shot list below is timed to 176, leaving four
seconds of headroom. Record the screen at 1920×1080; the console is designed to
read on a projector, so do not shrink the window.

If the submission cap turns out to be two minutes rather than three, cut in the
order given at the end — the script is built so the first 118 seconds stand on
their own.

**Before recording**, have all of this already running — never record a build
or a `docker compose up`:

```bash
docker compose -f deploy/demo-compose.yaml up -d --build
```

Wazuh dashboard open on Discover with `wazuh-archives-*` selected, time picker
on *Last 15 minutes*, `full_log` added as a column. ULPF console open at
<http://127.0.0.1:8787>, simulator at `/dev` in a second tab.

---

## Shot list

### 0:00 – 0:18 · The problem, in their own logs (18s)

**Screen:** Wazuh Discover, `full_log` column, sources already sending raw.

**Narration:**
> A firewall, an IDS and a proxy describing the same kind of event. Three
> vendors, three formats with nothing in common. There is no field to search
> on — an analyst asking "show me everything involving this address" has to
> know all three, and the other forty in the building.

**Direction:** Do not scroll fast. Let three visibly different lines sit on
screen. This shot is the entire justification for the project; if a viewer
does not feel the mess here, nothing after it lands.

---

### 0:18 – 0:30 · One click (12s)

**Screen:** Switch to the `/dev` tab. Press **ULPF** on the target switch.

**Narration:**
> Same traffic. Same capture files. One click sends it through ULPF first.

**Direction:** Show the cursor pressing the button. The switch is the pivot of
the whole video — make it unmistakable that nothing else changed.

---

### 0:30 – 0:54 · The same traffic, normalized (24s)

**Screen:** Back to Wazuh Discover. Refresh. Expand one new document.

**Narration:**
> The same records, in the same index, as OCSF. Every vendor now has
> `src_endpoint.ip`. One query covers all of them. Nothing was thrown away —
> that locator points back at the original bytes, and that fingerprint is
> chained to the event before it.

**Direction:** Expand the document and hold on three fields specifically:
`src_endpoint.ip`, `unmapped.ulpf_raw_locator`, `attestation_list`. Point at
each as it is named.

---

### 0:54 – 1:10 · The console (16s)

**Screen:** ULPF console Overview, traffic flowing.

**Narration:**
> The collector's own view. Coverage against OCSF, bytes vaulted before
> anything was parsed, and which Source Pack claimed each record.

**Direction:** The live table is the shot — several vendors resolving to one
schema at once, which is the "unified visibility" requirement in one frame.
Let the Pack column be readable; it is what shows the traffic is mixed.

---

### 1:10 – 1:36 · Nothing is lost, and tampering shows (26s)

**Screen:** Raw logs tab, then Integrity, then Tamper.

**Narration:**
> Every line is fetched back out of the vault by its locator — the fingerprint
> taken at ingest, beside one recomputed from the bytes that just came back.
> Now change one source IP on one event out of five hundred, and verify again.

**Direction:** Let the red failure sit on screen for a full two seconds:
`fingerprint mismatch: event content has been altered`. Then say the line
below over the still frame.

> The vault was never touched. The original is still there, and provably
> different.

---

### 1:36 – 2:12 · A device it has never seen (36s)

**Screen:** Simulator, switch on the unknown appliance. Console → Clusters.

**Narration:**
> A device with no pack. It is still vaulted, still fingerprinted, still
> searchable by indicator — and it is grouped into a template with an
> evidence-based profile. Note what it refuses to do: no vendor signature is
> strong enough, so it says Unknown rather than inventing a brand.

**Direction:** Show the warning text in the profile. That restraint is a
differentiator; most submissions guess.

> Draft a pack. Deterministic — no model, works air-gapped. Review it,
> approve it.

**Screen:** Click Heuristic, show the candidate, approve.

> Zero to a hundred percent on forty thousand records, with no parser written
> by hand.

---

### 2:12 – 2:34 · Prove one record, disclose nothing else (22s)

**Screen:** Terminal. `ulpf prove` then `ulpf verify-proof`, side by side with
the console still running.

**Narration:**
> Four hundred and sixteen bytes proving one record out of thirty-two million
> was in the log when the checkpoint was signed. It verifies against a public
> key alone — no vault, no chain, no other event. That is what makes an extract
> from a log you cannot share, shareable.

**Direction:** Let `PROOF VALID` and the `position: 1 of N` line be readable.
This shot is the answer to "how is this different from a parser", and two
minutes had no room for it.

---

### 2:34 – 2:56 · Scale and the evidence (22s)

**Screen:** Terminal, `python tools/measure_coverage.py` output already on
screen, then the throughput table.

**Narration:**
> Measured on real public capture data — Honeynet, Loghub, MACCDC — not
> synthesized. Every figure reproduces from one command in the repository.

**Direction:** Do not read numbers aloud; they will be stale by the time this
is judged. Let the table be visible and keep the claim about *method*.

---

### 2:56 – 3:00 · Close (4s)

**Screen:** The one-line architecture diagram from the README.

**Narration:**
> Any log in, OCSF out, nothing lost — and provably so.

---

## Rules for the recording

- **No terminal builds on camera.** Everything is already running.
- **No mouse hunting.** Rehearse the click path until it is muscle memory.
- **No reading numbers aloud.** They change; the method does not.
- **Do not claim what is not measured.** If a figure is a projection from a
  measured rate, the voiceover says "projected" or does not mention it.
- **One take per shot, cut between.** A continuous take will overrun.

## What to cut, in order, if you are over time

1. **The console shot** (0:54–1:10) — the comparison already showed the output.
2. **The proof shot** (2:12–2:34) — the strongest technical moment, but the
   only one that needs a terminal. Cutting it takes you to roughly two minutes.
3. **The scale shot** — the numbers are in the deck and the README.

Never cut the tamper shot or the one-click comparison. Those two are the
submission, and everything else is supporting material.
