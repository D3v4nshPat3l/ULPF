# Proving one event without disclosing the log

The hash chain proves a whole stream is intact, but only by replaying it.
Proving one record out of a million means handing over all million — slow, and
for a log that is itself sensitive, usually not permitted.

An inclusion proof answers the same question for a single record in
`ceil(log2 n)` hashes. Measured on a live collector: **11 hashes, 352 bytes,
out of 9,001 events**. The verifier learns nothing about the other 9,000.

## What a proof contains

```json
{
  "chain_uid": "console",
  "event_uid": "01a06fe5-74dc-77c1-9c38-482aebf28d28",
  "leaf_record": "7f15c79643b5a1c4fb682d35a30b5f6347bd22191501d098836...",
  "leaf_index": 513,
  "tree_size": 523,
  "path": ["5d2233...", "b1f175...", "0d548a...", "..."],
  "claimed_root": "b3016047283e17c0376d74de989a31db37a089cf2e675980...",
  "hash_algorithm": "sha256",
  "checkpoint": { "...the signed checkpoint this proof was made against..." }
}
```

`leaf_record` is the event's attestation fingerprint. `path` is the sibling
hashes from that leaf up to the root. `checkpoint` is the Ed25519-signed
statement of what the root was.

**The checkpoint is embedded on purpose.** The collector overwrites its
checkpoint file every few seconds, so a proof that merely *named* one would be
unverifiable almost immediately. Carrying it costs under a kilobyte and makes
the bundle self-contained: a verifier needs this file and a trusted public key,
nothing else. It is not trusted on its own — its signature is checked against a
key supplied out of band, exactly as if it had been read from disk.

## Making one

From the console: open any event, **Prove this event was logged**, *Generate
proof*. Copy it, or check it in place.

From the command line:

```bash
ulpf prove --integrity-dir data/integrity --chain console --event event.json > proof.json
```

Only leaves the last signed checkpoint commits to can be proved. The console
signs a checkpoint before building the proof, so anything on screen is
immediately provable; the CLI does not, so a very recent event may need a few
seconds. The error says which case you are in.

## Checking one

```bash
ulpf verify-proof --proof proof.json --public-key ed25519-signing.pub
```

```
PROOF VALID
  chain:            console
  event uid:        01a06d66-7b0a-7220-b252-47338dc8eead
  position:         120 of 300
  proof size:       9 hashes
  checkpoint:       verified against ed25519-signing.pub
```

Add `--event event.json` to also confirm a particular event is the one the
proof is about. Add `--checkpoint` to check against a checkpoint you hold
rather than the embedded copy.

`verify-proof` reads only the files it is given. No vault, no chain, no other
event.

Without `--public-key` it still runs, but reports `self-signed only`. Trusting
the key inside the checkpoint proves only that the file agrees with itself, so
that result is labelled rather than presented as a clean pass.

## What it refuses

Each of these is tested, and each fails differently because they are different
findings:

| | |
|---|---|
| Proof used with a different event | `fingerprints to X but the proof is for Y` |
| One sibling hash altered | `does not reproduce the signed root` |
| Forged `leaf_record` | `does not reproduce the signed root` |
| Embedded checkpoint's root or signature edited | `not signed by the supplied public key` |
| Checked with the wrong key | `not signed by the supplied public key` |
| Proof from a different log | `proof is for a tree of 300 leaves but the checkpoint signs 80` |
| Proof from an earlier, smaller tree | refused — see the test of the same name |

That last one is subtle and deliberate. A proof built when the log held 8
events must not pass against the root it grew into at 16, even though the leaf
is genuinely in both trees.

## A note on nanoseconds

`created_time` is nanoseconds since the epoch, around 1.8 × 10¹⁸ — past the
2⁵³ a JavaScript number holds exactly. Parsing a proof in a browser and
re-serializing it rounds that field and the signature stops matching, for a
reason nothing in the error would explain.

The console therefore never parses a proof it is going to send. `/api/proof`
returns the bundle as the whole response body, and the console shows, copies
and re-posts those exact bytes. Any other tool handling ULPF proofs — or ULPF
events, which carry nanosecond timestamps too — needs the same care.

## Construction

RFC 6962, the Certificate Transparency Merkle tree, including its domain
separation: leaves hash under a `0x00` prefix and interior nodes under `0x01`.
Without that an interior node could be presented as a record and proved,
despite never having been logged. There is a test for it.
