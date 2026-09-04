# Measured throughput

The problem statement asks for a framework that scales to billions of events
per day. That is 11,574 EPS sustained, and this document measures what one
collector actually reaches — with the method and the losses stated plainly,
rather than the target asserted.

## Method

One host, loopback UDP, sender and collector on the same machine. The sender is
`ulpf replay`, which paces against absolute deadlines rather than sleeping per
datagram, so it is not itself the limit — it sustains **200,752 EPS** on this
machine, an order of magnitude above anything measured below.

The corpus is `iptables.log` (179,752 real records, Honeynet SotM34). Each run
sends exactly ten seconds of traffic at a fixed rate into a fresh vault and a
fresh attestation chain:

```bash
ulpf listen --packs packs --vault /tmp/b/vault --integrity-dir /tmp/b/integrity --bind 127.0.0.1:5610
ulpf replay --source ../realdata/iptables.log --target 127.0.0.1:5610 --eps 10000 --count 100000
```

"Received" is what the collector durably vaulted, fingerprinted, chained and
emitted. It is not a count of datagrams that touched the NIC.

## Results

| Offered rate | Sent | Received | Loss | Coverage |
|---:|---:|---:|---:|---:|
| 4,000 EPS | 40,000 | 40,000 | 0% | 100.0000% |
| 10,000 EPS | 100,000 | 100,000 | 0% | 100.0000% |
| 12,000 EPS | 120,000 | 118,000 | 1.7% | 100.0000% |
| 15,000 EPS | 150,000 | 125,000 | 16.7% | 100.0000% |

**The sustained lossless ceiling is 10,000 EPS per collector**, single node,
with every accepted record durable before it is emitted.

Coverage stays at 100% throughout: what is lost is lost in the kernel before
ULPF sees it, so nothing is half-processed and no record is silently
misparsed. The distinction matters — a drop is a missing event, not a wrong
one.

## Against the 1B/day target

One billion events per day is 11,574 EPS sustained. A single collector on this
hardware does not reach it: 10,000 EPS is 864 million/day, about 86% of the
target. Reaching 1B/day needs two collectors, which the architecture already
allows — chains are per-collector and verify independently, so a second node is
a deployment decision, not a code change.

Stating this as "meets 1B/day" would require the 12,000 EPS row, and that row
drops 1.7% of records. For a log collector that is not a rounding error; it is
the failure mode the whole design exists to prevent.

## Two limits found by measuring

**The socket receive buffer.** The OS default is about 64 KB, which for
~150-byte syslog records is roughly 400 datagrams. At 15,000 EPS that lost 37%
of records, and UDP tells the sender nothing — the collector just reports a
lower number with no indication why. `ulpf listen` now requests an 8 MB receive
buffer and prints what the kernel actually granted. The same run then lost
16.7% instead of 37%.

**Per-datagram checkpointing.** Signing and fsyncing a checkpoint after every
event cost an Ed25519 signature plus a synchronous write per record, and
measured **102 EPS** — against roughly 15,000/sec for the same records read
from a file. Checkpoints are now written every 500 events or 5 seconds. This
costs nothing in tamper evidence: the per-event hash chain is what detects
modification, and a checkpoint only bounds how far back a verifier must walk to
reach a signed anchor.

Together these took the collector from 102 EPS to 10,000 EPS lossless.

## Reproducing

```bash
cargo build --release --locked
python tools/fetch_datasets.py
```

Then run the two commands at the top of this document, varying `--eps`. The
collector prints a running `received / parsed / coverage` line every 1,000
events; compare its final count against `--count`.
