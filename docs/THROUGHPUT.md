# Measured throughput

The problem statement asks for a framework that scales to billions of events
per day. That is 11,574 EPS sustained, and this document measures what one
collector actually reaches — with the method and the losses stated plainly,
rather than the target asserted.

## Two rates, and which machine each came from

This document reports **UDP ingest**: how fast a collector can be *sent*
records over the network before the kernel starts discarding them. That
ceiling is bounded by the socket, not by the pipeline.

It is a different measurement from **file ingest**, which is how fast the
pipeline processes records it already has. Measured on the current machine
over the Blue Coat capture — 8,130,590 real records, end to end, vaulted,
parsed, normalized, fingerprinted and chained — that is **13,290 events/sec**,
which projects to 1,148,256,000 events per day per collector.

That projection is arithmetic on a measured rate (rate × 86,400). It is not a
claim to have ingested that many records, and the two rates must not be quoted
interchangeably.

The UDP table below was measured on a different machine and predates the
removal of a quadratic Merkle-root recomputation that cost roughly 5× on large
runs, so it is a floor rather than a current figure. Reproduce it here with:

```bash
python tools/measure_throughput.py
```

which runs the method below automatically and prints the events/day projection
alongside it.

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
ulpf replay --source realdata/iptables.log --target 127.0.0.1:5610 --eps 10000 --count 100000
```

"Received" is what the collector durably vaulted, fingerprinted, chained and
emitted. It is not a count of datagrams that touched the NIC.

## Results

Measured on this machine with `python tools/measure_throughput.py`, fifteen
seconds of traffic per rate into a fresh vault and a fresh attestation chain.

| Offered rate | Sent | Received | Loss | Coverage |
|---:|---:|---:|---:|---:|
| 4,000 EPS | 60,000 | 60,000 | 0% | 100.0000% |
| 8,000 EPS | 120,000 | 120,000 | 0% | 100.0000% |
| 12,000 EPS | 180,000 | 171,000 | 5.0% | 100.0000% |
| 16,000 EPS | 240,000 | 195,000 | 18.8% | 100.0000% |
| 20,000 EPS | 300,000 | 188,000 | 37.3% | 100.0000% |
| 25,000 EPS | 375,000 | 203,000 | 45.9% | 100.0000% |
| 30,000 EPS | 450,000 | 239,000 | 46.9% | 100.0000% |

**The sustained lossless ceiling is 8,000 EPS per collector**, single node,
with every accepted record durable before it is emitted.

Coverage stays at 100% throughout: what is lost is lost in the kernel before
ULPF sees it, so nothing is half-processed and no record is silently
misparsed. The distinction matters — a drop is a missing event, not a wrong
one.

### A measurement bug worth recording

An earlier version of this table reported an identical 70,000 received at
every rate from 8,000 EPS upward. That is not how loss behaves, and it was not
the collector's ceiling: it is what an 8 MB receive buffer holds in ~120-byte
records. The harness terminated the collector five seconds after the sender
stopped, so the buffer never finished draining, and the buffer's capacity was
being read back as a throughput limit.

The harness now follows the collector's counter as it advances and stops when
it stops moving. The figures above are from after that fix. It is recorded
here because the failure mode is not obvious — a flat number across rates
reads like a hard limit rather than like a bug in how it was taken.

## Two limits found by measuring## Two limits found by measuring

**The socket receive buffer.** The OS default is about 64 KB, which for
~150-byte syslog records is roughly 400 datagrams. UDP tells the sender nothing when this happens — the collector just reports a
lower number with no indication why. `ulpf listen` now requests an 8 MB receive
buffer and prints what the kernel actually granted.

**Per-datagram checkpointing.** Signing and fsyncing a checkpoint after every
event cost an Ed25519 signature plus a synchronous write per record, and
measured **102 EPS** — against roughly 15,000/sec for the same records read
from a file. Checkpoints are now written every 500 events or 5 seconds. This
costs nothing in tamper evidence: the per-event hash chain is what detects
modification, and a checkpoint only bounds how far back a verifier must walk to
reach a signed anchor.

Together these took the collector from 102 EPS to the figures above.

## Reproducing

```bash
cargo build --release --locked
python tools/fetch_datasets.py
```

Then run the two commands at the top of this document, varying `--eps`. The
collector prints a running `received / parsed / coverage` line every 1,000
events; compare its final count against `--count`.
