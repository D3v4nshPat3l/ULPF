# Scaling past one collector

One ULPF collector sustains **10,000 EPS lossless** ([THROUGHPUT.md](THROUGHPUT.md)).
The problem statement asks for a framework suitable for "billions of events per
day", which is 11,574 EPS sustained, and a 50,000 EPS target needs five times
what one node does.

This document is how that is reached, and — equally — why it is not reached by
making one collector faster.

## Why one collector does not go faster

The pipeline is single-writer by construction, and deliberately so:

- one vault, appended in order, so a locator is stable;
- one attestation chain, so event *N+1* links to event *N*;
- one Merkle log, so an inclusion proof means something.

Those are the properties requirements (a) and (d) are built on. Parallelising
inside a collector would mean either several chains behind one process — which
is sharding with extra steps — or locking around the chain, which serialises
the work again. The measured limits are the socket receive path (~10,000 EPS
lossless) and the per-event pipeline (~15,000 EPS from file). Neither is
five-times away from the target.

So the answer is more collectors, not a faster one.

## The shard model

Each collector is fully independent: its own UDP port, its own vault, its own
signing key, its own chain. Nothing is shared, so nothing needs coordinating,
and a shard that dies takes only its own tail block with it.

```text
             ┌── :5514  chain=collector-a  vault=/data/a  key=a ──┐
 devices ────┼── :5515  chain=collector-b  vault=/data/b  key=b ──┼──▶ SIEM / lake
             └── :5516  chain=collector-c  vault=/data/c  key=c ──┘
```

Traffic is divided by pointing groups of devices at different ports, or by
putting a UDP load balancer in front. Perimeter devices are configured with a
syslog destination, so splitting them across ports is a configuration change on
the estate, not a code change here.

### Running a shard

```bash
ulpf serve --packs packs \
  --vault /data/a/vault --integrity-dir /data/a/integrity \
  --chain collector-a --syslog-bind 0.0.0.0:5514 --port 8787
```

Each additional shard changes four values: `--vault`, `--integrity-dir`,
`--chain`, `--syslog-bind` (and `--port` if the console is exposed). The chain
name must be unique per shard; everything else follows from it.

## Verifying a sharded deployment

A merged stream from N collectors contains N chains. Verifying it as one would
report a break at the first point two collectors interleave — which is not
tampering, it is two independent logs in one file. `ulpf verify` therefore
partitions by `attestation_list[0].chain_uid` and verifies each chain on its
own:

```bash
ulpf verify merged.ndjson \
  --checkpoint /data/a/integrity/collector-a.checkpoint.json \
  --checkpoint /data/b/integrity/collector-b.checkpoint.json \
  --public-key /data/a/integrity/ed25519-signing.pub \
  --public-key /data/b/integrity/ed25519-signing.pub
```

```text
2 chains in this stream
[collector-a] OK  1000 events verified
[collector-a]     signed checkpoint verified
[collector-a]     trusted public key verified
[collector-b] OK  1000 events verified
[collector-b]     signed checkpoint verified
[collector-b]     trusted public key verified
```

`--public-key` is a **set**, not one key. Each shard generates its own signing
key inside its own integrity directory, so the trust statement being made is
"every chain was signed by one of my collectors" — which is what a set
expresses, and what keeps a shard's key from having to leave its host.

### One shard failing does not invalidate the others

Altering a single attribute on one event in `collector-b`:

```text
[collector-a] OK  1000 events verified
[collector-b] FAIL  fingerprint mismatch: event content has been altered
Error: 1 of 2 chains failed verification
```

The blast radius of a compromised or corrupted collector is its own chain. That
is the practical argument for sharding beyond throughput: it bounds what a
single failure can put in doubt.

## Capacity planning

| Shards | Sustained lossless | Events/day |
|---:|---:|---:|
| 1 | 10,000 EPS | 864 million |
| 2 | 20,000 EPS | 1.73 billion |
| 5 | 50,000 EPS | 4.32 billion |

These are the measured single-node figure multiplied by shard count. **They are
arithmetic, not a measurement**, and are stated as such: shards share no lock,
no chain and no file, so the model predicts linear scaling, but a multi-host
measurement has not been run.

### What has been measured

Two collectors on one machine, each on its own port, vault, key and chain, each
offered 60,000 records of the Honeynet SotM34 iptables capture at 12,000 EPS:

| Shard | Offered | Landed | Loss |
|---|---:|---:|---:|
| `shard-a` (:5610) | 60,000 | 60,000 | 0% |
| `shard-b` (:5611) | 60,000 | 60,000 | 0% |
| **Aggregate** | **120,000** | **120,000** | **0%** |

Two caveats, because this number is easy to over-read. It was taken on
different hardware from [THROUGHPUT.md](THROUGHPUT.md), so it must not be
compared with the 10,000 EPS figure there or blended into it. And both shards
shared one host's kernel and disk; the interference a real two-host deployment
avoids is therefore *not* what this measures. What it does establish is that
two independent chains absorb their traffic concurrently without loss and
verify separately afterwards — which is the property sharding depends on.

A genuine N-host measurement remains the outstanding work on this claim, and
belongs in [THROUGHPUT.md](THROUGHPUT.md) with the other measured numbers.

What *has* been verified on one machine is the part that is not arithmetic: two
independent collectors producing two chains, merged into one stream, each
verifying against its own key, and tampering in one detected without disturbing
the other.

## What this does not solve

- **Ordering across shards.** Events from different collectors have no relative
  order beyond their receipt timestamps. Nothing downstream should assume one.
- **A device's traffic must not be split** across shards mid-stream, or its
  records land in two chains. Split by device, not by packet.
- **The console is per-shard.** Each collector serves its own view of its own
  traffic; a unified operator view across shards is not built.
