# testdata

**This directory is synthetic. Nothing in it is evidence.**

`mixed.log` is 7,319 invented records mixing eight vendor formats — CEF,
iptables, Snort, Squid, FortiGate, PAN-OS, Juniper SRX and syslog — so that the
pipeline can be exercised immediately after a clone, without first downloading
the ~200 MB of real corpora that `tools/fetch_datasets.py` fetches.

It uses [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) documentation
addresses (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) precisely so
that it cannot be mistaken for a capture: no real network hands you 7,179 of
them.

## What it is for

```bash
ulpf run --packs packs --vault /tmp/v --integrity-dir /tmp/i \
  --input testdata/mixed.log --output /tmp/events.ndjson
```

Smoke-testing the pipeline, demonstrating that several formats normalize to one
schema, and generating load for a throughput run.

## What it is not for

Any coverage figure. Every number in [README.md](../README.md) and
[docs/DATASETS.md](../docs/DATASETS.md) comes from unmodified third-party
capture data, and `tools/measure_coverage.py` never reads this directory.

The distinction matters: a parser measured against logs its own authors wrote
proves only that they agree with themselves. See
[docs/CAPTURING-LOGS.md](../docs/CAPTURING-LOGS.md).
