# Real dataset protocol

ULPF performance and coverage claims must come from authentic, unmodified telemetry. Synthetic logs are useful only for repeatable load testing and must never be represented as coverage evidence.

## Public corpus used

The validated corpus is the Honeynet Project Scan of the Month 30 and 34 material:

| Local source | Records | Purpose |
|---|---:|---|
| `SotM30-anton.log` | 307,524 | iptables pack development and regression |
| `SotM34/iptables/iptablesyslog` | 179,752 | independent iptables cross-validation |
| `SotM34/snort/snortsyslog` | 69,039 | Snort NIDS validation |
| Combined | 556,315 | release benchmark |

The raw corpus is not committed because it is approximately 119 MB after concatenation and is independently available. Keeping it out of Git prevents history bloat and avoids silently relicensing third-party data.

Primary source pages:

- [Honeynet Project Scan 30](https://honeynet.onofri.org/scans/scan30/)
- [Honeynet Project Scan index](https://honeynet.onofri.org/scans/index.html)

## Local preparation

Place the extracted files in a sibling directory named `realdata`, matching the paths above. Then run:

```powershell
.\scripts\prepare-real-dataset.ps1
```

or:

```bash
./scripts/prepare-real-dataset.sh
```

The scripts concatenate bytes in the stated order and print the record count and SHA-256. The expected combined result for the local verified copy is:

- records: `556315`
- bytes: `119113071`

Because historical mirrors may package line endings differently, record count and the individual upstream checksums should be retained alongside any published benchmark. Never normalize line endings before a losslessness test.

## Run the real-corpus benchmark

```bash
./target/release/ulpf run \
  --packs packs \
  --vault data/benchmark/vault \
  --integrity-dir data/benchmark/integrity \
  --chain benchmark \
  --input testdata/real/all-perimeter.log \
  --output data/benchmark/events.ndjson \
  --dead-letter data/benchmark/dead-letter.ndjson
```

Record the CPU, RAM, operating system, Rust version, build profile, input hash, output counts, elapsed time, and vault size. Do not compare results from debug and release builds.

## Console evidence protocol

The README screenshots were captured from `ulpf serve` after selecting the unmodified `snortsyslog` file through the console. The browser processes only the first 2,000 non-empty lines per selection to keep the interactive request bounded. Those records travelled through the same vault, pack, OCSF, and integrity pipeline as CLI input.

## Synthetic benchmark

`tools/gen_bench.py` generates documentation-shaped FortiGate, PAN-OS, and CEF data. Use it for profiler comparisons only:

```bash
python tools/gen_bench.py 200000 > testdata/bench.log
```

Synthetic coverage is always 100% by construction and is not a product-quality metric.
