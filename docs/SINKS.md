# ULPF sink operations

`ulpf run` always writes the selected NDJSON output. The optional sinks are a
fan-out, not a replacement for the raw vault or the signed chain. A sink error
returns a non-zero exit status; rerun with the same chain after fixing the
destination and use the checkpoint to identify the durable boundary.

## Parquet

Pass `--parquet data/run/events.parquet`. ULPF writes a self-contained,
uncompressed Parquet file without Python, Node.js, or a runtime plugin. Each
row group is bounded (250 events by default) and contains:

| Column | Type | Meaning |
|---|---|---|
| `event_json` | UTF-8 byte array | Complete compact OCSF event, including integrity and raw-vault locator metadata |
| `class_uid` | INT64 | OCSF event class |
| `activity_id` | INT64 | OCSF activity |
| `time` | INT64 | Event time in nanoseconds since Unix epoch |

The file is suitable for PyArrow, DuckDB, Spark, and other Parquet readers.
The JSON column is intentionally retained so a future schema revision cannot
make the archive lose fields.

## OpenSearch Bulk

Pass the base URL with `--opensearch`, for example
`http://127.0.0.1:9200`, and select an index with
`--opensearch-index ulpf-events`. ULPF appends `/_bulk`, sends newline-delimited
`index` actions followed by OCSF documents, and uses a bounded request body.

Set `ULPF_OPENSEARCH_TOKEN` when the endpoint expects a bearer token. The
current adapter deliberately speaks HTTP/1.1 only. Put it behind a local,
authenticated TLS reverse proxy for HTTPS deployments; do not put a bearer
token on an untrusted network.

## Splunk HEC

Pass the HEC endpoint with `--splunk-hec` and provide the token through the
environment variable named by `--splunk-token-env` (default:
`ULPF_SPLUNK_HEC_TOKEN`):

```powershell
$env:ULPF_SPLUNK_HEC_TOKEN = "..."
ulpf.exe run --splunk-hec http://127.0.0.1:8088/services/collector
```

Each line is an HEC event envelope with `source: ulpf` and
`sourcetype: ocsf`. Use the HEC endpoint's newline/batched-event mode or a
trusted proxy that converts the batch to the deployment's preferred format.

## UDP forward

Pass `--forward-udp 127.0.0.1:514`. Each normalized event is emitted as one
UDP datagram of compact OCSF JSON.

This exists for the side-by-side demonstration: the same captured traffic is
sent to an existing SIEM raw, then through ULPF and on to that same SIEM as
OCSF, so both forms land in one index and the difference is visible in one
view rather than described in prose. Syslog rather than the SIEM's indexer API
because every SIEM in this class already listens on 514 and needs no
credential, no index template and no TLS to accept a line.

Unlike the HTTP sinks, delivery is best-effort, which is the honest property of
UDP rather than something papered over:

| Counter | Meaning |
|---|---|
| `sent` | Datagrams handed to the socket |
| `failed` | Sends the OS refused |
| `oversized` | Events above 65,000 bytes, skipped rather than truncated |

All three are reported at shutdown. A failure here never fails the run, because
durability lives in the vault and the attestation chain, not in a fan-out
sink. Do not use this as a system of record; use it to put ULPF's output in
front of something that already exists.

## Delivery and recovery

Remote requests are bounded by `--sink-batch-size` (default 250). A response
outside HTTP 2xx fails the run, and an OpenSearch 2xx response with an item-level
`error` also fails the run. There is no silent drop or local retry loop that
could hide a partially accepted batch. OpenSearch receives deterministic event
documents and can be deduplicated downstream by `metadata.uid`. The vault and
checkpoint are authoritative, so operators can replay a bounded range after a
destination outage without losing the original bytes.

Sink paths are checked against the input, NDJSON output, and dead-letter path
before any output is created. HTTPS is intentionally terminated outside the
minimal offline binary so certificate policy stays with the deployment proxy.
