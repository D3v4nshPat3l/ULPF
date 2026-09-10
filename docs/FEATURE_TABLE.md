# The feature table

A columnar table with a fixed column contract, for analytics and model
training. This is requirement (h).

```bash
ulpf run --packs packs --vault data/vault --integrity-dir data/integrity \
  --input logs.txt --output events.ndjson --features data/features
```

```bash
ulpf serve --packs packs --vault data/vault --integrity-dir data/integrity \
  --features data/features
```

Output is Hive-partitioned Parquet, one file per UTC day:

```
data/features/dt=2026-09-05/features-01a0702b-....parquet
```

## Why it is separate from `--parquet`

`--parquet` writes an archive: whole OCSF documents plus a few scalar columns.
That is right for retention and wrong for training.

A model consumer reading that archive re-derives every field from JSON, and
the shape they derive depends on what the packs happened to map. Add a pack,
change a mapping, and the effective schema moves underneath a model that was
trained on the old one — with nothing to signal that it moved.

The feature table fixes the shape instead. `COLUMNS` in
`crates/ulpf-cli/src/features.rs` is the whole contract:

- A pack that starts mapping a new attribute **does not** add a column.
- A pack that stops mapping one leaves its column present and empty.
- Adding a column is a deliberate edit to that file, recorded here, with
  `CONTRACT_VERSION` bumped.

The version travels in the Parquet footer, so a consumer can check what a file
was written against rather than assuming:

```python
import pyarrow.parquet as pq
pq.ParquetFile(path).metadata.created_by   # 'ulpf feature table v1'
```

## Contract version 1 — 24 columns

Twenty-four columns are written into each file. A reader that opens the
*directory* as a partitioned dataset sees a twenty-fifth, `dt`, which is not
stored in the file at all — it is the Hive partition key, derived by the reader
from the `dt=YYYY-MM-DD` directory name:

```python
pq.ParquetFile(one_file).schema_arrow.names   # 24
pq.read_table(feature_dir).column_names       # 25, the extra one is dt
```

Both are correct and neither is a contract change. Select columns by name
rather than by position if your consumer might be handed either.

| Column | Type | Meaning |
|---|---|---|
| `event_uid` | string | `metadata.uid`, unique per event |
| `time_ns` | int64 | Event time, nanoseconds since the epoch |
| `epoch_seconds` | int64 | The same instant in seconds |
| `pack_id` | string | Source pack that claimed the record |
| `vendor` | string | `metadata.product.vendor_name` |
| `product` | string | `metadata.product.name` |
| `disposition` | string | `parsed`, or why it was not |
| `class_uid` | int64 | OCSF class |
| `category_uid` | int64 | OCSF category |
| `activity_id` | int64 | Activity within the class |
| `type_uid` | int64 | `class_uid × 100 + activity_id` |
| `severity_id` | int64 | 0 Unknown … 6 Fatal |
| `src_ip` | string | `src_endpoint.ip` |
| `src_port` | int64 | `src_endpoint.port` |
| `dst_ip` | string | `dst_endpoint.ip` |
| `dst_port` | int64 | `dst_endpoint.port` |
| `protocol` | string | `connection_info.protocol_name` |
| `device_hostname` | string | `device.hostname` |
| `hour_of_day` | int64 | 0–23, UTC |
| `day_of_week` | int64 | 0 Monday … 6 Sunday, UTC |
| `src_is_private` | int64 | 1 when the source is RFC 1918, loopback, link-local or ULA |
| `dst_is_private` | int64 | Same, for the destination |
| `is_alert` | int64 | 1 when the event is an alert |
| `finding_uid` | string | Rule identifier, for detections |

### Absence

Every column is **required**, not nullable. A feature table is read densely,
and a null costs a branch on every row. Absence is a documented sentinel:

- **Numbers:** `-1`. Safe because no column above can legitimately be
  negative — a port is 0–65535, an enum id is non-negative, a timestamp in
  range is positive.
- **Text:** the empty string.

This is why `-1` and `0` are different answers: `dst_port = 0` means port
zero, `dst_port = -1` means the event had no destination port. A model that
treats them the same is wrong, and a table that used `0` for both would make
that mistake unavoidable.

### `time_ns` and `epoch_seconds`

Both are carried on purpose. Nanoseconds since the epoch is about 1.8 × 10¹⁸,
past the 2⁵³ that a float64 — and therefore JavaScript, and pandas' default
numeric handling in places — represents exactly. Anything going near JSON
should use `epoch_seconds`. `time_ns` is there when full precision matters.

## When the file becomes readable

Parquet keeps its schema and row-group index in a footer written when the
writer closes, so a file being appended to is not yet a valid Parquet file.

`ulpf run` closes its writers when the input ends. `ulpf serve` closes them on
Ctrl-C or SIGTERM — the signal `docker stop` and systemd send. Both print
`sinks closed` when it is done.

A collector killed outright (`kill -9`, power loss) leaves the current file
without a footer, and readers will reject it. The events themselves are not
lost: they are in the vault and in the signed chain, and the table can be
rebuilt by replaying them. Stop the collector properly if you care about the
current file.

## Reading it

```python
import pyarrow.parquet as pq

table = pq.read_table("data/features", partitioning="hive")
print(table.num_rows, table.schema.names)
```

DuckDB and Spark read the same files. The writer emits PLAIN-encoded,
uncompressed pages with a standard Thrift footer; nothing vendor-specific.

## What this does not do

- **No feature scaling, encoding or imputation.** Those are modelling choices
  and belong to whoever trains the model, not to the collector.
- **No text of the event.** If a model needs the message body, join back to
  the archive or the vault on `event_uid`.
- **No pack content digest yet.** `pack_id` says which pack produced a row,
  but a pack edited without a version bump is indistinguishable from its
  predecessor. Until a content hash is recorded, a training set is
  reproducible only as far as the pack files are unchanged. This is the next
  thing worth adding, and it is tracked in
  the roadmap in [README.md](../README.md#what-is-next).

## Changing the contract

1. Edit `COLUMNS` in `crates/ulpf-cli/src/features.rs`.
2. Bump `CONTRACT_VERSION`.
3. Update the table above.
4. Run the tests — several assert the row width and the declared types match.

Consumers pin the version they trained against and can then tell, from the
footer alone, whether a file matches.
