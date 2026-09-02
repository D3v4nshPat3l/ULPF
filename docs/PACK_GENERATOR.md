# Offline Source Pack generator

Unknown and malformed records are never discarded. When `ulpf run` receives
`--dead-letter data/run/dead-letter.ndjson`, each record contains the original
text (plus a lossy-safe hex copy for invalid UTF-8), its disposition, vault
locator, and receipt time. `ulpf draft` turns that stream into reviewable
candidate packs:

```bash
ulpf draft \
  --dead-letter data/run/dead-letter.ndjson \
  --output data/run/candidates \
  --max-clusters 20 \
  --examples-per-cluster 5
```

For teams with an approved local model runner, add `--sidecar path/to/runner`.
ULPF starts that executable without a shell, sends one JSON request using the
`ulpf-pack-draft-v1` protocol on stdin, and expects exactly one Source Pack YAML
document on stdout. The request contains the candidate id, conservative
detector, and raw cluster examples. Sidecar output is capped at 1 MiB, parsed
with `deny_unknown_fields`, forced back to the conservative detector, and sent
through the same fixture/compiler gate. The sidecar is never called during
event ingestion; at most 32 raw examples are sent per cluster, and no network
model is required.

## What the command does

1. Reads only the dead-letter stream; it does not fetch or execute remote code.
2. Replaces volatile IP addresses, numbers, long hexadecimal values, and
   key/value contents with placeholders to form deterministic templates.
3. Ranks recurring templates and chooses tokens shared by every record in a
   cluster as a conservative `contains_all` detector.
4. Writes one YAML pack per cluster with representative real fixtures,
   provenance (`author: generated`, cluster hash, and generator identifier),
   and a minimal class/activity mapping for human completion.
5. Loads each YAML through the same strict compiler used by production packs and
   runs its fixtures before reporting success.
6. Writes `manifest.json` with counts and `approval_required: true`.

The implementation is deliberately deterministic and air-gap compatible. It is
an offline parser *drafting* assistant rather than an opaque model in the
ingestion hot path. The deterministic path works without a model; the optional
sidecar protocol lets a local LLM improve mappings while preserving the same
compiler and fixture gate.

## Human approval gate

Before enabling a candidate:

- confirm the vendor, product, version, and wire format from an authoritative
  sample or device document;
- tighten detectors so the pack cannot shadow an existing source;
- replace the placeholder class/activity mappings and add typed fields,
  timestamps, enums, and observables;
- add fixtures covering accepted, rejected, missing, and malformed variants;
- run `ulpf test --packs packs` and inspect the candidate's field accuracy;
- set `provenance.approved_by` and record the review in the pull request;
- copy the approved YAML into `packs/`, then restart ULPF.

Generated candidates are never loaded automatically, and a candidate with no
detector cannot claim all input. This keeps parser generation outside the trust
boundary while reducing the time needed to onboard an unfamiliar source.
