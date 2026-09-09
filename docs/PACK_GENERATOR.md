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

If the input is raw logs rather than an existing dead-letter stream, profile it
first. This keeps observable syntax, inferred family, and exact identity at
different confidence levels:

```bash
ulpf profile --input unknown.log --max-clusters 20 > source-profile.json
```

The console performs the same profile for every unknown cluster and displays
the evidence before either generator runs. A model suggestion cannot override
the deterministic identity gate: a vendor/product is emitted only when a
distinctive signature supports it; otherwise the candidate remains
`Unknown/Unknown` for the operator to identify from transport provenance or
device documentation.

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
   and a provisional class when family evidence is strong. `activity_id` stays
   `0` (Unknown) until a reviewer maps source-specific actions.
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
- check `unknown_ocsf_paths` in the candidate's generation response (empty in
  the console UI, non-empty and shown as a warning pill otherwise) — a path
  compiling and passing its own fixture proves a value reached that path, not
  that the path is a real OCSF attribute of the right type. This caught a
  real bug: an earlier version of both generators mapped a URL-like field
  straight to `url`, which is an *object* in OCSF (`url.url_string`,
  `.hostname`, `.path`, ...), not a string — the mapping compiled, the
  fixture passed, and the resulting event was still wrong. `ocsf_paths.rs`
  checks the fixed set of paths either generator can produce against the
  vendored schema; it is not wired into this approval gate as a hard
  rejection, because a hand-written pack may correctly use OCSF paths
  neither generator has ever been taught (`linux-iptables-firewall.yaml`'s
  `src_endpoint.interface_name` and class-specific `count`, for example) —
  read the warning, do not assume its absence covers every mistake;
- set `provenance.approved_by` and record the review in the pull request;
- copy the approved YAML into `packs/`, then restart ULPF.

The batch `ulpf draft` command never loads candidates automatically. In the
console, **Approve and deploy** writes a candidate to the configured packs
directory only after it compiles and passes its fixtures; the watcher then
reloads it. A candidate with no detector cannot claim all input. This keeps
generation outside the automatic ingestion path while reducing the time needed
to onboard an unfamiliar source.
