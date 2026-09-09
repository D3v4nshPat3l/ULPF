# Onboarding completely unknown logs

ULPF should not answer every unfamiliar record with a confident vendor name.
Some logs contain an explicit product marker; others contain only a timestamp
and prose. This workflow records what is observable, ranks what is inferable,
and leaves what is unknowable as `Unknown` until provenance or documentation
settles it.

## The three identification levels

| Level | Example answer | Meaning |
|---|---|---|
| Wire format | `syslog-keyvalue` at 90% | The syntax supports a syslog envelope followed by key/value fields. |
| Source family | `network-firewall` at 78% | Field names and vocabulary resemble firewall events. This is a hypothesis. |
| Vendor/product | `Fortinet FortiGate` at 97% | Several distinctive literals occur together. Exact identity remains reviewable. |

These confidences are not probabilities produced by a trained classifier. They
are deterministic scores that make the evidence and uncertainty visible. They
are stable for the same samples and work inside an air gap.

## Raw-file workflow

```bash
ulpf profile --input unknown.log --max-clusters 20 > source-profile.json
```

`profile` does not assume one file equals one source. It groups lines with the
bounded Drain-inspired clusterer first. For every highest-volume shape it emits:

- record count, template and template specificity;
- inferred decoder chain and wire format;
- source family and provisional OCSF class, when evidence crosses the threshold;
- zero or more vendor/product hypotheses with the exact literals that triggered them;
- field names the inferred decoder can expose;
- stable detector terms that occur across the representative samples;
- ambiguity and single-sample warnings;
- a recommended next validation action.

An exact product is intentionally absent when the bytes do not identify one.
Transport metadata is usually the best missing evidence: the sending IP, syslog
configuration, asset inventory, collector listener or device export path can
identify a source more reliably than guessing from prose.

## Live-console workflow

1. Send records to the collector or paste them into Event inspector.
2. Known packs run first. Any non-parsed record remains vaulted and enters the
   bounded unknown-log clusterer.
3. Open **Needs a pack**. Each cluster shows format, family confidence and any
   supported product hypothesis. Hover for evidence and warnings.
4. Select deterministic **Heuristic** or local-model **AI Copilot** generation.
5. Review the profile and YAML together. The profile is independent of the
   candidate's self-generated fixture score.
6. Validate with held-out records from the same source. Add negative examples
   from similar sources so the detector does not shadow an installed pack.
7. Set exact class/activity, time, enum and endpoint semantics from authoritative
   evidence. Keep `activity_id: 0` while the action is still unknown.
8. Approve only after the candidate compiles, passes meaningful fixtures and
   has no unexplained OCSF-path warning. The watcher activates it for later
   records; signed historical events are not rewritten.

## Why the model cannot simply decide

The local model receives a deterministic pre-analysis and a closed set of field
names. Rust code still chooses the decoder chain, derives detector literals and
rejects an uncorroborated vendor/product guess. The model can help recognize
relationships, but it cannot create evidence that is absent from the input.

The heuristic and model-backed paths use diverse samples rather than the first
three adjacent lines. Both use a provisional source-family class only above a
confidence threshold. Both use `activity_id: 0`: category evidence cannot tell
whether an HTTP record is GET/POST, a firewall record is accept/deny, or an auth
record is logon/logoff.

## Approval checklist

- Are all samples actually from one source and event family?
- Is the format claim supported by syntax, not a filename?
- Does each exact identity hypothesis show distinctive evidence?
- Do detector terms stay constant on held-out records?
- Does the detector reject similar installed formats?
- Are source and destination roles independently known?
- Is event time distinguished from collector receipt time?
- Are OCSF class and activity valid for their meanings?
- Do fixtures contain independent expected values rather than only generated output?
- Has the candidate been tested on malformed, missing-field and unseen variants?

## Limits

- A record with no source marker cannot be attributed to an exact product from
  content alone.
- A family score is not device authentication and not a threat verdict.
- Clustering by textual shape can split one product or merge similar products.
- Positional CSV needs headers or documentation before columns have semantics.
- New binary/proprietary wire formats may require a new decoder in Rust, not
  only a YAML pack.
- Approval affects future processing. Reprocessing history is a separate,
  provenance-sensitive operation.
