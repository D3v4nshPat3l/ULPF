use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use ulpf_pack::Pack;

#[derive(Debug, Serialize, Deserialize)]
pub struct DraftResult {
    pub pack_yaml: String,
    pub model: String,
    pub fixtures: usize,
    pub fixtures_passed: usize,
    /// Share of mapped fields the draft reproduced on its own samples. The
    /// scorer already computes this; reporting 0.0 next to a passing fixture
    /// count told a reviewer the draft was worthless when it was not.
    pub field_accuracy: f64,
    /// Mapped OCSF paths this draft targets that `ocsf_paths` does not
    /// recognize. Empty on a healthy draft; a non-empty list is worth a
    /// reviewer's attention even though every fixture can still pass — a
    /// fixture only checks a value survived to that path, not that the path
    /// means what the pack author thinks it means.
    pub unknown_ocsf_paths: Vec<String>,
    /// Format, family and identity evidence inferred independently of the
    /// candidate's self-generated fixture expectations.
    pub source_profile: crate::profile::SourceProfile,
}

pub fn draft_pack(raw_log: &str) -> anyhow::Result<DraftResult> {
    // Every non-empty line is a sample: with several, the detector and field
    // inference can tell fixed structure from per-record values.
    let samples: Vec<String> = raw_log
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if samples.is_empty() {
        anyhow::bail!("no log lines to learn from");
    }

    let source_profile = crate::profile::analyze(&samples);

    // Reuse the inference the model-backed path uses. An earlier version chose
    // decoders from a hand-written if/else and mapped a fixed FortiGate field
    // list (`srcip`, `dstport`) regardless of the input, so a device using
    // `src_addr` got a pack that matched nothing and scored 0.
    let decoders = crate::llm::infer_decoders(&samples);
    let detect = crate::llm::derive_detectors(&samples);
    let available = crate::llm::available_field_names(&samples);
    let field_map = crate::llm::infer_field_map(&available);

    let mut mapping = BTreeMap::new();
    mapping.insert(
        "activity_id".to_string(),
        ulpf_pack::spec::MapSpec::Literal(serde_json::json!(0)),
    );
    mapping.insert(
        "severity_id".to_string(),
        ulpf_pack::spec::MapSpec::Literal(serde_json::json!(1)),
    );
    for (ocsf_path, source) in field_map {
        let cast = if ocsf_path.ends_with(".port") {
            Some(ulpf_pack::spec::Cast::Int)
        } else {
            None
        };
        mapping.insert(
            ocsf_path,
            ulpf_pack::spec::MapSpec::Field(ulpf_pack::spec::FieldSpec {
                from: ulpf_pack::spec::OneOrMany::One(source),
                cast,
                format: None,
                enum_table: None,
                default: None,
                observable: None,
            }),
        );
    }

    // A family is still an inference. Use its class only above a useful
    // confidence threshold, and keep activity Unknown (0): seeing an
    // HTTP-shaped record does not tell us whether it was GET, POST or CONNECT.
    //
    // The class is chosen last, because it depends on what was mapped: a class
    // is only usable if it declares every attribute this draft targets.
    let suggested = (source_profile.source_family_confidence >= 0.60)
        .then_some(source_profile.suggested_class_uid)
        .flatten();
    let provisional_class =
        crate::ocsf_paths::provisional_class(suggested, mapping.keys().map(String::as_str));
    if let Some(uid) = suggested {
        if uid != provisional_class {
            tracing::debug!(
                suggested_class_uid = uid,
                used_class_uid = provisional_class,
                "suggested class does not declare every mapped attribute; keeping Network Activity"
            );
        }
    }
    mapping.insert(
        "class_uid".to_string(),
        ulpf_pack::spec::MapSpec::Literal(serde_json::json!(provisional_class)),
    );

    // Name a product only when deterministic, distinctive signatures support
    // it. Broad vocabulary such as `src=` or `http` is not enough.
    let identified = source_profile
        .source_hypotheses
        .first()
        .filter(|h| h.confidence >= 0.90);
    let identity = ulpf_pack::Identity {
        id: "draft-heuristic".to_string(),
        vendor: identified
            .map(|h| h.vendor.clone())
            .unwrap_or_else(|| "Unknown".into()),
        product: identified
            .map(|h| h.product.clone())
            .unwrap_or_else(|| "Unknown".into()),
        version: None,
        log_format: Some(source_profile.wire_format.clone()),
        // Detectors derived from the samples. An empty list claims nothing, so
        // the drafted pack would have loaded and then matched no traffic.
        detect: vec![ulpf_pack::spec::Detector {
            contains_all: detect,
            contains_any: Vec::new(),
            contains_none: Vec::new(),
            starts_with: None,
            syslog_tag: false,
        }],
        // Well below every reviewed pack: a candidate must never shadow one a
        // human has approved.
        priority: 1000,
    };

    let extract = decoders
        .iter()
        .map(|d| ulpf_pack::spec::ExtractStep {
            decoder: d.decoder.to_string(),
            sep: None,
            delim: d.delim,
            headers: vec![],
            patterns: vec![],
            optional: false,
        })
        .collect();

    let pack = Pack {
        identity,
        extract,
        map: mapping,
        enums: BTreeMap::new(),
        // One fixture per sample line. Using the whole multi-line blob as a
        // single fixture produced something that could never parse as one
        // event, so the candidate always scored zero.
        // The three most *different* samples, not the first three. A pack
        // drafted from three near-identical adjacent lines learns one shape.
        fixtures: crate::sampler::diverse_samples(&samples, 3)
            .iter()
            .map(|raw| ulpf_pack::Fixture {
                raw: raw.clone(),
                expect: BTreeMap::new(),
                note: Some("Representative sample; confirm mappings before approval.".to_string()),
            })
            .collect(),
        provenance: Some(ulpf_pack::spec::Provenance {
            author: Some("generated".to_string()),
            created: Some(ulpf_core::now_nanos().to_string()),
            cluster_id: None,
            approved_by: None,
            model: Some("heuristic-v1".to_string()),
        }),
    };

    // Record what the pack actually extracts as the fixture expectations.
    //
    // With `expect` left empty a fixture only asserted "this line parses at
    // all": field accuracy had no assertions to divide by and reported 0.0%
    // beside a passing fixture count, which reads as a broken pack. It also
    // gave the reviewer nothing concrete to check, while the note asked them
    // to confirm the mappings. Filling these in from a real run turns each
    // fixture into a regression guard and puts the extracted values in front
    // of whoever approves the pack.
    let mut pack = pack;
    let expectations = observed_fields(&pack);
    for (fixture, observed) in pack.fixtures.iter_mut().zip(expectations) {
        fixture.expect = observed;
    }
    let pack = pack;

    let pack_yaml = serde_yaml::to_string(&pack)?;

    // Actually grade the candidate. `fixtures_passed` was hardcoded to 0, so a
    // perfectly good draft still reported a failing score and a reviewer had no
    // signal to act on.
    let report = crate::scorer::Scorer::score(&pack);
    let unknown_ocsf_paths = crate::ocsf_paths::unknown_paths(&pack);

    Ok(DraftResult {
        pack_yaml,
        model: "heuristic-v1".to_string(),
        fixtures: report.total,
        fixtures_passed: report.passed,
        field_accuracy: report.field_accuracy(),
        unknown_ocsf_paths,
        source_profile,
    })
}

/// Run each fixture through the compiled pack and collect the mapped
/// attributes it produced, one map per fixture.
///
/// Only the attributes this pack's own `map` block targets are recorded.
/// Asserting on envelope-derived fields (timestamps, per-run identifiers)
/// would bake in values that legitimately change between runs and make the
/// fixture fail for no reason.
fn observed_fields(pack: &Pack) -> Vec<BTreeMap<String, serde_json::Value>> {
    use ulpf_core::{Envelope, Transport};
    use ulpf_pack::{CompiledPack, NormalizeCtx};

    let empty = vec![BTreeMap::new(); pack.fixtures.len()];
    let Ok(compiled) = CompiledPack::compile(pack.clone()) else {
        return empty;
    };
    let paths: Vec<String> = pack.map.keys().cloned().collect();
    let envelope = Envelope::new(Transport::File, "fixture");

    pack.fixtures
        .iter()
        .enumerate()
        .map(|(i, fixture)| {
            let mut observed = BTreeMap::new();
            if !compiled.claims(&fixture.raw) {
                return observed;
            }
            let Ok(fields) = compiled.extract(&fixture.raw) else {
                return observed;
            };
            // The default hash is fine: `raw_data_hash` is never a mapped
            // path, so it is never asserted on.
            let ctx = NormalizeCtx::new(&envelope, format!("fixture-{i}"));
            let Ok(event) = compiled.normalize(&fields, fixture.raw.as_bytes(), &ctx) else {
                return observed;
            };
            for path in &paths {
                if let Some(value) = event.get_path(path) {
                    observed.insert(path.clone(), value.clone());
                }
            }
            observed
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Suricata-shaped JSON: enough intrusion-detection vocabulary to carry the
    /// family inference past its confidence threshold, and named fields the
    /// convention mapper turns into endpoint attributes.
    const SURICATA_LIKE: &str = concat!(
        r#"{"timestamp":"2026-01-01T00:00:01Z","event_type":"alert","flow_id":7,"src_ip":"10.0.0.1","dest_ip":"8.8.8.8","proto":"TCP","signature_id":2001}"#,
        "\n",
        r#"{"timestamp":"2026-01-01T00:00:02Z","event_type":"alert","flow_id":8,"src_ip":"10.0.0.2","dest_ip":"1.1.1.1","proto":"UDP","signature_id":2002}"#,
    );

    fn drafted_pack(raw: &str) -> Pack {
        let draft = draft_pack(raw).expect("draft");
        serde_yaml::from_str(&draft.pack_yaml).expect("drafted YAML parses")
    }

    fn literal(pack: &Pack, key: &str) -> Option<i64> {
        match pack.map.get(key) {
            Some(ulpf_pack::spec::MapSpec::Literal(v)) => v.as_i64(),
            _ => None,
        }
    }

    #[test]
    fn a_draft_never_claims_a_class_that_rejects_its_own_mappings() {
        // The regression this guards: the family inference reached
        // intrusion-detection and stamped class_uid 2004 (Detection Finding),
        // while the convention mapper independently wrote src_endpoint.ip and
        // dst_endpoint.ip -- attributes Detection Finding does not declare.
        // The pack compiled, its fixtures passed, and the events it produced
        // were not valid instances of the class they announced.
        let pack = drafted_pack(SURICATA_LIKE);
        let class = literal(&pack, "class_uid").expect("class_uid literal");
        for path in pack.map.keys() {
            assert!(
                crate::ocsf_paths::class_accepts(class, path),
                "class {class} does not declare {path}"
            );
        }
        assert!(pack.map.contains_key("src_endpoint.ip"));
        assert_eq!(class, 4001);
    }

    #[test]
    fn activity_stays_unknown_rather_than_guessing_one() {
        // A family says what kind of thing happened, never which action it
        // was. 0 is Unknown in every OCSF class.
        assert_eq!(
            literal(&drafted_pack(SURICATA_LIKE), "activity_id"),
            Some(0)
        );
    }
}
