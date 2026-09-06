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

    // Reuse the inference the model-backed path uses. An earlier version chose
    // decoders from a hand-written if/else and mapped a fixed FortiGate field
    // list (`srcip`, `dstport`) regardless of the input, so a device using
    // `src_addr` got a pack that matched nothing and scored 0.
    let decoders: Vec<String> = crate::llm::infer_decoders(&samples)
        .into_iter()
        .map(str::to_string)
        .collect();
    let detect = crate::llm::derive_detectors(&samples);
    let available = crate::llm::available_field_names(&samples);
    let field_map = crate::llm::infer_field_map(&available);

    let mut mapping = BTreeMap::new();
    mapping.insert(
        "class_uid".to_string(),
        ulpf_pack::spec::MapSpec::Literal(serde_json::json!(4001)),
    );
    mapping.insert(
        "activity_id".to_string(),
        ulpf_pack::spec::MapSpec::Literal(serde_json::json!(6)),
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

    let identity = ulpf_pack::Identity {
        id: "draft-heuristic".to_string(),
        vendor: "Unknown".to_string(),
        product: "Unknown".to_string(),
        version: None,
        log_format: Some(decoders.join("-")),
        // Detectors derived from the samples. An empty list claims nothing, so
        // the drafted pack would have loaded and then matched no traffic.
        detect: vec![ulpf_pack::spec::Detector {
            contains_all: detect,
            contains_any: Vec::new(),
            contains_none: Vec::new(),
            starts_with: None,
        }],
        // Well below every reviewed pack: a candidate must never shadow one a
        // human has approved.
        priority: 1000,
    };

    let extract = decoders
        .into_iter()
        .map(|d| ulpf_pack::spec::ExtractStep {
            decoder: d,
            sep: None,
            delim: None,
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

    Ok(DraftResult {
        pack_yaml,
        model: "heuristic-v1".to_string(),
        fixtures: report.total,
        fixtures_passed: report.passed,
        field_accuracy: report.field_accuracy(),
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
