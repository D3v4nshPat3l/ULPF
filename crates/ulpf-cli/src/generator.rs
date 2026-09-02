//! Dead-letter clustering and candidate Source Pack generation.
//!
//! This command is intentionally conservative. It drafts a pack from repeated
//! raw shapes, embeds representative fixtures, and validates the YAML with the
//! normal pack compiler. Generated files carry provenance and are never loaded
//! into a running collector automatically. A local LLM can refine these
//! candidates later without becoming a trust boundary for ingestion. An
//! optional local sidecar can refine a candidate over a bounded JSON
//! stdin/stdout protocol; the deterministic path is always available.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use ulpf_pack::spec::{Detector, ExtractStep, Fixture, Identity, MapSpec, Pack, Provenance};

#[derive(Debug, Deserialize)]
struct DeadLetter {
    raw_text: String,
}

#[derive(Debug, serde::Serialize)]
struct Manifest {
    source: String,
    generator: String,
    records_read: usize,
    clusters: Vec<ClusterSummary>,
    approval_required: bool,
}

#[derive(Debug, serde::Serialize)]
struct ClusterSummary {
    id: String,
    records: usize,
    detector: Vec<String>,
    candidate: String,
}

struct Cluster {
    key: String,
    records: Vec<DeadLetter>,
}

/// Draft candidate packs from a dead-letter NDJSON stream.
pub fn draft(
    input: &Path,
    output_dir: &Path,
    max_clusters: usize,
    examples_per_cluster: usize,
    sidecar: Option<&Path>,
) -> anyhow::Result<()> {
    if max_clusters == 0 || examples_per_cluster == 0 {
        anyhow::bail!("max-clusters and examples-per-cluster must be greater than zero");
    }
    let file = std::fs::File::open(input)
        .with_context(|| format!("opening dead-letter stream {}", input.display()))?;
    let mut grouped: BTreeMap<String, Vec<DeadLetter>> = BTreeMap::new();
    let mut records_read = 0usize;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: DeadLetter = serde_json::from_str(&line)
            .with_context(|| format!("parsing dead-letter record {}", records_read + 1))?;
        records_read += 1;
        grouped
            .entry(template(&record.raw_text))
            .or_default()
            .push(record);
    }
    let mut clusters: Vec<Cluster> = grouped
        .into_iter()
        .map(|(key, records)| Cluster { key, records })
        .collect();
    clusters.sort_by_key(|cluster| std::cmp::Reverse(cluster.records.len()));
    clusters.truncate(max_clusters);
    std::fs::create_dir_all(output_dir)?;

    let mut summaries = Vec::new();
    for (index, cluster) in clusters.iter().enumerate() {
        let id = format!("ulpf-candidate-{:03}", index + 1);
        let detector = infer_detector(&cluster.records);
        let fixture_records = cluster.records.iter().take(examples_per_cluster);
        let fixtures: Vec<Fixture> = fixture_records
            .map(|record| Fixture {
                raw: record.raw_text.clone(),
                expect: [("class_uid".to_string(), serde_json::json!(4001))]
                    .into_iter()
                    .collect(),
                note: Some("Generated representative; refine mappings before approval.".into()),
            })
            .collect();
        let mut pack = baseline_pack(&id, &detector, fixtures, &cluster.key);
        if let Some(sidecar) = sidecar {
            pack = invoke_sidecar(
                sidecar,
                &id,
                &detector,
                &cluster.key,
                &cluster.records,
                pack.fixtures,
            )?;
        }
        let path = output_dir.join(format!("{id}.yaml"));
        let yaml = serde_yaml::to_string(&pack)?;
        std::fs::write(&path, yaml)?;
        let compiled = ulpf_pack::PackLibrary::load_file(&path)
            .with_context(|| format!("validating generated candidate {}", path.display()))?;
        let report = ulpf_pack::library::test_pack(&compiled);
        if !report.is_ok() {
            anyhow::bail!(
                "generated candidate {} failed its own fixtures: {:?}",
                id,
                report.failures
            );
        }
        summaries.push(ClusterSummary {
            id,
            records: cluster.records.len(),
            detector,
            candidate: path.display().to_string(),
        });
    }
    let manifest = Manifest {
        source: input.display().to_string(),
        generator: sidecar
            .map(|path| format!("sidecar:{}", path.display()))
            .unwrap_or_else(|| "deterministic-template-drafter".into()),
        records_read,
        clusters: summaries,
        approval_required: true,
    };
    std::fs::write(
        output_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    println!(
        "drafted {} candidate pack(s) from {} dead-letter record(s) into {}",
        manifest.clusters.len(),
        records_read,
        output_dir.display()
    );
    println!("candidates remain disabled until a human reviews and approves them");
    Ok(())
}

fn baseline_pack(id: &str, detector: &[String], fixtures: Vec<Fixture>, cluster_key: &str) -> Pack {
    Pack {
        identity: Identity {
            id: id.into(),
            vendor: "Unknown".into(),
            product: "Unidentified source".into(),
            version: None,
            log_format: Some("unknown".into()),
            detect: vec![Detector {
                contains_all: detector.to_vec(),
                ..Default::default()
            }],
            priority: 1000,
        },
        extract: vec![
            ExtractStep {
                decoder: "syslog".into(),
                sep: None,
                delim: None,
                headers: Vec::new(),
                patterns: Vec::new(),
                optional: true,
            },
            ExtractStep {
                decoder: "keyvalue".into(),
                sep: None,
                delim: None,
                headers: Vec::new(),
                patterns: Vec::new(),
                optional: true,
            },
        ],
        map: [
            (
                "class_uid".into(),
                MapSpec::Literal(serde_json::json!(4001)),
            ),
            ("activity_id".into(), MapSpec::Literal(serde_json::json!(1))),
        ]
        .into_iter()
        .collect(),
        enums: BTreeMap::new(),
        fixtures,
        provenance: Some(Provenance {
            author: Some("generated".into()),
            created: Some(ulpf_core::now_nanos().to_string()),
            cluster_id: Some(short_hash(cluster_key)),
            approved_by: None,
            model: Some("deterministic-template-drafter".into()),
        }),
    }
}

#[derive(Debug, Serialize)]
struct SidecarRequest<'a> {
    protocol: &'static str,
    candidate_id: &'a str,
    detector: &'a [String],
    records: Vec<&'a str>,
    constraints: SidecarConstraints,
}

#[derive(Debug, Serialize)]
struct SidecarConstraints {
    class_uid: i64,
    activity_id: i64,
    output: &'static str,
}

fn invoke_sidecar(
    executable: &Path,
    id: &str,
    detector: &[String],
    cluster_key: &str,
    records: &[DeadLetter],
    fixtures: Vec<Fixture>,
) -> anyhow::Result<Pack> {
    let request = SidecarRequest {
        protocol: "ulpf-pack-draft-v1",
        candidate_id: id,
        detector,
        records: records
            .iter()
            .take(32)
            .map(|record| record.raw_text.as_str())
            .collect(),
        constraints: SidecarConstraints {
            class_uid: 4001,
            activity_id: 1,
            output: "complete Source Pack YAML on stdout; retain class_uid=4001 and activity_id=1 until human approval",
        },
    };
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting local pack sidecar {}", executable.display()))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("pack sidecar stdin was not available"))?;
        serde_json::to_writer(&mut stdin, &request)?;
        stdin.write_all(b"\n")?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!(
            "pack sidecar exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if output.stdout.len() > 1_048_576 {
        anyhow::bail!("pack sidecar output exceeds the 1 MiB safety limit");
    }
    let mut pack: Pack = serde_yaml::from_slice(&output.stdout)
        .context("pack sidecar stdout was not a valid Source Pack YAML document")?;
    if !has_literal(&pack, "class_uid", 4001) || !has_literal(&pack, "activity_id", 1) {
        anyhow::bail!(
            "pack sidecar must retain class_uid: 4001 and activity_id: 1 placeholders until human approval"
        );
    }
    pack.identity.id = id.into();
    pack.identity.detect = vec![Detector {
        contains_all: detector.to_vec(),
        ..Default::default()
    }];
    pack.fixtures = fixtures;
    pack.provenance = Some(Provenance {
        author: Some("generated".into()),
        created: Some(ulpf_core::now_nanos().to_string()),
        cluster_id: Some(short_hash(cluster_key)),
        approved_by: None,
        model: Some(format!("sidecar:{}", executable.display())),
    });
    Ok(pack)
}

fn has_literal(pack: &Pack, key: &str, expected: i64) -> bool {
    matches!(
        pack.map.get(key),
        Some(MapSpec::Literal(value)) if value == &serde_json::json!(expected)
    )
}

fn template(raw: &str) -> String {
    raw.split_whitespace()
        .map(|token| {
            if token.parse::<std::net::IpAddr>().is_ok() {
                "<ip>".to_string()
            } else if token.parse::<u64>().is_ok() {
                "<number>".to_string()
            } else if token.len() > 24 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
                "<hex>".to_string()
            } else if let Some((key, _)) = token.split_once('=') {
                format!("{key}=<value>")
            } else {
                token.to_ascii_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn infer_detector(records: &[DeadLetter]) -> Vec<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for record in records {
        let mut seen = std::collections::BTreeSet::new();
        for token in record.raw_text.split_whitespace() {
            let candidate = token
                .split_once('=')
                .map(|(key, _)| format!("{key}="))
                .or_else(|| token.strip_suffix(':').map(|key| format!("{key}:")))
                .unwrap_or_else(|| token.to_string());
            if candidate.len() >= 4 && seen.insert(candidate.clone()) {
                *counts.entry(candidate).or_default() += 1;
            }
        }
    }
    let required = records.len();
    let mut detector: Vec<String> = counts
        .into_iter()
        .filter(|(_, count)| *count == required)
        .map(|(token, _)| token)
        .take(3)
        .collect();
    if detector.is_empty() {
        detector.push(
            records
                .first()
                .and_then(|record| record.raw_text.split_whitespace().next())
                .unwrap_or("unknown")
                .to_string(),
        );
    }
    detector
}

fn short_hash(value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("cluster-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_removes_volatile_values_but_keeps_shape() {
        assert_eq!(
            template("vendor src=10.2.3.4 port=443 id=00112233445566778899aabbccddeeff"),
            "vendor src=<value> port=<value> id=<value>"
        );
        assert_eq!(
            template("CEF:0|Acme|Gateway|1|7|blocked|5|"),
            "cef:0|acme|gateway|1|7|blocked|5|"
        );
    }

    #[test]
    fn detector_uses_tokens_shared_by_the_cluster() {
        let records = vec![
            DeadLetter {
                raw_text: "device=gw action=deny src=10.0.0.1".into(),
            },
            DeadLetter {
                raw_text: "device=gw action=allow src=10.0.0.2".into(),
            },
        ];
        assert_eq!(infer_detector(&records), vec!["action=", "device=", "src="]);
    }
}
