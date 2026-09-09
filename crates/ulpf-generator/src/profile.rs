//! Evidence-based profiling for records that no Source Pack claims.
//!
//! Profiling deliberately separates three questions:
//! 1. Which syntax/envelope is visible (JSON, CEF, syslog + key-value, ...)?
//! 2. Which broad source family does the vocabulary suggest?
//! 3. Is there enough distinctive evidence to name a vendor/product?
//!
//! The first is usually observable, the second is a ranked inference, and the
//! third is often unknowable. Separate confidences keep a plausible label from
//! silently becoming a production identity.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceHypothesis {
    pub vendor: String,
    pub product: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceProfile {
    pub sample_count: usize,
    pub wire_format: String,
    pub wire_format_confidence: f64,
    pub decoder_chain: Vec<String>,
    pub source_family: String,
    pub source_family_confidence: f64,
    pub suggested_class_uid: Option<i64>,
    pub source_hypotheses: Vec<SourceHypothesis>,
    pub extracted_field_names: Vec<String>,
    pub stable_detector_terms: Vec<String>,
    pub evidence: Vec<String>,
    pub warnings: Vec<String>,
    pub recommended_next_step: String,
}

#[derive(Clone, Copy)]
struct FamilyRule {
    name: &'static str,
    class_uid: Option<i64>,
    markers: &'static [(&'static str, f64)],
}

const FAMILY_RULES: &[FamilyRule] = &[
    FamilyRule {
        name: "network-firewall",
        class_uid: Some(4001),
        markers: &[
            ("firewall", 3.0),
            ("iptables", 4.0),
            ("filterlog", 4.0),
            ("deny", 1.8),
            ("drop", 1.8),
            ("accept", 1.2),
            ("action", 1.1),
            ("srcip", 1.5),
            ("dstip", 1.5),
            ("proto", 1.0),
        ],
    },
    FamilyRule {
        name: "intrusion-detection",
        class_uid: Some(2004),
        markers: &[
            ("suricata", 5.0),
            ("snort", 5.0),
            ("signature_id", 3.0),
            ("event_type", 2.0),
            ("classification", 2.5),
            ("alert", 1.8),
            ("sid", 1.5),
            ("intrusion", 2.5),
            ("priority", 1.0),
        ],
    },
    FamilyRule {
        name: "web-or-proxy",
        class_uid: Some(4002),
        markers: &[
            ("http", 2.3),
            ("https", 1.2),
            ("request", 1.5),
            ("uri", 1.8),
            ("url", 1.8),
            ("user_agent", 2.0),
            ("status", 1.0),
            ("proxy", 3.0),
            ("squid", 5.0),
            ("connect", 1.1),
        ],
    },
    FamilyRule {
        name: "identity-or-authentication",
        class_uid: Some(3002),
        markers: &[
            ("sshd", 5.0),
            ("authentication", 3.0),
            ("login", 2.0),
            ("logon", 2.0),
            ("logout", 2.0),
            ("password", 2.0),
            ("account", 1.3),
            ("username", 1.3),
            ("failed", 0.8),
        ],
    },
    FamilyRule {
        name: "email",
        class_uid: Some(4009),
        markers: &[
            ("sendmail", 5.0),
            ("postfix", 5.0),
            ("smtp", 3.0),
            ("message-id", 2.5),
            ("recipient", 1.5),
            ("relay", 1.2),
        ],
    },
    FamilyRule {
        name: "operating-system-or-audit",
        class_uid: Some(1008),
        markers: &[
            ("kernel", 2.2),
            ("systemd", 3.0),
            ("auditd", 5.0),
            ("eventid", 2.0),
            ("process", 1.0),
            ("pid", 1.0),
            ("service", 0.8),
            ("cbs", 3.0),
        ],
    },
    FamilyRule {
        name: "cloud-or-container",
        class_uid: None,
        markers: &[
            ("kubernetes", 5.0),
            ("container", 2.0),
            ("docker", 4.0),
            ("pod", 2.0),
            ("namespace", 1.5),
            ("aws", 3.0),
            ("azure", 3.0),
            ("gcp", 3.0),
            ("cloud", 1.8),
        ],
    },
    FamilyRule {
        name: "database",
        class_uid: None,
        markers: &[
            ("postgres", 5.0),
            ("mysql", 5.0),
            ("mongodb", 5.0),
            ("database", 2.5),
            ("query", 1.7),
            ("sql", 2.0),
            ("transaction", 1.2),
        ],
    },
    FamilyRule {
        name: "endpoint-security",
        class_uid: Some(2004),
        markers: &[
            ("malware", 4.0),
            ("antivirus", 4.0),
            ("edr", 4.0),
            ("quarantine", 3.0),
            ("threat", 2.0),
            ("process_hash", 2.5),
            ("detection", 1.5),
        ],
    },
];

/// Profile up to 100 representative records from one unknown-log cluster.
pub fn analyze(samples: &[String]) -> SourceProfile {
    let samples: Vec<String> = samples
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .take(100)
        .collect();
    if samples.is_empty() {
        return SourceProfile {
            sample_count: 0,
            wire_format: "unknown".into(),
            wire_format_confidence: 0.0,
            decoder_chain: Vec::new(),
            source_family: "unknown".into(),
            source_family_confidence: 0.0,
            suggested_class_uid: None,
            source_hypotheses: Vec::new(),
            extracted_field_names: Vec::new(),
            stable_detector_terms: Vec::new(),
            evidence: Vec::new(),
            warnings: vec!["No non-empty samples were supplied.".into()],
            recommended_next_step: "Collect several representative records from one source.".into(),
        };
    }

    let decoder_steps = crate::llm::infer_decoders(&samples);
    let decoder_chain: Vec<String> = decoder_steps
        .iter()
        .map(|d| match d.delim {
            Some(delim) => format!("{}('{}')", d.decoder, delim),
            None => d.decoder.to_string(),
        })
        .collect();
    let (wire_format, wire_format_confidence, mut evidence) =
        infer_wire_format(&samples, &decoder_chain);
    let extracted_field_names = crate::llm::available_field_names(&samples);
    let stable_detector_terms = crate::llm::derive_detectors(&samples);
    let vocabulary = Vocabulary::new(&samples, &extracted_field_names);
    let (source_family, source_family_confidence, suggested_class_uid, family_evidence, ambiguous) =
        infer_family(&vocabulary);
    evidence.extend(family_evidence);
    evidence.sort();
    evidence.dedup();

    let source_hypotheses = infer_products(&vocabulary, &wire_format);
    let mut warnings = Vec::new();
    if samples.len() == 1 {
        warnings.push(
            "Only one record was supplied; confidence can rise after observing variations from the same source."
                .into(),
        );
    }
    if ambiguous {
        warnings.push(
            "The top source families are close; keep the category provisional until more samples or transport metadata are available."
                .into(),
        );
    }
    if source_hypotheses.is_empty() {
        warnings.push(
            "No vendor/product signature is strong enough. Use Unknown identity rather than inventing one."
                .into(),
        );
    }
    if stable_detector_terms.is_empty() {
        warnings.push(
            "No stable detector literal was found; this draft must not be activated until a source-specific discriminator is added."
                .into(),
        );
    }
    if decoder_chain.iter().any(|d| d.starts_with("csv")) {
        warnings.push(
            "Delimited positional fields need vendor documentation or independently labelled examples before endpoint roles are approved."
                .into(),
        );
    }

    let recommended_next_step = if stable_detector_terms.is_empty() {
        "Collect 5-20 more records from the same transport/source and find a stable program, vendor, event-type or field-name marker before drafting a pack."
    } else if source_hypotheses.is_empty() {
        "Draft with an Unknown vendor/product, validate the proposed family and field meanings on held-out samples, then rename only when provenance identifies the source."
    } else {
        "Draft a candidate from diverse samples, verify the identity evidence and OCSF mappings on held-out records, then approve it for future traffic."
    }
    .into();

    SourceProfile {
        sample_count: samples.len(),
        wire_format,
        wire_format_confidence,
        decoder_chain,
        source_family,
        source_family_confidence,
        suggested_class_uid,
        source_hypotheses,
        extracted_field_names,
        stable_detector_terms,
        evidence,
        warnings,
        recommended_next_step,
    }
}

fn infer_wire_format(samples: &[String], decoders: &[String]) -> (String, f64, Vec<String>) {
    let n = samples.len() as f64;
    let fraction = |predicate: &dyn Fn(&str) -> bool| {
        samples.iter().filter(|s| predicate(s)).count() as f64 / n
    };
    let json = fraction(&|s| serde_json::from_str::<serde_json::Value>(s).is_ok());
    let cef = fraction(&|s| s.contains("CEF:"));
    let leef = fraction(&|s| s.contains("LEEF:"));
    let xml = fraction(&|s| {
        let t = s.trim_start();
        t.starts_with('<') && t.contains("</") && t.ends_with('>')
    });
    let kv = fraction(&|s| count_key_values(s) >= 2);
    let syslog = fraction(&looks_syslog_framed);

    let (body, body_score) = if cef >= 0.5 {
        ("cef", cef)
    } else if leef >= 0.5 {
        ("leef", leef)
    } else if json >= 0.5 {
        ("json", json)
    } else if xml >= 0.5 {
        ("xml", xml * 0.9)
    } else if kv >= 0.5 {
        ("keyvalue", kv * 0.9)
    } else if decoders.iter().any(|d| d.starts_with("csv")) {
        ("delimited", 0.78)
    } else {
        ("unstructured-text", 0.35)
    };
    let wire_format = if syslog >= 0.5 && !matches!(body, "cef" | "leef") {
        format!("syslog-{body}")
    } else {
        body.to_string()
    };
    let confidence = if syslog >= 0.5 {
        body_score.min(syslog).max(0.55)
    } else {
        body_score
    };
    let mut evidence = vec![format!(
        "Decoder chain inferred from observed syntax: {}.",
        if decoders.is_empty() {
            "none".into()
        } else {
            decoders.join(" -> ")
        }
    )];
    if syslog >= 0.5 {
        evidence.push(format!(
            "{:.0}% of samples have a syslog-like envelope.",
            syslog * 100.0
        ));
    }
    evidence.push(format!(
        "{:.0}% of samples support the selected body format.",
        body_score * 100.0
    ));
    (wire_format, round(confidence.clamp(0.0, 0.99)), evidence)
}

fn count_key_values(s: &str) -> usize {
    s.split_whitespace()
        .filter(|token| {
            token.split_once('=').is_some_and(|(key, _)| {
                !key.is_empty()
                    && key
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            })
        })
        .count()
}

fn looks_syslog_framed(s: &str) -> bool {
    let first = s.split_whitespace().next().unwrap_or_default();
    if first.starts_with('<') && first.find('>').is_some() {
        return true;
    }
    matches!(
        first.to_ascii_lowercase().as_str(),
        "jan"
            | "feb"
            | "mar"
            | "apr"
            | "may"
            | "jun"
            | "jul"
            | "aug"
            | "sep"
            | "oct"
            | "nov"
            | "dec"
    )
}

struct Vocabulary {
    original: String,
    joined: String,
    tokens: BTreeSet<String>,
    keys: BTreeSet<String>,
}

impl Vocabulary {
    fn new(samples: &[String], fields: &[String]) -> Self {
        let original = samples.join("\n");
        let joined = original.to_ascii_lowercase();
        let tokens = joined
            .split(|c: char| !c.is_ascii_alphanumeric() && !matches!(c, '_' | '-' | '.'))
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect();
        let keys = fields.iter().map(|k| k.to_ascii_lowercase()).collect();
        Self {
            original,
            joined,
            tokens,
            keys,
        }
    }

    fn has(&self, marker: &str) -> bool {
        let marker = marker.to_ascii_lowercase();
        self.keys.contains(&marker)
            || self.tokens.contains(&marker)
            || (marker.contains(|c: char| !c.is_ascii_alphanumeric())
                && self.joined.contains(&marker))
    }
}

fn infer_family(v: &Vocabulary) -> (String, f64, Option<i64>, Vec<String>, bool) {
    let mut ranked: Vec<(FamilyRule, f64, Vec<String>)> = FAMILY_RULES
        .iter()
        .map(|rule| {
            let mut score = 0.0;
            let mut hits = Vec::new();
            for (marker, weight) in rule.markers {
                if v.has(marker) {
                    score += weight;
                    hits.push((*marker).to_string());
                }
            }
            (*rule, score, hits)
        })
        .collect();
    ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.name.cmp(b.0.name)));
    let Some((best, score, hits)) = ranked.first() else {
        return ("unknown".into(), 0.0, None, Vec::new(), false);
    };
    if *score < 2.5 {
        return (
            "unknown".into(),
            round((*score / 10.0).clamp(0.0, 0.3)),
            None,
            vec!["No source-family vocabulary passed the minimum evidence threshold.".into()],
            false,
        );
    }
    let second = ranked.get(1).map(|r| r.1).unwrap_or(0.0);
    let ambiguous = second >= score * 0.8;
    let confidence = ((*score / 9.0) * if ambiguous { 0.72 } else { 1.0 }).clamp(0.25, 0.95);
    (
        best.name.into(),
        round(confidence),
        best.class_uid,
        vec![format!(
            "Source-family markers for {}: {}.",
            best.name,
            hits.join(", ")
        )],
        ambiguous,
    )
}

fn infer_products(v: &Vocabulary, wire_format: &str) -> Vec<SourceHypothesis> {
    let mut out = Vec::new();
    let mut add = |vendor: &str, product: &str, confidence: f64, terms: &[&str]| {
        if terms
            .iter()
            .all(|t| v.joined.contains(&t.to_ascii_lowercase()))
        {
            out.push(SourceHypothesis {
                vendor: vendor.into(),
                product: product.into(),
                confidence,
                evidence: terms.iter().map(|t| format!("literal `{t}`")).collect(),
            });
        }
    };
    add("Cisco", "ASA", 0.99, &["%asa-"]);
    add(
        "Fortinet",
        "FortiGate",
        0.97,
        &["devname=", "srcip=", "dstip="],
    );
    add(
        "Linux",
        "netfilter/iptables",
        0.96,
        &["kernel:", "src=", "dst=", "proto="],
    );
    add(
        "OISF",
        "Suricata EVE",
        0.98,
        &["\"event_type\"", "\"flow_id\""],
    );
    add("Snort", "NIDS", 0.97, &["[**]", "[classification:"]);
    add("pfSense", "filterlog", 0.98, &["filterlog:"]);
    add("OpenBSD", "OpenSSH", 0.97, &["sshd["]);
    add(
        "Zeek",
        "Connection Log",
        0.98,
        &["#fields", "id.orig_h", "id.resp_h"],
    );
    add(
        "Check Point",
        "Firewall",
        0.92,
        &["orig=", "action=", "xlatesrc="],
    );
    if let Some((vendor, product)) = explicit_envelope_identity(&v.original, wire_format) {
        out.push(SourceHypothesis {
            vendor: vendor.clone(),
            product: product.clone(),
            confidence: 0.99,
            evidence: vec![format!(
                "The {wire_format} header explicitly names vendor `{vendor}` and product `{product}`."
            )],
        });
    } else if matches!(wire_format, "cef" | "leef") {
        out.push(SourceHypothesis {
            vendor: "Unknown".into(),
            product: wire_format.to_ascii_uppercase(),
            confidence: 0.65,
            evidence: vec![format!("A {wire_format} envelope is visible, but its embedded vendor/product still needs validation.")],
        });
    }
    out.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
    out.dedup_by(|a, b| a.vendor == b.vendor && a.product == b.product);
    out
}

/// CEF and LEEF headers carry explicit vendor/product fields. Split only on
/// unescaped pipes: an escaped `\|` belongs to a header value.
fn explicit_envelope_identity(text: &str, wire_format: &str) -> Option<(String, String)> {
    let marker = match wire_format {
        "cef" => "CEF:",
        "leef" => "LEEF:",
        _ => return None,
    };
    let start = text.find(marker)?;
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in text[start..].chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '|' {
            fields.push(std::mem::take(&mut current));
            if fields.len() >= 3 {
                break;
            }
        } else {
            current.push(ch);
        }
    }
    // fields[0] is CEF:<version> / LEEF:<version>, followed by vendor/product.
    let vendor = fields.get(1)?.trim();
    let product = fields.get(2)?.trim();
    if vendor.is_empty() || product.is_empty() {
        None
    } else {
        Some((vendor.to_string(), product.to_string()))
    }
}

fn round(n: f64) -> f64 {
    (n * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn fortigate_is_a_high_confidence_hypothesis_not_a_guess() {
        let profile = analyze(&strings(&[
            r#"<134>date=2026-01-01 devname=FGT-1 type=traffic srcip=10.0.0.1 dstip=8.8.8.8 proto=6 action=accept"#,
            r#"<134>date=2026-01-02 devname=FGT-1 type=traffic srcip=10.0.0.2 dstip=1.1.1.1 proto=17 action=deny"#,
        ]));
        assert_eq!(profile.wire_format, "syslog-keyvalue");
        assert_eq!(profile.source_family, "network-firewall");
        assert_eq!(profile.suggested_class_uid, Some(4001));
        assert_eq!(profile.source_hypotheses[0].product, "FortiGate");
        assert!(profile.source_hypotheses[0].confidence > 0.9);
    }

    #[test]
    fn anonymous_json_stays_unknown_instead_of_inventing_a_vendor() {
        let profile = analyze(&strings(&[
            r#"{"time":"x","level":"warn","message":"worker stopped"}"#,
            r#"{"time":"y","level":"info","message":"worker started"}"#,
        ]));
        assert_eq!(profile.wire_format, "json");
        assert!(profile.source_hypotheses.is_empty());
        assert!(profile
            .warnings
            .iter()
            .any(|w| w.contains("Unknown identity")));
    }

    #[test]
    fn suricata_json_is_separated_from_generic_json() {
        let profile = analyze(&strings(&[
            r#"{"timestamp":"x","event_type":"alert","flow_id":7,"src_ip":"10.0.0.1","dest_ip":"8.8.8.8"}"#,
        ]));
        assert_eq!(profile.source_family, "intrusion-detection");
        assert_eq!(profile.suggested_class_uid, Some(2004));
        assert_eq!(profile.source_hypotheses[0].product, "Suricata EVE");
    }

    #[test]
    fn one_opaque_line_reports_low_confidence_and_no_identity() {
        let profile = analyze(&strings(&["2026-01-01 thing happened 18273"]));
        assert_eq!(profile.source_family, "unknown");
        assert!(profile.source_hypotheses.is_empty());
        assert!(profile
            .warnings
            .iter()
            .any(|w| w.contains("Only one record")));
    }

    #[test]
    fn empty_input_is_total() {
        let profile = analyze(&[]);
        assert_eq!(profile.sample_count, 0);
        assert_eq!(profile.wire_format_confidence, 0.0);
    }

    #[test]
    fn cef_header_identity_is_explicit_evidence() {
        let profile = analyze(&strings(&[
            r#"CEF:0|Acme\|Security|Edge Firewall|1.0|42|Blocked connection|7|src=10.0.0.1 dst=8.8.8.8"#,
        ]));
        assert_eq!(profile.wire_format, "cef");
        assert_eq!(profile.source_hypotheses[0].vendor, "Acme|Security");
        assert_eq!(profile.source_hypotheses[0].product, "Edge Firewall");
        assert_eq!(profile.source_hypotheses[0].confidence, 0.99);
    }
}
