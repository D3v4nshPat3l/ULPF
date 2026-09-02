//! The Source Pack file format.
//!
//! A pack is one declarative YAML file describing how to recognise a log
//! source, pull fields out of it, and map those fields onto OCSF. It carries
//! its own test fixtures, so a pack can be scored before anyone trusts it —
//! which is what makes accepting an AI-drafted pack a reviewable act rather
//! than a leap of faith.
//!
//! Five sections:
//!
//! * `identity` — vendor, product, and the detectors that claim an event.
//! * `extract` — an ordered decoder chain producing named fields.
//! * `map` — field to OCSF attribute path, with coercions and enums.
//! * `enums` — named lookup tables shared by the mapping.
//! * `fixtures` — sample lines and what they must produce.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A complete Source Pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub identity: Identity,
    pub extract: Vec<ExtractStep>,
    pub map: BTreeMap<String, MapSpec>,
    #[serde(default)]
    pub enums: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    pub fixtures: Vec<Fixture>,
    #[serde(default)]
    pub provenance: Option<Provenance>,
}

/// Who this pack is for, and how to recognise their events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Stable pack identifier, e.g. `fortinet-fortigate-traffic`.
    pub id: String,
    pub vendor: String,
    pub product: String,
    #[serde(default)]
    pub version: Option<String>,
    /// Wire format label recorded in OCSF `metadata.log_format`.
    #[serde(default)]
    pub log_format: Option<String>,
    /// Any detector matching claims the event.
    #[serde(default)]
    pub detect: Vec<Detector>,
    /// Ordering hint: lower numbers are tried first. Use it to put a specific
    /// pack ahead of a broad one that would otherwise shadow it.
    #[serde(default)]
    pub priority: i32,
}

/// A cheap test for whether an event belongs to this source.
///
/// Detectors run against the raw text before any decoding, so identification
/// costs a substring search rather than a parse. `contains_all` is deliberately
/// the primary mechanism: perimeter devices stamp their own name and log type
/// into nearly every line, which makes for a fast and unambiguous signal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detector {
    /// Every string must be present.
    #[serde(default)]
    pub contains_all: Vec<String>,
    /// At least one string must be present, when non-empty.
    #[serde(default)]
    pub contains_any: Vec<String>,
    /// None of these may be present.
    #[serde(default)]
    pub contains_none: Vec<String>,
    /// Raw text must start with this.
    #[serde(default)]
    pub starts_with: Option<String>,
}

impl Detector {
    /// Whether this detector claims `raw`.
    pub fn matches(&self, raw: &str) -> bool {
        if let Some(prefix) = &self.starts_with {
            if !raw.starts_with(prefix.as_str()) {
                return false;
            }
        }
        if !self.contains_all.iter().all(|n| raw.contains(n.as_str())) {
            return false;
        }
        if !self.contains_any.is_empty()
            && !self.contains_any.iter().any(|n| raw.contains(n.as_str()))
        {
            return false;
        }
        if self.contains_none.iter().any(|n| raw.contains(n.as_str())) {
            return false;
        }
        // An empty detector must not claim everything.
        self.starts_with.is_some() || !self.contains_all.is_empty() || !self.contains_any.is_empty()
    }
}

/// One stage of the decoder chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractStep {
    /// Built-in decoder name, e.g. `syslog`, `keyvalue`, `csv`.
    pub decoder: String,
    /// Key/value separator, for `keyvalue`.
    #[serde(default)]
    pub sep: Option<char>,
    /// Pair delimiter for `keyvalue`, or column delimiter for `csv`.
    #[serde(default)]
    pub delim: Option<char>,
    /// Column names, for `csv`.
    #[serde(default)]
    pub headers: Vec<String>,
    /// Alternative patterns for `regex`, tried in order. Named capture groups
    /// become fields; a group named `body` narrows what the next step sees.
    #[serde(default)]
    pub patterns: Vec<String>,
    /// Treat a failure of this step as non-fatal and continue with what the
    /// previous steps produced. Useful for optional envelopes.
    #[serde(default)]
    pub optional: bool,
}

/// How one OCSF attribute is produced.
///
/// Variant order matters and is load-bearing. `serde(untagged)` tries variants
/// top to bottom, and `serde_json::Value` deserializes from *anything* — so
/// with `Literal` first, every field spec would be silently swallowed as a
/// literal object and no mapping would ever read a field. `Field` must be tried
/// first; it requires `from`, so a bare scalar falls through to `Literal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MapSpec {
    /// Derived from an extracted field.
    Field(FieldSpec),
    /// A constant, e.g. `class_uid: 4001`.
    Literal(serde_json::Value),
}

/// Derive an OCSF attribute from an extracted field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSpec {
    /// Source field name. The first one present wins, so a pack can express
    /// "whichever of these the firmware happens to emit".
    #[serde(alias = "from")]
    pub from: OneOrMany,
    /// Target type. Absent means keep the string.
    #[serde(default, rename = "as")]
    pub cast: Option<Cast>,
    /// Timestamp interpretation. Implies a nanosecond integer result.
    #[serde(default)]
    pub format: Option<TimeFormat>,
    /// Name of an entry in the pack's `enums` table.
    #[serde(default, rename = "enum")]
    pub enum_table: Option<String>,
    /// Used when the source field is absent or an empty marker.
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    /// Emit an observable of this type alongside the attribute.
    #[serde(default)]
    pub observable: Option<String>,
}

/// One field name, or several tried in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn candidates(&self) -> &[String] {
        match self {
            OneOrMany::One(s) => std::slice::from_ref(s),
            OneOrMany::Many(v) => v,
        }
    }
}

/// Target type for a mapped value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cast {
    Int,
    Float,
    Bool,
    String,
}

/// How to read a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeFormat {
    /// Seconds since the Unix epoch.
    EpochS,
    EpochMs,
    EpochUs,
    EpochNs,
    /// RFC 3339 / ISO 8601, e.g. `2026-08-31T10:23:45Z`.
    Rfc3339,
    /// `YYYY-MM-DD HH:MM:SS`, treated as UTC.
    DateTime,
    /// PAN-OS style `YYYY/MM/DD HH:MM:SS`, treated as UTC.
    SlashDateTime,
}

/// A sample line and what it must produce.
///
/// Fixtures live inside the pack so that `ulpf pack test` can validate the
/// whole library in CI, and so a generated pack arrives already scored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub raw: String,
    /// Expected OCSF attributes, by dotted path. Only the listed paths are
    /// checked, so a fixture states what matters rather than a whole event.
    #[serde(default)]
    pub expect: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Where a pack came from. Records whether a human approved a generated pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// `handwritten` or `generated`.
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub created: Option<String>,
    /// Dead-letter cluster this pack was drafted from.
    #[serde(default)]
    pub cluster_id: Option<String>,
    #[serde(default)]
    pub approved_by: Option<String>,
    /// Model identifier, when drafted by the pack generator.
    #[serde(default)]
    pub model: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_requires_all_of_contains_all() {
        let d = Detector {
            contains_all: vec!["devname=".into(), "type=traffic".into()],
            ..Default::default()
        };
        assert!(d.matches(r#"date=x devname="FGT" type=traffic srcip=1.1.1.1"#));
        assert!(!d.matches(r#"date=x devname="FGT" type=utm"#));
    }

    #[test]
    fn detector_contains_any_is_a_disjunction() {
        let d = Detector {
            contains_any: vec!["type=traffic".into(), "type=utm".into()],
            ..Default::default()
        };
        assert!(d.matches("type=utm foo"));
        assert!(d.matches("type=traffic foo"));
        assert!(!d.matches("type=event foo"));
    }

    #[test]
    fn detector_contains_none_excludes() {
        let d = Detector {
            contains_all: vec!["devname=".into()],
            contains_none: vec!["type=event".into()],
            ..Default::default()
        };
        assert!(d.matches("devname=x type=traffic"));
        assert!(!d.matches("devname=x type=event"));
    }

    #[test]
    fn an_empty_detector_claims_nothing() {
        // Otherwise a pack with a blank detector would swallow every event.
        assert!(!Detector::default().matches("anything at all"));
    }

    #[test]
    fn starts_with_anchors_at_the_front() {
        let d = Detector {
            starts_with: Some("CEF:".into()),
            ..Default::default()
        };
        assert!(d.matches("CEF:0|V|P|1|1|n|5|"));
        assert!(!d.matches("<134>CEF:0|V|P|1|1|n|5|"));
    }

    #[test]
    fn pack_parses_from_yaml() {
        let yaml = r#"
identity:
  id: test-pack
  vendor: Fortinet
  product: FortiGate
  log_format: syslog-keyvalue
  detect:
    - contains_all: ["devname=", "type=traffic"]
extract:
  - decoder: syslog
  - decoder: keyvalue
map:
  class_uid: 4001
  activity_id:
    from: action
    enum: fg_action
    default: 6
  src_endpoint.ip:
    from: srcip
    observable: ip
  src_endpoint.port:
    from: srcport
    as: int
enums:
  fg_action:
    accept: 6
    deny: 3
fixtures:
  - raw: 'devname="X" type=traffic srcip=10.0.0.1 srcport=443 action=accept'
    expect:
      src_endpoint.ip: 10.0.0.1
"#;
        let pack: Pack = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(pack.identity.id, "test-pack");
        assert_eq!(pack.extract.len(), 2);
        assert_eq!(pack.fixtures.len(), 1);
        assert!(matches!(pack.map["class_uid"], MapSpec::Literal(_)));
        assert!(matches!(pack.map["src_endpoint.ip"], MapSpec::Field(_)));
        assert_eq!(pack.enums["fg_action"]["accept"], serde_json::json!(6));
    }

    #[test]
    fn from_accepts_a_list_of_candidate_fields() {
        let yaml = r#"
identity: { id: t, vendor: v, product: p }
extract: [{ decoder: keyvalue }]
map:
  time:
    from: [eventtime, date, itime]
    format: epoch_s
"#;
        let pack: Pack = serde_yaml::from_str(yaml).unwrap();
        let MapSpec::Field(spec) = &pack.map["time"] else {
            panic!("expected a field spec");
        };
        assert_eq!(spec.from.candidates().len(), 3);
        assert_eq!(spec.format, Some(TimeFormat::EpochS));
    }
}
