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
    /// The line must carry an RFC 3164 program tag: `name:` or `name[pid]:`
    /// following the timestamp and hostname.
    ///
    /// A shape, not a literal, because a list of program names cannot be
    /// finished. `linux-syslog-host` shipped seventeen names and still missed
    /// `snmpd`, `sm-msp-queue` and every other daemon nobody happened to think
    /// of, so each new one arrived as a fresh "needs a pack" cluster forever.
    /// The tag's shape is what RFC 3164 actually defines, and that does not
    /// grow.
    #[serde(default)]
    pub syslog_tag: bool,
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
        if self.syslog_tag && !has_syslog_tag(raw) {
            return false;
        }
        // An empty detector must not claim everything.
        self.starts_with.is_some()
            || !self.contains_all.is_empty()
            || !self.contains_any.is_empty()
            || self.syslog_tag
    }
}

/// Whether `raw` carries an RFC 3164 program tag.
///
/// RFC 3164 §4.1.3 puts the tag at the head of the MSG part: an alphanumeric
/// name of up to 32 characters, optionally `[pid]`, then a colon. Anchored to
/// the header rather than searched for, so a colon anywhere in the message
/// body cannot be mistaken for one -- `kernel: ... proto=TCP: 80` has exactly
/// one tag, not two.
fn has_syslog_tag(raw: &str) -> bool {
    let rest = raw.trim_start();
    // Skip an optional <PRI>.
    let rest = match rest.strip_prefix('<') {
        Some(r) => match r.find('>') {
            Some(i) if i <= 3 => &r[i + 1..],
            _ => return false,
        },
        None => rest,
    };
    // Skip the RFC 3164 timestamp: "MMM d HH:MM:SS", 15 characters.
    if rest.len() < 16 {
        return false;
    }
    let rest = &rest[15..];
    let mut parts = rest.split_whitespace();
    // Hostname, then the tag.
    let Some(_host) = parts.next() else {
        return false;
    };
    let Some(tag) = parts.next() else {
        return false;
    };
    let Some(name) = tag.strip_suffix(':') else {
        return false;
    };
    // Strip an optional [pid].
    let name = match name.split_once('[') {
        Some((n, pid)) => {
            if !pid.ends_with(']') || !pid[..pid.len() - 1].chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
            n
        }
        None => name,
    };
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            // Parentheses because Linux PAM writes `su(pam_unix)[26013]:`,
            // which is the shape in the wild whatever the RFC says.
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '(' | ')'))
}

#[cfg(test)]
mod syslog_tag_tests {
    use super::has_syslog_tag;

    #[test]
    fn the_daemons_nobody_listed_are_recognised_by_shape() {
        // Every one of these arrived as its own "needs a pack" cluster
        // because it was not in the hand-written name list.
        assert!(has_syslog_tag(
            "Mar  6 16:24:13 combo sm-msp-queue[1755]: runqueue"
        ));
        assert!(has_syslog_tag(
            "Jun 20 04:44:39 combo snmpd[2318]: Received SNMP"
        ));
        assert!(has_syslog_tag("Mar  6 16:24:13 combo cups: started"));
        // Linux PAM's own shape, matched structurally rather than by name.
        assert!(has_syslog_tag(
            "Mar 13 04:10:10 combo su(pam_unix)[26013]: opened"
        ));
        assert!(has_syslog_tag(
            "<134>Feb 27 02:25:52 gizmo diskarray[7]: FAULT"
        ));
    }

    #[test]
    fn a_colon_in_the_message_is_not_a_tag() {
        // The failure that would make this claim everything: a bare syslog
        // line whose body merely contains a colon.
        assert!(!has_syslog_tag(
            "Mar  6 16:24:13 combo last message repeated 4 times"
        ));
        assert!(!has_syslog_tag("Mar  6 16:24:13 combo ratio was 3:1 today"));
    }

    #[test]
    fn non_syslog_shapes_are_refused() {
        assert!(!has_syslog_tag(""));
        assert!(!has_syslog_tag("short"));
        assert!(!has_syslog_tag(
            r#"{"ts":"2021-11-05T22:10:01Z","a":"b:c"}"#
        ));
        assert!(!has_syslog_tag(
            "218.23.48.35 - - [08/Feb/2005:19:50:39] \"GET /\""
        ));
    }

    #[test]
    fn a_malformed_pid_is_not_a_tag() {
        assert!(!has_syslog_tag("Mar  6 16:24:13 combo daemon[abc]: text"));
        assert!(!has_syslog_tag("Mar  6 16:24:13 combo daemon[12: text"));
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
    /// RFC 3164 syslog: `Mar 13 04:10:10`. The format carries no year, so the
    /// current year is assumed - which is what every syslog collector does, and
    /// is correct for live traffic but wrong for a historical replay.
    Rfc3164,
    /// NCSA Common Log Format: `10/Oct/2000:13:55:36 -0700`. Used by Apache,
    /// nginx and most reverse proxies, and it carries its own UTC offset.
    Clf,
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
