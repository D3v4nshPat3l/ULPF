//! The OCSF event document.
//!
//! An event is held as a JSON object rather than a static struct. Source Packs
//! map arbitrary device fields onto arbitrary OCSF paths, and 88 event classes
//! sharing one code path is only possible if the target is dynamic. What is
//! *not* dynamic is the base contract: [`EventBuilder`] refuses to produce an
//! event missing any of the seven attributes OCSF marks required, so an invalid
//! event cannot be constructed by accident.

use serde_json::{json, Map, Value};

use crate::jcs;
use crate::types::{Fingerprint, Metadata, Observable, Severity};

/// OCSF schema version this build targets. Kept in step with `schema/ocsf`.
pub const SCHEMA_VERSION: &str = "1.9.0";

#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("missing required OCSF attribute `{0}`")]
    MissingRequired(&'static str),

    #[error("cannot traverse `{path}`: `{segment}` is a {found}, not an object")]
    PathConflict {
        path: String,
        segment: String,
        found: &'static str,
    },

    #[error("empty attribute path")]
    EmptyPath,

    #[error(transparent)]
    Canonicalization(#[from] jcs::JcsError),
}

pub type Result<T> = std::result::Result<T, EventError>;

/// A normalized OCSF event.
#[derive(Debug, Clone, PartialEq)]
pub struct OcsfEvent {
    doc: Map<String, Value>,
}

impl OcsfEvent {
    /// Wrap an existing object, e.g. one read back from a sink for verification.
    pub fn from_map(doc: Map<String, Value>) -> Self {
        Self { doc }
    }

    pub fn as_map(&self) -> &Map<String, Value> {
        &self.doc
    }

    pub fn as_map_mut(&mut self) -> &mut Map<String, Value> {
        &mut self.doc
    }

    pub fn into_value(self) -> Value {
        Value::Object(self.doc)
    }

    pub fn to_value(&self) -> Value {
        Value::Object(self.doc.clone())
    }

    /// Read an attribute by dotted path.
    pub fn get_path(&self, path: &str) -> Option<&Value> {
        let mut cur = self.doc.get(path.split('.').next()?)?;
        for seg in path.split('.').skip(1) {
            cur = cur.as_object()?.get(seg)?;
        }
        Some(cur)
    }

    /// Write an attribute by dotted path, creating intermediate objects.
    ///
    /// This is the single entry point every Source Pack mapping goes through,
    /// so it fails loudly rather than silently discarding a value when a path
    /// collides with an existing scalar — `src_endpoint` cannot be both a
    /// string and the parent of `src_endpoint.ip`, and a pack that says both is
    /// a bug worth surfacing.
    pub fn set_path(&mut self, path: &str, value: Value) -> Result<()> {
        let mut segments = path.split('.').peekable();
        let mut cur = &mut self.doc;
        let mut walked = String::new();

        while let Some(seg) = segments.next() {
            if seg.is_empty() {
                return Err(EventError::EmptyPath);
            }
            if segments.peek().is_none() {
                cur.insert(seg.to_string(), value);
                return Ok(());
            }

            if !walked.is_empty() {
                walked.push('.');
            }
            walked.push_str(seg);

            let entry = cur
                .entry(seg.to_string())
                .or_insert_with(|| Value::Object(Map::new()));

            if !entry.is_object() {
                return Err(EventError::PathConflict {
                    path: path.to_string(),
                    segment: walked,
                    found: value_kind(entry),
                });
            }
            cur = entry.as_object_mut().expect("checked is_object above");
        }
        Err(EventError::EmptyPath)
    }

    /// Append an observable, creating the list if absent.
    pub fn push_observable(&mut self, obs: Observable) {
        let list = self
            .doc
            .entry("observables".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(items) = list {
            if let Ok(v) = serde_json::to_value(obs) {
                items.push(v);
            }
        }
    }

    /// Record an unmappable field under OCSF `unmapped`.
    ///
    /// Requirement (a) is about the raw bytes, but losslessness at the
    /// *structured* level matters too: a field the pack extracted but had no
    /// OCSF home for is kept here rather than dropped, so a later schema
    /// version or a revised pack can pick it up without a reparse.
    pub fn set_unmapped(&mut self, key: &str, value: Value) {
        let slot = self
            .doc
            .entry("unmapped".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(map) = slot {
            map.insert(key.to_string(), value);
        }
    }

    pub fn class_uid(&self) -> Option<i64> {
        self.doc.get("class_uid")?.as_i64()
    }

    pub fn type_uid(&self) -> Option<i64> {
        self.doc.get("type_uid")?.as_i64()
    }

    /// `metadata.uid` — this event's identifier.
    pub fn uid(&self) -> Option<&str> {
        self.get_path("metadata.uid")?.as_str()
    }

    /// RFC 8785 canonical serialization of the whole event.
    ///
    /// Serializes from the borrowed map rather than `to_value()`, which would
    /// deep-clone the entire event on every attestation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(jcs::canonicalize_map_bytes(&self.doc)?)
    }

    /// Serialize as compact JSON.
    ///
    /// Serializes the borrowed map directly; wrapping it in an owned `Value`
    /// first would deep-clone the event on every emit.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.doc).expect("a JSON map serializes infallibly")
    }
}

fn value_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Builds an OCSF event, enforcing the base-class required attributes.
///
/// OCSF marks `activity_id`, `category_uid`, `class_uid`, `metadata`,
/// `severity_id`, `time` and `type_uid` as required on every event. `type_uid`
/// is derived rather than supplied, because it is a pure function of the other
/// two and hand-setting it is a reliable source of invalid events.
#[derive(Debug, Default)]
pub struct EventBuilder {
    class_uid: Option<i64>,
    activity_id: Option<i64>,
    time: Option<i64>,
    severity_id: Option<u8>,
    metadata: Option<Metadata>,
    doc: Map<String, Value>,
}

impl EventBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the event class. `category_uid` is derived from it.
    pub fn class(mut self, class_uid: i64) -> Self {
        self.class_uid = Some(class_uid);
        self
    }

    pub fn activity(mut self, activity_id: i64) -> Self {
        self.activity_id = Some(activity_id);
        self
    }

    /// Event time in nanoseconds since the Unix epoch.
    pub fn time(mut self, nanos: i64) -> Self {
        self.time = Some(nanos);
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity_id = Some(severity as u8);
        self
    }

    pub fn severity_id(mut self, id: u8) -> Self {
        self.severity_id = Some(id);
        self
    }

    pub fn metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Attach the original bytes and their fingerprint.
    ///
    /// This is requirement (a) expressed in the standard's own vocabulary:
    /// `raw_data` carries the original text, `raw_data_hash` proves it was not
    /// altered, and `raw_data_size` records the true length even when the text
    /// itself is held back for size reasons.
    pub fn raw(mut self, raw: &[u8], hash: Fingerprint) -> Self {
        self.doc.insert(
            "raw_data".to_string(),
            Value::String(String::from_utf8_lossy(raw).into_owned()),
        );
        self.doc
            .insert("raw_data_size".to_string(), json!(raw.len()));
        if let Ok(v) = serde_json::to_value(hash) {
            self.doc.insert("raw_data_hash".to_string(), v);
        }
        self
    }

    /// Record the raw fingerprint and size without inlining the payload.
    ///
    /// Used when the vault holds the bytes and duplicating them into every
    /// event would double storage for no forensic gain — the locator plus the
    /// hash is still enough to retrieve and verify the original.
    pub fn raw_reference(mut self, len: usize, hash: Fingerprint) -> Self {
        self.doc.insert("raw_data_size".to_string(), json!(len));
        if let Ok(v) = serde_json::to_value(hash) {
            self.doc.insert("raw_data_hash".to_string(), v);
        }
        self
    }

    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.doc
            .insert("message".to_string(), Value::String(msg.into()));
        self
    }

    /// Set an arbitrary attribute by dotted path.
    pub fn set(mut self, path: &str, value: Value) -> Result<Self> {
        let mut ev = OcsfEvent {
            doc: std::mem::take(&mut self.doc),
        };
        ev.set_path(path, value)?;
        self.doc = ev.doc;
        Ok(self)
    }

    pub fn build(self) -> Result<OcsfEvent> {
        let class_uid = self
            .class_uid
            .ok_or(EventError::MissingRequired("class_uid"))?;
        let activity_id = self
            .activity_id
            .ok_or(EventError::MissingRequired("activity_id"))?;
        let time = self.time.ok_or(EventError::MissingRequired("time"))?;
        let severity_id = self
            .severity_id
            .ok_or(EventError::MissingRequired("severity_id"))?;
        let metadata = self
            .metadata
            .ok_or(EventError::MissingRequired("metadata"))?;

        let mut doc = self.doc;
        doc.insert("class_uid".to_string(), json!(class_uid));
        doc.insert("category_uid".to_string(), json!(category_of(class_uid)));
        doc.insert("activity_id".to_string(), json!(activity_id));
        doc.insert(
            "type_uid".to_string(),
            json!(type_uid(class_uid, activity_id)),
        );
        doc.insert("time".to_string(), json!(time));
        doc.insert("severity_id".to_string(), json!(severity_id));
        doc.insert(
            "metadata".to_string(),
            serde_json::to_value(metadata).expect("Metadata serializes infallibly"),
        );

        Ok(OcsfEvent { doc })
    }
}

/// `type_uid = class_uid * 100 + activity_id`, per the OCSF specification.
pub fn type_uid(class_uid: i64, activity_id: i64) -> i64 {
    class_uid * 100 + activity_id
}

/// `category_uid` is the leading digit(s) of `class_uid`.
pub fn category_of(class_uid: i64) -> i64 {
    class_uid / 1000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Product;

    fn meta() -> Metadata {
        Metadata::new(SCHEMA_VERSION, Product::new("Fortinet", "FortiGate"))
    }

    fn base() -> EventBuilder {
        EventBuilder::new()
            .class(4001)
            .activity(6)
            .time(1_756_636_800_000_000_000)
            .severity(Severity::Informational)
            .metadata(meta())
    }

    #[test]
    fn derives_type_uid_and_category_uid() {
        let ev = base().build().unwrap();
        // Network Activity (4001), activity Traffic (6) -> 400106.
        assert_eq!(ev.type_uid(), Some(400106));
        assert_eq!(ev.as_map()["category_uid"], json!(4));
        assert_eq!(ev.class_uid(), Some(4001));
    }

    #[test]
    fn every_required_attribute_is_enforced() {
        assert!(matches!(
            EventBuilder::new()
                .activity(6)
                .time(1)
                .severity_id(1)
                .metadata(meta())
                .build(),
            Err(EventError::MissingRequired("class_uid"))
        ));
        assert!(matches!(
            EventBuilder::new()
                .class(4001)
                .time(1)
                .severity_id(1)
                .metadata(meta())
                .build(),
            Err(EventError::MissingRequired("activity_id"))
        ));
        assert!(matches!(
            EventBuilder::new()
                .class(4001)
                .activity(6)
                .severity_id(1)
                .metadata(meta())
                .build(),
            Err(EventError::MissingRequired("time"))
        ));
        assert!(matches!(
            EventBuilder::new()
                .class(4001)
                .activity(6)
                .time(1)
                .metadata(meta())
                .build(),
            Err(EventError::MissingRequired("severity_id"))
        ));
        assert!(matches!(
            EventBuilder::new()
                .class(4001)
                .activity(6)
                .time(1)
                .severity_id(1)
                .build(),
            Err(EventError::MissingRequired("metadata"))
        ));
    }

    #[test]
    fn dotted_paths_create_nested_objects() {
        let mut ev = base().build().unwrap();
        ev.set_path("src_endpoint.ip", json!("10.2.4.7")).unwrap();
        ev.set_path("src_endpoint.port", json!(44321)).unwrap();
        ev.set_path("connection_info.direction_id", json!(2))
            .unwrap();

        assert_eq!(ev.get_path("src_endpoint.ip").unwrap(), &json!("10.2.4.7"));
        assert_eq!(ev.get_path("src_endpoint.port").unwrap(), &json!(44321));
        // Both writes must land in the *same* object, not clobber each other.
        assert_eq!(ev.as_map()["src_endpoint"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn deep_paths_work() {
        let mut ev = base().build().unwrap();
        ev.set_path("a.b.c.d", json!(1)).unwrap();
        assert_eq!(ev.get_path("a.b.c.d").unwrap(), &json!(1));
    }

    #[test]
    fn path_collision_is_reported_not_swallowed() {
        let mut ev = base().build().unwrap();
        ev.set_path("src_endpoint", json!("10.2.4.7")).unwrap();
        // src_endpoint is now a string; making it a parent must fail loudly.
        let err = ev
            .set_path("src_endpoint.ip", json!("1.1.1.1"))
            .unwrap_err();
        match err {
            EventError::PathConflict { segment, found, .. } => {
                assert_eq!(segment, "src_endpoint");
                assert_eq!(found, "string");
            }
            other => panic!("expected PathConflict, got {other:?}"),
        }
    }

    #[test]
    fn missing_path_reads_as_none() {
        let ev = base().build().unwrap();
        assert!(ev.get_path("src_endpoint.ip").is_none());
        assert!(ev.get_path("nope").is_none());
        assert!(ev.get_path("metadata.product.vendor_name").is_some());
    }

    #[test]
    fn raw_data_carries_original_bytes_and_size() {
        let raw = b"date=2026-08-31 devname=FGT-01 action=accept";
        let fp = Fingerprint::over_raw(crate::types::HashAlgorithm::Sha256, raw);
        let ev = base().raw(raw, fp).build().unwrap();

        assert_eq!(ev.as_map()["raw_data"], json!(String::from_utf8_lossy(raw)));
        assert_eq!(ev.as_map()["raw_data_size"], json!(raw.len()));
        assert!(ev.as_map()["raw_data_hash"]["value"].is_string());
        // Flat serialization: the original was hashed as opaque bytes.
        assert_eq!(ev.as_map()["raw_data_hash"]["serialization_id"], json!(1));
    }

    #[test]
    fn unmapped_fields_are_kept_not_dropped() {
        let mut ev = base().build().unwrap();
        ev.set_unmapped("fortigate_policyid", json!("42"));
        ev.set_unmapped("fortigate_vd", json!("root"));
        assert_eq!(ev.as_map()["unmapped"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn observables_accumulate() {
        use crate::types::ObservableType;
        let mut ev = base().build().unwrap();
        ev.push_observable(Observable::new(
            "src_endpoint.ip",
            ObservableType::IpAddress,
            "10.2.4.7",
        ));
        ev.push_observable(Observable::new(
            "dst_endpoint.ip",
            ObservableType::IpAddress,
            "8.8.8.8",
        ));
        let obs = ev.as_map()["observables"].as_array().unwrap();
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0]["type_id"], json!(2));
    }

    #[test]
    fn canonical_bytes_are_stable_across_rebuilds() {
        let a = base().build().unwrap().canonical_bytes().unwrap();
        let b = base().build().unwrap().canonical_bytes().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn type_uid_arithmetic() {
        assert_eq!(type_uid(4001, 6), 400106);
        assert_eq!(type_uid(1001, 1), 100101);
        assert_eq!(category_of(4001), 4);
        assert_eq!(category_of(1001), 1);
    }
}
