//! The flat field map produced by a decoder chain.
//!
//! Values borrow from the source buffer wherever a decoder can hand back a
//! substring unchanged, which covers the common perimeter-device cases
//! (key=value bodies, syslog headers, CSV columns). A decoder that must
//! transform a value — unescaping a quoted JSON string, decoding an entity
//! reference — produces an owned value instead. Both live in the same
//! [`Value`] via [`Cow`], so callers never care which happened.
//!
//! Nested structures are flattened with dotted keys (`a.b.0.c`) rather than
//! modelled recursively. Field maps are an intermediate form on the way to
//! OCSF, and every mapping expression addresses a leaf, so a tree here would
//! be built only to be walked flat again.

use std::borrow::Cow;

use crate::error::{Error, Result};

/// A single extracted value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    Str(Cow<'a, str>),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

impl<'a> Value<'a> {
    /// Borrow a value from the source buffer. No allocation.
    pub fn borrowed(s: &'a str) -> Self {
        Value::Str(Cow::Borrowed(s))
    }

    /// Take ownership of a transformed value.
    pub fn owned(s: impl Into<String>) -> Self {
        Value::Str(Cow::Owned(s.into()))
    }

    /// Name of the variant, for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Str(_) => "string",
            Value::Int(_) => "integer",
            Value::Float(_) => "float",
            Value::Bool(_) => "boolean",
            Value::Null => "null",
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_ref()),
            _ => None,
        }
    }

    /// Interpret the value as an integer, parsing a string if necessary.
    ///
    /// Device logs are overwhelmingly untyped text, so a numeric field arrives
    /// as `Str("443")` far more often than as `Int(443)`. Coercing here keeps
    /// that detail out of every mapping rule.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Float(f) if f.fract() == 0.0 => Some(*f as i64),
            Value::Str(s) => s.trim().parse().ok(),
            Value::Bool(b) => Some(*b as i64),
            Value::Null => None,
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            Value::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    /// Interpret the value as a boolean.
    ///
    /// Accepts the spellings that actually appear in device logs, not just
    /// Rust's `true`/`false`.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            Value::Int(i) => Some(*i != 0),
            Value::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "yes" | "y" | "1" | "on" | "enable" | "enabled" => Some(true),
                "false" | "no" | "n" | "0" | "off" | "disable" | "disabled" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    /// Whether this value carries no information and should not be mapped.
    ///
    /// Perimeter devices pad absent fields rather than omitting them: FortiGate
    /// writes `srcip=N/A`, Cisco writes `-`. Mapping those through as literal
    /// strings would put junk in typed OCSF fields, so they are treated as
    /// absent at the point of extraction.
    pub fn is_empty_marker(&self) -> bool {
        match self {
            Value::Null => true,
            Value::Str(s) => {
                let t = s.trim();
                t.is_empty()
                    || t == "-"
                    || t.eq_ignore_ascii_case("n/a")
                    || t.eq_ignore_ascii_case("null")
                    || t.eq_ignore_ascii_case("none")
                    || t.eq_ignore_ascii_case("unknown")
            }
            _ => false,
        }
    }

    /// Detach from the source buffer, so the value can outlive it.
    pub fn into_owned(self) -> Value<'static> {
        match self {
            Value::Str(s) => Value::Str(Cow::Owned(s.into_owned())),
            Value::Int(i) => Value::Int(i),
            Value::Float(f) => Value::Float(f),
            Value::Bool(b) => Value::Bool(b),
            Value::Null => Value::Null,
        }
    }
}

impl<'a> From<&'a str> for Value<'a> {
    fn from(s: &'a str) -> Self {
        Value::borrowed(s)
    }
}

impl From<i64> for Value<'_> {
    fn from(i: i64) -> Self {
        Value::Int(i)
    }
}

impl From<bool> for Value<'_> {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

/// An insertion-ordered map of extracted fields.
///
/// Backed by a `Vec` with linear lookup rather than a hash map. Device events
/// carry tens of fields, not thousands, and at that size a contiguous scan
/// beats hashing on both time and allocation count. Insertion order is kept
/// because it mirrors the order fields appeared in the original line, which
/// makes diffing a field map against its source line straightforward when
/// debugging a pack.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FieldMap<'a> {
    entries: Vec<(Cow<'a, str>, Value<'a>)>,
}

impl<'a> FieldMap<'a> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn with_capacity(n: usize) -> Self {
        Self {
            entries: Vec::with_capacity(n),
        }
    }

    /// Insert a field, replacing any existing value for the same key.
    pub fn insert(&mut self, key: impl Into<Cow<'a, str>>, value: Value<'a>) {
        let key = key.into();
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => self.entries.push((key, value)),
        }
    }

    /// Insert without checking for an existing key.
    ///
    /// Decoders that generate keys structurally — CSV columns, positional
    /// syslog fields — already know the keys are distinct, and skipping the
    /// scan makes extraction linear rather than quadratic in field count.
    pub fn push_unchecked(&mut self, key: impl Into<Cow<'a, str>>, value: Value<'a>) {
        self.entries.push((key.into(), value));
    }

    pub fn get(&self, key: &str) -> Option<&Value<'a>> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Look up a field, treating empty markers as absent.
    pub fn get_present(&self, key: &str) -> Option<&Value<'a>> {
        self.get(key).filter(|v| !v.is_empty_marker())
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key)?.as_str()
    }

    /// Look up a field that must be present.
    pub fn require(&self, key: &str) -> Result<&Value<'a>> {
        self.get_present(key)
            .ok_or_else(|| Error::MissingField(key.to_string()))
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value<'a>)> {
        self.entries.iter().map(|(k, v)| (k.as_ref(), v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_ref())
    }

    /// Merge another map into this one. Existing keys are kept.
    ///
    /// Decoder chains run outermost-first — a syslog envelope decoder, then a
    /// key-value body decoder — and the envelope's `host` should not be
    /// overwritten by a body field of the same name.
    pub fn merge_keeping_existing(&mut self, other: FieldMap<'a>) {
        for (k, v) in other.entries {
            if !self.contains(k.as_ref()) {
                self.entries.push((k, v));
            }
        }
    }

    /// Prefix every key, for namespacing one decoder's output within a chain.
    pub fn prefixed(self, prefix: &str) -> FieldMap<'static> {
        FieldMap {
            entries: self
                .entries
                .into_iter()
                .map(|(k, v)| (Cow::Owned(format!("{prefix}{k}")), v.into_owned()))
                .collect(),
        }
    }

    /// Detach every entry from the source buffer.
    pub fn into_owned(self) -> FieldMap<'static> {
        FieldMap {
            entries: self
                .entries
                .into_iter()
                .map(|(k, v)| (Cow::Owned(k.into_owned()), v.into_owned()))
                .collect(),
        }
    }
}

impl<'a> FromIterator<(Cow<'a, str>, Value<'a>)> for FieldMap<'a> {
    fn from_iter<T: IntoIterator<Item = (Cow<'a, str>, Value<'a>)>>(iter: T) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_values_do_not_allocate() {
        let line = String::from("srcip=10.0.0.1");
        let v = Value::borrowed(&line[6..]);
        match v {
            Value::Str(Cow::Borrowed(s)) => assert_eq!(s, "10.0.0.1"),
            other => panic!("expected borrowed, got {other:?}"),
        }
    }

    #[test]
    fn insert_replaces_and_keeps_position() {
        let mut m = FieldMap::new();
        m.insert("a", Value::Int(1));
        m.insert("b", Value::Int(2));
        m.insert("a", Value::Int(3));
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("a").unwrap().as_int(), Some(3));
        assert_eq!(m.keys().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn numeric_strings_coerce() {
        assert_eq!(Value::borrowed("443").as_int(), Some(443));
        assert_eq!(Value::borrowed(" 443 ").as_int(), Some(443));
        assert_eq!(Value::borrowed("nope").as_int(), None);
        assert_eq!(Value::Float(7.0).as_int(), Some(7));
        // A fractional float is not silently truncated into an integer field.
        assert_eq!(Value::Float(7.5).as_int(), None);
    }

    #[test]
    fn device_boolean_spellings_parse() {
        for t in ["true", "YES", "y", "1", "on", "enabled"] {
            assert_eq!(Value::borrowed(t).as_bool(), Some(true), "{t}");
        }
        for f in ["false", "NO", "n", "0", "off", "disabled"] {
            assert_eq!(Value::borrowed(f).as_bool(), Some(false), "{f}");
        }
        assert_eq!(Value::borrowed("maybe").as_bool(), None);
    }

    #[test]
    fn device_absence_markers_are_treated_as_absent() {
        for marker in ["-", "N/A", "n/a", "NULL", "none", "", "  ", "unknown"] {
            assert!(Value::borrowed(marker).is_empty_marker(), "{marker:?}");
        }
        assert!(!Value::borrowed("10.0.0.1").is_empty_marker());
        assert!(!Value::Int(0).is_empty_marker());
    }

    #[test]
    fn get_present_filters_markers() {
        let mut m = FieldMap::new();
        m.insert("srcip", Value::borrowed("N/A"));
        m.insert("dstip", Value::borrowed("10.0.0.2"));
        assert!(m.get("srcip").is_some());
        assert!(m.get_present("srcip").is_none());
        assert!(m.get_present("dstip").is_some());
        assert!(m.require("srcip").is_err());
    }

    #[test]
    fn merge_does_not_clobber_envelope_fields() {
        let mut envelope = FieldMap::new();
        envelope.insert("host", Value::borrowed("fw-01"));
        let mut body = FieldMap::new();
        body.insert("host", Value::borrowed("bogus"));
        body.insert("action", Value::borrowed("accept"));
        envelope.merge_keeping_existing(body);
        assert_eq!(envelope.get_str("host"), Some("fw-01"));
        assert_eq!(envelope.get_str("action"), Some("accept"));
    }
}
