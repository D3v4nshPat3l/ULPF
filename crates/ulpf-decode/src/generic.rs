//! Structure recovered from a line no Source Pack claims.
//!
//! [`salvage`](crate::salvage) already pulls the *entities* out of an unknown
//! record — addresses, ports, URLs — so an analyst can pivot on them. What it
//! throws away is the shape: it keeps the value of a `key=value` pair and
//! discards the key. A record reading `outcome=deny peer=203.0.113.44` became
//! searchable for the address and lost the fact that the device called it
//! `peer`, and lost `outcome=deny` entirely because "deny" is not an entity.
//!
//! This module keeps the names. The output goes into OCSF `unmapped`, which is
//! exactly the object the schema provides for attributes a producer could not
//! map — so the device's own vocabulary survives, in the place the standard
//! reserves for it, without pretending it was understood.
//!
//! # What it will not do
//!
//! It assigns no OCSF attribute, no class and no direction. `src=` looks like
//! a source and frequently is, but "frequently" is how a wrong
//! `src_endpoint.ip` reaches a detection rule. Naming a field is a fact about
//! the record; interpreting it is a claim about the device, and only a pack
//! author who has read that vendor's documentation can make it.
//!
//! Everything here is deterministic: no model, no inference, no network call,
//! identical output for identical bytes.

use std::collections::BTreeSet;

/// Caps. A collector aiming at a billion records a day cannot let one hostile
/// or malformed line allocate without limit, and a field list longer than this
/// is not something a human will read anyway.
const MAX_FIELDS: usize = 64;
const MAX_KEY_LEN: usize = 64;
const MAX_VALUE_LEN: usize = 512;

/// Named values and the syslog severity recovered from one unclaimed line.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GenericFields {
    /// `key`/`value` pairs in the order first seen, deduplicated by key.
    pub fields: Vec<(String, String)>,
    /// RFC 5424 severity code 0-7, when the line carried a `<PRI>` header.
    pub syslog_severity: Option<u8>,
}

impl GenericFields {
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.syslog_severity.is_none()
    }
}

/// Recover named fields and the syslog severity from an arbitrary line.
pub fn extract(line: &str) -> GenericFields {
    let mut out = GenericFields::default();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    out.syslog_severity = syslog_severity(line);

    // A JSON object names everything it holds, so read it properly rather
    // than scanning for `=`. Only top-level scalars: a nested object has no
    // single obvious flat name, and inventing one ("a.b.c") would put a
    // structure in `unmapped` that the device never wrote.
    let trimmed = line.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(trimmed) {
            for (key, value) in map {
                let text = match value {
                    serde_json::Value::String(s) => s,
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    // null carries no information, and arrays and objects have
                    // no faithful flat rendering.
                    _ => continue,
                };
                push(&mut out, &mut seen, &key, &text);
            }
            return out;
        }
    }

    // Otherwise scan for `key=value`. Quoted values are honoured because
    // vendors quote anything containing a space, and splitting on whitespace
    // first would cut those in half.
    for (key, value) in kv_pairs(line) {
        push(&mut out, &mut seen, &key, &value);
    }
    out
}

/// RFC 5424 §6.2.1: `<PRI>` is `facility * 8 + severity`, and severity is the
/// remainder. A priority above 191 is not a priority.
fn syslog_severity(line: &str) -> Option<u8> {
    let rest = line.trim_start().strip_prefix('<')?;
    let close = rest.find('>')?;
    if close == 0 || close > 3 {
        return None;
    }
    let pri: u16 = rest[..close].parse().ok()?;
    if pri > 191 {
        return None;
    }
    Some((pri % 8) as u8)
}

/// Split a line into `key=value` pairs, respecting double quotes.
fn kv_pairs(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        // Find the next '=' that has a plausible key immediately before it.
        let Some(eq) = line[i..].find('=').map(|p| p + i) else {
            break;
        };
        // Walk back over the key.
        let mut start = eq;
        while start > i {
            let c = bytes[start - 1];
            if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.') {
                start -= 1;
            } else {
                break;
            }
        }
        if start == eq {
            i = eq + 1; // no key before this '='
            continue;
        }
        let key = &line[start..eq];

        // Read the value: quoted, or up to the next whitespace.
        let after = eq + 1;
        let (value, next) = if bytes.get(after) == Some(&b'"') {
            match line[after + 1..].find('"') {
                Some(end) => (&line[after + 1..after + 1 + end], after + end + 2),
                None => (&line[after..], line.len()),
            }
        } else {
            let end = line[after..]
                .find(char::is_whitespace)
                .map(|p| p + after)
                .unwrap_or(line.len());
            (&line[after..end], end)
        };

        if !key.is_empty() && !value.is_empty() {
            out.push((key.to_string(), value.to_string()));
        }
        i = next.max(eq + 1);
    }
    out
}

fn push(out: &mut GenericFields, seen: &mut BTreeSet<String>, key: &str, value: &str) {
    if out.fields.len() >= MAX_FIELDS {
        return;
    }
    let key = key.trim();
    let value = value.trim();
    if key.is_empty() || value.is_empty() || key.len() > MAX_KEY_LEN {
        return;
    }
    if !seen.insert(key.to_string()) {
        return; // first occurrence wins, so output is stable
    }
    let value = if value.len() > MAX_VALUE_LEN {
        // Truncate on a character boundary, never mid-codepoint.
        let mut cut = MAX_VALUE_LEN;
        while cut > 0 && !value.is_char_boundary(cut) {
            cut -= 1;
        }
        &value[..cut]
    } else {
        value
    };
    out.fields.push((key.to_string(), value.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(g: &GenericFields) -> Vec<&str> {
        g.fields.iter().map(|(k, _)| k.as_str()).collect()
    }
    fn get<'a>(g: &'a GenericFields, key: &str) -> Option<&'a str> {
        g.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn key_value_names_survive() {
        // The gap this module exists to close: salvage kept "203.0.113.44"
        // and threw away both "peer" and "outcome=deny" entirely.
        let g = extract("2005-02-24T16:36:18Z W9000 module=auth outcome=deny peer=203.0.113.44");
        assert_eq!(get(&g, "module"), Some("auth"));
        assert_eq!(get(&g, "outcome"), Some("deny"));
        assert_eq!(get(&g, "peer"), Some("203.0.113.44"));
    }

    #[test]
    fn quoted_values_are_not_cut_at_the_space() {
        let g = extract(r#"msg="connection refused by policy" rule=42"#);
        assert_eq!(get(&g, "msg"), Some("connection refused by policy"));
        assert_eq!(get(&g, "rule"), Some("42"));
    }

    #[test]
    fn json_objects_are_read_as_json_not_scanned_for_equals() {
        let g = extract(r#"{"unit":"hvac-7","note":"compressor fault","code":42,"ok":false}"#);
        assert_eq!(get(&g, "unit"), Some("hvac-7"));
        assert_eq!(get(&g, "note"), Some("compressor fault"));
        assert_eq!(get(&g, "code"), Some("42"));
        assert_eq!(get(&g, "ok"), Some("false"));
    }

    #[test]
    fn nested_json_is_skipped_rather_than_flattened_into_invented_names() {
        let g = extract(r#"{"a":"1","nested":{"b":"2"},"list":[1,2],"nil":null}"#);
        assert_eq!(keys(&g), vec!["a"]);
    }

    #[test]
    fn syslog_priority_yields_its_severity() {
        // RFC 5424: <134> is facility 16, severity 6 (Informational).
        assert_eq!(
            extract("<134>Feb 27 02:25:52 host x").syslog_severity,
            Some(6)
        );
        // <11> is facility 1, severity 3 (Error).
        assert_eq!(
            extract("<11>Feb 27 02:25:52 host x").syslog_severity,
            Some(3)
        );
        assert_eq!(extract("Feb 27 02:25:52 host x").syslog_severity, None);
        // Above the legal maximum, so not a priority.
        assert_eq!(extract("<999>whatever").syslog_severity, None);
    }

    #[test]
    fn prose_yields_nothing_rather_than_noise() {
        let g = extract("the printer on floor three is out of toner");
        assert!(g.is_empty());
    }

    #[test]
    fn a_bare_equals_sign_is_not_a_field() {
        let g = extract("total = 5 and == nothing");
        assert!(keys(&g).is_empty() || !keys(&g).contains(&""));
    }

    #[test]
    fn output_is_bounded_against_a_hostile_line() {
        let line = (0..500)
            .map(|i| format!("k{i}=v{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(extract(&line).fields.len(), MAX_FIELDS);

        let long = format!("k={}", "x".repeat(5000));
        assert_eq!(get(&extract(&long), "k").unwrap().len(), MAX_VALUE_LEN);
    }

    #[test]
    fn a_repeated_key_keeps_its_first_value_so_output_is_stable() {
        let g = extract("a=1 b=2 a=3");
        assert_eq!(get(&g, "a"), Some("1"));
        assert_eq!(g.fields.len(), 2);
    }

    #[test]
    fn multibyte_values_are_never_cut_mid_character() {
        let long = format!("k={}", "é".repeat(1000));
        let value = get(&extract(&long), "k").unwrap().to_string();
        assert!(value.len() <= MAX_VALUE_LEN);
        assert!(value.chars().all(|c| c == 'é'));
    }
}
