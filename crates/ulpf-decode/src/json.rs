//! JSON body decoding, flattened to dotted keys.
//!
//! Nested objects become `a.b.c` and arrays become `a.0`, matching the address
//! form a Source Pack mapping uses. Flattening rather than preserving the tree
//! keeps one mapping syntax across every decoder: a pack author writes
//! `srcip` for FortiGate and `network.src.ip` for a JSON source, and both are
//! just field names.

use ulpf_core::{FieldMap, Value};

use crate::{DecodeError, Decoded, Decoder, Result};

/// Decodes a JSON object into a flat field map.
#[derive(Debug, Clone, Copy)]
pub struct JsonDecoder;

impl Decoder for JsonDecoder {
    fn name(&self) -> &'static str {
        "json"
    }

    fn decode<'a>(&self, input: &'a str) -> Result<Decoded<'a>> {
        let input = input.trim();
        if input.is_empty() {
            return Err(DecodeError::Empty);
        }

        let parsed: serde_json::Value =
            serde_json::from_str(input).map_err(|e| DecodeError::NotThisFormat {
                format: "json",
                detail: e.to_string(),
            })?;

        // A bare scalar is valid JSON but is not an event, and accepting one
        // would let this decoder claim any line containing a number.
        if !parsed.is_object() && !parsed.is_array() {
            return Err(DecodeError::NotThisFormat {
                format: "json",
                detail: "top level is a scalar, not an object".to_string(),
            });
        }

        let mut fields = FieldMap::with_capacity(32);
        flatten("", &parsed, &mut fields);
        Ok(Decoded::terminal(fields))
    }
}

fn flatten(prefix: &str, value: &serde_json::Value, out: &mut FieldMap<'static>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&key, v, out);
            }
        }
        serde_json::Value::Array(items) => {
            // Record the length so a mapping can branch on "did this have any".
            out.insert(
                std::borrow::Cow::Owned(format!("{prefix}.len")),
                Value::Int(items.len() as i64),
            );
            for (i, v) in items.iter().enumerate() {
                flatten(&format!("{prefix}.{i}"), v, out);
            }
        }
        serde_json::Value::String(s) => {
            out.insert(
                std::borrow::Cow::Owned(prefix.to_string()),
                Value::owned(s.clone()),
            );
        }
        serde_json::Value::Number(n) => {
            let v = if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::owned(n.to_string())
            };
            out.insert(std::borrow::Cow::Owned(prefix.to_string()), v);
        }
        serde_json::Value::Bool(b) => {
            out.insert(std::borrow::Cow::Owned(prefix.to_string()), Value::Bool(*b));
        }
        serde_json::Value::Null => {
            out.insert(std::borrow::Cow::Owned(prefix.to_string()), Value::Null);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(input: &str) -> FieldMap<'static> {
        // The JSON decoder always owns its output, so the lifetime is 'static.
        let d = JsonDecoder.decode(input).unwrap();
        d.fields.into_owned()
    }

    #[test]
    fn flattens_nested_objects_to_dotted_keys() {
        let f = decode(r#"{"src":{"ip":"10.0.0.1","port":443},"action":"allow"}"#);
        assert_eq!(f.get_str("src.ip"), Some("10.0.0.1"));
        assert_eq!(f.get("src.port").unwrap().as_int(), Some(443));
        assert_eq!(f.get_str("action"), Some("allow"));
    }

    #[test]
    fn arrays_become_indexed_keys_with_a_length() {
        let f = decode(r#"{"tags":["a","b","c"]}"#);
        assert_eq!(f.get_str("tags.0"), Some("a"));
        assert_eq!(f.get_str("tags.2"), Some("c"));
        assert_eq!(f.get("tags.len").unwrap().as_int(), Some(3));
    }

    #[test]
    fn preserves_integer_precision_beyond_f64() {
        // Nanosecond timestamps exceed 2^53; a decoder that routes everything
        // through f64 corrupts them.
        let f = decode(r#"{"time":1756636800123456789}"#);
        assert_eq!(
            f.get("time").unwrap().as_int(),
            Some(1_756_636_800_123_456_789)
        );
    }

    #[test]
    fn booleans_and_nulls_are_typed() {
        let f = decode(r#"{"ok":true,"missing":null}"#);
        assert_eq!(f.get("ok").unwrap().as_bool(), Some(true));
        assert!(f.get("missing").unwrap().is_empty_marker());
    }

    #[test]
    fn deeply_nested_paths_flatten() {
        let f = decode(r#"{"a":{"b":{"c":{"d":"deep"}}}}"#);
        assert_eq!(f.get_str("a.b.c.d"), Some("deep"));
    }

    #[test]
    fn arrays_of_objects_flatten_positionally() {
        let f = decode(r#"{"rules":[{"id":1},{"id":2}]}"#);
        assert_eq!(f.get("rules.0.id").unwrap().as_int(), Some(1));
        assert_eq!(f.get("rules.1.id").unwrap().as_int(), Some(2));
    }

    #[test]
    fn a_bare_scalar_is_not_an_event() {
        // Otherwise this decoder would claim any line that parses as a number.
        assert!(JsonDecoder.decode("42").is_err());
        assert!(JsonDecoder.decode(r#""just a string""#).is_err());
    }

    #[test]
    fn malformed_json_is_rejected_for_the_chain_to_continue() {
        let err = JsonDecoder.decode(r#"{"a":"#).unwrap_err();
        assert!(matches!(err, DecodeError::NotThisFormat { .. }));
    }

    #[test]
    fn empty_input_errors() {
        assert_eq!(JsonDecoder.decode("  ").unwrap_err(), DecodeError::Empty);
    }
}
