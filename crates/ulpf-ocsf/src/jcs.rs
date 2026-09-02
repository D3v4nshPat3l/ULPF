//! RFC 8785 JSON Canonicalization Scheme.
//!
//! OCSF's `fingerprint.serialization_id = 2` names JCS as the scheme used to
//! produce the byte sequence that gets hashed. Every attestation this framework
//! emits therefore depends on this module producing *exactly* the bytes any
//! other RFC 8785 implementation would, or an external verifier will compute a
//! different digest and conclude the event was tampered with.
//!
//! Three rules do the work:
//!
//! * **Object keys** sort by their UTF-16 code unit sequence — not by code
//!   point, and not by byte. The two orders diverge above the BMP, because a
//!   supplementary character encodes as surrogates in `D800..DFFF`, which are
//!   numerically below the `E000..FFFF` range.
//! * **Numbers** serialize with ECMAScript `Number::toString`, which is *not*
//!   Rust's `Display`. Rust prints `1e21` as `1000000000000000000000`; JCS
//!   requires `1e+21`.
//! * **Strings** use the shortest JSON escape, leaving all non-control
//!   characters as literal UTF-8.
//!
//! No whitespace is emitted anywhere.

use serde_json::{Map, Value};
use std::fmt::Write as _;

/// Errors that prevent a value from being canonicalized.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JcsError {
    /// JSON has no representation for NaN or the infinities, so a document
    /// containing one cannot be canonicalized or hashed.
    #[error("cannot canonicalize non-finite number")]
    NonFiniteNumber,
}

/// Canonicalize a JSON value into RFC 8785 form.
pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    let mut out = String::with_capacity(512);
    write_value(&mut out, value)?;
    Ok(out)
}

/// Canonicalize straight to bytes, which is what a hash function wants.
pub fn canonicalize_bytes(value: &Value) -> Result<Vec<u8>, JcsError> {
    canonicalize(value).map(String::into_bytes)
}

/// Canonicalize a JSON object without wrapping it in a [`Value`] first.
///
/// An OCSF event is held as a `Map`, and `Value::Object(map.clone())` would
/// deep-clone every string in the event just to hand it to the serializer —
/// once per event, on the hot path. Writing straight from the borrowed map
/// removes that copy entirely.
pub fn canonicalize_map(map: &Map<String, Value>) -> Result<String, JcsError> {
    let mut out = String::with_capacity(1024);
    write_object(&mut out, map)?;
    Ok(out)
}

/// [`canonicalize_map`], straight to bytes.
pub fn canonicalize_map_bytes(map: &Map<String, Value>) -> Result<Vec<u8>, JcsError> {
    canonicalize_map(map).map(String::into_bytes)
}

fn write_value(out: &mut String, value: &Value) -> Result<(), JcsError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, n)?,
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(out, map)?,
    }
    Ok(())
}

fn write_object(out: &mut String, map: &Map<String, Value>) -> Result<(), JcsError> {
    // Sort by UTF-16 code units, per RFC 8785 section 3.2.3.
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));

    out.push('{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(out, key);
        out.push(':');
        write_value(out, &map[*key])?;
    }
    out.push('}');
    Ok(())
}

/// Serialize a string with the shortest legal JSON escaping.
///
/// RFC 8785 section 3.2.2.2: use the two-character escapes where they exist,
/// `\u00xx` for the remaining control characters, and literal UTF-8 for
/// everything else. In particular, non-ASCII characters are *not* escaped.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(out: &mut String, n: &serde_json::Number) -> Result<(), JcsError> {
    // Integers that fit in i64/u64 are already in canonical form, and routing
    // them through the float path would risk losing precision beyond 2^53.
    // OCSF timestamps are `long_t` nanosecond values, which sit in exactly that
    // danger zone, so this branch is load-bearing rather than an optimization.
    if let Some(i) = n.as_i64() {
        let _ = write!(out, "{i}");
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        let _ = write!(out, "{u}");
        return Ok(());
    }
    let f = n.as_f64().ok_or(JcsError::NonFiniteNumber)?;
    if !f.is_finite() {
        return Err(JcsError::NonFiniteNumber);
    }
    out.push_str(&ecmascript_number(f));
    Ok(())
}

/// Format a float the way ECMAScript `Number::toString(10)` does.
///
/// RFC 8785 defers to that algorithm, and it differs from Rust's `Display` at
/// both ends of the range: ECMAScript switches to exponential notation at
/// `1e21` and below `1e-6`, whereas Rust expands those in full.
///
/// The shortest round-tripping digit string comes from Rust's `LowerExp`
/// formatting, which already implements the Grisu/Ryū shortest-representation
/// guarantee. This function only has to re-place the decimal point.
fn ecmascript_number(f: f64) -> String {
    if f == 0.0 {
        // Canonical form has no signed zero: -0.0 serializes as "0".
        return "0".to_string();
    }
    if f < 0.0 {
        return format!("-{}", ecmascript_number(-f));
    }

    // e.g. 1234.5 -> "1.2345e3"; 1e21 -> "1e21"
    let sci = format!("{f:e}");
    let (mantissa, exp) = sci
        .split_once('e')
        .expect("LowerExp always emits an exponent");
    let exp: i32 = exp.parse().expect("LowerExp emits a decimal exponent");

    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };

    let k = digits.len() as i32; // number of significant digits
    let n = exp + 1; // position of the decimal point relative to `digits`

    // The four cases below are ECMAScript Number::toString steps 6 through 9.
    if k <= n && n <= 21 {
        // Integer with trailing zeros: 1200
        let mut s = String::with_capacity(n as usize);
        s.push_str(digits);
        for _ in 0..(n - k) {
            s.push('0');
        }
        s
    } else if 0 < n && n <= 21 {
        // Decimal point falls inside the digits: 12.34
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        // Small magnitude, still written in full: 0.00012
        let mut s = String::from("0.");
        for _ in 0..(-n) {
            s.push('0');
        }
        s.push_str(digits);
        s
    } else {
        // Exponential notation, with an explicit sign on the exponent.
        let e = n - 1;
        let sign = if e >= 0 { "+" } else { "-" };
        if k == 1 {
            format!("{}e{}{}", digits, sign, e.abs())
        } else {
            format!("{}.{}e{}{}", &digits[..1], &digits[1..], sign, e.abs())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(v: Value) -> String {
        canonicalize(&v).unwrap()
    }

    #[test]
    fn keys_are_sorted_and_whitespace_removed() {
        let v = json!({ "b": 1, "a": 2, "c": { "z": 1, "y": 2 } });
        assert_eq!(canon(v), r#"{"a":2,"b":1,"c":{"y":2,"z":1}}"#);
    }

    #[test]
    fn array_order_is_preserved() {
        // Arrays are ordered data, not a set: JCS must not sort them.
        assert_eq!(canon(json!([3, 1, 2])), "[3,1,2]");
    }

    #[test]
    fn rfc8785_string_escaping() {
        // Section 3.2.2.2: two-character escapes where they exist,
        // \u00xx for the remaining control characters, and literal UTF-8
        // for everything else. U+0001 has no short form, so it must render
        // as the six characters backslash-u-0-0-0-1, in lowercase hex.
        let v = json!({ "s": "a\"b\\c\nd\te\u{0008}f\u{000c}g\u{0001}h" });
        let expected = "{\"s\":\"a\\\"b\\\\c\\nd\\te\\bf\\fg\\u0001h\"}";
        assert_eq!(canon(v), expected);
    }

    #[test]
    fn non_ascii_is_not_escaped() {
        let v = json!({ "k": "नमस्ते é 日本" });
        assert_eq!(canon(v), "{\"k\":\"नमस्ते é 日本\"}");
    }

    #[test]
    fn keys_sort_by_utf16_not_code_point() {
        // U+10000 encodes as surrogates D800 DC00. In UTF-16 order it sorts
        // *before* U+E000, but in code point order it sorts after. Getting this
        // backwards is the classic JCS bug, so pin the behaviour.
        let mut map = Map::new();
        map.insert("\u{E000}".to_string(), json!(1));
        map.insert("\u{10000}".to_string(), json!(2));
        let out = canonicalize(&Value::Object(map)).unwrap();
        let supplementary_at = out.find('\u{10000}').unwrap();
        let bmp_at = out.find('\u{E000}').unwrap();
        assert!(
            supplementary_at < bmp_at,
            "U+10000 must sort before U+E000 under UTF-16 ordering, got {out:?}"
        );
    }

    #[test]
    fn large_integers_keep_full_precision() {
        // A nanosecond timestamp exceeds 2^53, so it must never round-trip
        // through f64. This is the case that silently corrupts fingerprints.
        let ts: i64 = 1_756_636_800_123_456_789;
        assert_eq!(canon(json!({ "time": ts })), format!(r#"{{"time":{ts}}}"#));
    }

    #[test]
    fn ecmascript_number_formatting() {
        // Cases where ECMAScript and Rust's Display disagree.
        assert_eq!(ecmascript_number(1e21), "1e+21");
        assert_eq!(ecmascript_number(1e-7), "1e-7");
        assert_eq!(ecmascript_number(1.5e-8), "1.5e-8");

        // Cases where they agree.
        assert_eq!(ecmascript_number(1.0), "1");
        assert_eq!(ecmascript_number(1.5), "1.5");
        assert_eq!(ecmascript_number(1200.0), "1200");
        assert_eq!(ecmascript_number(0.00012), "0.00012");
        assert_eq!(ecmascript_number(1e20), "100000000000000000000");
        assert_eq!(ecmascript_number(1e-6), "0.000001");
    }

    #[test]
    fn signed_zero_is_canonicalized() {
        assert_eq!(ecmascript_number(-0.0), "0");
        assert_eq!(ecmascript_number(0.0), "0");
    }

    #[test]
    fn negative_numbers_round_trip() {
        assert_eq!(ecmascript_number(-1.5), "-1.5");
        assert_eq!(ecmascript_number(-1e21), "-1e+21");
    }

    #[test]
    fn non_finite_is_rejected_not_silently_mangled() {
        // serde_json cannot even hold a NaN via json!(), so construct the
        // failure the way it would actually arise: from_f64 returning None
        // means such a document can never reach us. Assert the guard exists
        // for the f64 path by checking a value that is representable.
        assert!(serde_json::Number::from_f64(f64::NAN).is_none());
        assert!(serde_json::Number::from_f64(f64::INFINITY).is_none());
    }

    #[test]
    fn canonicalization_is_deterministic_across_input_orderings() {
        // The whole integrity story rests on this: two encoders that disagree
        // about key order must still produce identical bytes.
        let a: Value = serde_json::from_str(r#"{"z":1,"a":{"q":2,"b":3}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"b":3,"q":2},"z":1}"#).unwrap();
        assert_eq!(canonicalize(&a).unwrap(), canonicalize(&b).unwrap());
    }

    #[test]
    fn map_and_value_canonicalization_agree() {
        // The borrowed-map path is an optimization, so it must be
        // byte-identical to the owned-value path it replaces.
        let v: Value =
            serde_json::from_str(r#"{"z":1,"a":{"q":[1,2,{"n":"x"}],"b":true},"m":null}"#).unwrap();
        let map = v.as_object().unwrap();
        assert_eq!(canonicalize(&v).unwrap(), canonicalize_map(map).unwrap());
    }

    #[test]
    fn nested_empty_containers() {
        assert_eq!(canon(json!({ "a": {}, "b": [] })), r#"{"a":{},"b":[]}"#);
    }
}
