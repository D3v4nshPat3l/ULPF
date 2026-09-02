//! ArcSight Common Event Format.
//!
//! `CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension`
//!
//! Two escaping rules make CEF harder than it looks, and they are *different*
//! in the header and the extension. In the header, `\|` is a literal pipe. In
//! the extension, `\=` is a literal equals and pipes are ordinary characters.
//! A decoder that applies one rule everywhere silently mangles any event whose
//! message contains a pipe — which, for firewall rule names, is common.

use std::borrow::Cow;

use ulpf_core::{FieldMap, Value};

use crate::{DecodeError, Decoded, Decoder, Result};

const HEADER_FIELDS: [&str; 6] = [
    "cef.device_vendor",
    "cef.device_product",
    "cef.device_version",
    "cef.signature_id",
    "cef.name",
    "cef.severity",
];

/// Decodes a CEF record into header and extension fields.
#[derive(Debug, Clone, Copy)]
pub struct CefDecoder;

impl Decoder for CefDecoder {
    fn name(&self) -> &'static str {
        "cef"
    }

    fn decode<'a>(&self, input: &'a str) -> Result<Decoded<'a>> {
        let input = input.trim_end_matches(['\r', '\n']);
        // Some senders prefix a syslog header even when a pack routed straight
        // here, so find the marker rather than demanding it at position zero.
        let start = input.find("CEF:").ok_or(DecodeError::NotThisFormat {
            format: "cef",
            detail: "no `CEF:` marker".to_string(),
        })?;
        let rest = &input[start + 4..];

        let mut fields = FieldMap::with_capacity(24);

        // Version, then the six header fields, all pipe-delimited.
        let (version, mut rest) = take_header_field(rest).ok_or(DecodeError::Malformed {
            format: "cef",
            offset: start,
            detail: "truncated before version".to_string(),
        })?;
        fields.push_unchecked("cef.version", to_value(version));

        for name in HEADER_FIELDS {
            let (value, r) = take_header_field(rest).ok_or(DecodeError::Malformed {
                format: "cef",
                offset: start,
                detail: format!("truncated before `{name}`"),
            })?;
            fields.push_unchecked(name, to_value(value));
            rest = r;
        }

        parse_extension(rest, &mut fields);
        Ok(Decoded::terminal(fields))
    }
}

fn to_value(v: Cow<'_, str>) -> Value<'_> {
    match v {
        Cow::Borrowed(s) => Value::borrowed(s),
        Cow::Owned(s) => Value::owned(s),
    }
}

/// Take one `|`-delimited header field, honouring `\|` and `\\`.
fn take_header_field(input: &str) -> Option<(Cow<'_, str>, &str)> {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut escaped = false;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                escaped = true;
                i += 2;
                continue;
            }
            b'|' => {
                let raw = &input[..i];
                let value = if escaped {
                    Cow::Owned(unescape_header(raw))
                } else {
                    Cow::Borrowed(raw)
                };
                return Some((value, &input[i + 1..]));
            }
            _ => i += 1,
        }
    }
    None
}

fn unescape_header(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next) => out.push(next),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse the `key=value key2=value2` extension.
///
/// Values run to the next unescaped ` key=`, because a value may legally
/// contain spaces. Scanning for the *next key* rather than the next space is
/// the only way to get `msg=connection denied by policy src=10.0.0.1` right.
fn parse_extension<'a>(input: &'a str, fields: &mut FieldMap<'a>) {
    let mut rest = input.trim_start();

    while let Some(eq) = find_unescaped(rest, b'=') {
        let key = rest[..eq].trim();
        let after = &rest[eq + 1..];

        let end = next_key_start(after).unwrap_or(after.len());
        let raw = after[..end].trim_end();

        if !key.is_empty() && !key.contains(' ') {
            let value = if raw.contains('\\') {
                Value::owned(unescape_extension(raw))
            } else {
                Value::borrowed(raw)
            };
            fields.insert(Cow::Borrowed(key), value);
        }

        if end >= after.len() {
            break;
        }
        rest = after[end..].trim_start();
    }
}

/// Find where the next `key=` begins, i.e. the space before a token that
/// contains an unescaped `=`.
fn next_key_start(input: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b' ' {
            // Look ahead: is the following token a key?
            let mut j = i + 1;
            let mut saw_char = false;
            while j < bytes.len() {
                match bytes[j] {
                    b'\\' => {
                        j += 2;
                        saw_char = true;
                        continue;
                    }
                    b'=' if saw_char => return Some(i),
                    b' ' => break,
                    _ => {
                        saw_char = true;
                        j += 1;
                    }
                }
            }
        }
        i += 1;
    }
    None
}

fn find_unescaped(input: &str, needle: u8) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b if b == needle => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn unescape_extension(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(input: &str) -> FieldMap<'_> {
        CefDecoder.decode(input).unwrap().fields
    }

    #[test]
    fn parses_the_arcsight_reference_example() {
        let line = "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|\
                    src=10.0.0.1 dst=2.1.2.2 spt=1232";
        let f = decode(line);
        assert_eq!(f.get_str("cef.version"), Some("0"));
        assert_eq!(f.get_str("cef.device_vendor"), Some("Security"));
        assert_eq!(f.get_str("cef.device_product"), Some("threatmanager"));
        assert_eq!(f.get_str("cef.device_version"), Some("1.0"));
        assert_eq!(f.get_str("cef.signature_id"), Some("100"));
        assert_eq!(f.get_str("cef.name"), Some("worm successfully stopped"));
        assert_eq!(f.get_str("cef.severity"), Some("10"));
        assert_eq!(f.get_str("src"), Some("10.0.0.1"));
        assert_eq!(f.get_str("dst"), Some("2.1.2.2"));
        assert_eq!(f.get("spt").unwrap().as_int(), Some(1232));
    }

    #[test]
    fn extension_values_may_contain_spaces() {
        // The classic CEF trap: `msg` runs until the next real key.
        let line = "CEF:0|V|P|1.0|1|Name|5|msg=connection denied by policy src=10.0.0.1 spt=443";
        let f = decode(line);
        assert_eq!(f.get_str("msg"), Some("connection denied by policy"));
        assert_eq!(f.get_str("src"), Some("10.0.0.1"));
        assert_eq!(f.get_str("spt"), Some("443"));
    }

    #[test]
    fn escaped_pipe_in_header_is_literal() {
        let line = r"CEF:0|Vendor|Prod\|uct|1.0|100|Name|5|src=10.0.0.1";
        let f = decode(line);
        assert_eq!(f.get_str("cef.device_product"), Some("Prod|uct"));
        assert_eq!(f.get_str("cef.device_version"), Some("1.0"));
    }

    #[test]
    fn escaped_equals_in_extension_is_literal() {
        let line = r"CEF:0|V|P|1.0|1|Name|5|query=a\=b src=10.0.0.1";
        let f = decode(line);
        assert_eq!(f.get_str("query"), Some("a=b"));
        assert_eq!(f.get_str("src"), Some("10.0.0.1"));
    }

    #[test]
    fn pipe_inside_extension_is_ordinary_text() {
        // Header escaping rules must not leak into the extension.
        let line = "CEF:0|V|P|1.0|1|Name|5|rule=allow|dns src=10.0.0.1";
        let f = decode(line);
        assert_eq!(f.get_str("rule"), Some("allow|dns"));
        assert_eq!(f.get_str("src"), Some("10.0.0.1"));
    }

    #[test]
    fn syslog_prefixed_cef_is_found() {
        let line = "<134>Aug 31 10:23:45 fw CEF:0|V|P|1.0|1|Name|5|src=10.0.0.1";
        let f = decode(line);
        assert_eq!(f.get_str("cef.device_vendor"), Some("V"));
        assert_eq!(f.get_str("src"), Some("10.0.0.1"));
    }

    #[test]
    fn empty_extension_is_valid() {
        let f = decode("CEF:0|V|P|1.0|1|Name|5|");
        assert_eq!(f.get_str("cef.name"), Some("Name"));
        assert_eq!(f.get_str("cef.severity"), Some("5"));
    }

    #[test]
    fn truncated_header_is_reported() {
        let err = CefDecoder.decode("CEF:0|Vendor|Product").unwrap_err();
        assert!(matches!(err, DecodeError::Malformed { .. }));
    }

    #[test]
    fn a_non_cef_line_is_rejected_so_the_chain_can_continue() {
        let err = CefDecoder
            .decode("date=2026-08-31 srcip=10.0.0.1")
            .unwrap_err();
        assert!(matches!(err, DecodeError::NotThisFormat { .. }));
    }

    #[test]
    fn last_extension_value_is_trimmed() {
        let f = decode("CEF:0|V|P|1.0|1|Name|5|src=10.0.0.1   ");
        assert_eq!(f.get_str("src"), Some("10.0.0.1"));
    }
}
