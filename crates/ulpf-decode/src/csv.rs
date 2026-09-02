//! Positional CSV body decoding, as emitted by Palo Alto PAN-OS.
//!
//! PAN-OS sends a comma-separated record whose meaning is entirely positional —
//! field 8 is the source address because it is field 8, and a schema change
//! between releases shifts everything after it. The decoder therefore emits
//! `col.N` for every column by index, and a Source Pack maps the positions it
//! cares about. Packs that supply a header list get named fields instead.
//!
//! Positional output has a useful property for requirement (e): a device whose
//! column layout is unknown still produces a complete, inspectable field map,
//! so an analyst can see the data before anyone writes a mapping for it.

use std::borrow::Cow;

use ulpf_core::{FieldMap, Value};

use crate::{DecodeError, Decoded, Decoder, Result};

/// Decodes a delimited record into positional or named columns.
#[derive(Debug, Clone)]
pub struct CsvDecoder {
    pub delimiter: char,
    /// Column names. When shorter than the record, the remaining columns fall
    /// back to `col.N`, so a new firmware version that appends fields degrades
    /// gracefully instead of failing.
    pub headers: Vec<String>,
    /// Also emit `col.N` when headers are present.
    pub keep_positional: bool,
}

impl Default for CsvDecoder {
    fn default() -> Self {
        Self {
            delimiter: ',',
            headers: Vec::new(),
            keep_positional: true,
        }
    }
}

impl CsvDecoder {
    pub fn with_headers(headers: Vec<String>) -> Self {
        Self {
            delimiter: ',',
            headers,
            keep_positional: true,
        }
    }
}

impl Decoder for CsvDecoder {
    fn name(&self) -> &'static str {
        "csv"
    }

    fn decode<'a>(&self, input: &'a str) -> Result<Decoded<'a>> {
        let input = input.trim_end_matches(['\r', '\n']);
        if input.is_empty() {
            return Err(DecodeError::Empty);
        }

        let columns = split_record(input, self.delimiter);
        let mut fields = FieldMap::with_capacity(columns.len() * 2);

        for (i, raw) in columns.iter().enumerate() {
            let value = match raw {
                Cow::Borrowed(s) => Value::borrowed(s),
                Cow::Owned(s) => Value::owned(s.clone()),
            };

            match self.headers.get(i) {
                Some(name) if !name.is_empty() => {
                    fields.push_unchecked(Cow::Owned(name.clone()), value.clone());
                    if self.keep_positional {
                        fields.push_unchecked(Cow::Owned(format!("col.{i}")), value);
                    }
                }
                _ => fields.push_unchecked(Cow::Owned(format!("col.{i}")), value),
            }
        }

        fields.push_unchecked("col.count", Value::Int(columns.len() as i64));
        Ok(Decoded::terminal(fields))
    }
}

/// Split one record, honouring RFC 4180 double-quoting.
///
/// A field is quoted if it *starts* with a quote; inside such a field, `""` is
/// a literal quote and the delimiter is ordinary text. Anything else is taken
/// verbatim, which is what keeps a stray quote mid-field from corrupting the
/// rest of the line.
fn split_record(input: &str, delimiter: char) -> Vec<Cow<'_, str>> {
    let mut out = Vec::with_capacity(32);
    let mut rest = input;

    loop {
        if let Some(inner) = rest.strip_prefix('"') {
            match scan_quoted(inner) {
                Some((value, after)) => {
                    out.push(value);
                    match after.strip_prefix(delimiter) {
                        Some(next) => rest = next,
                        None => break,
                    }
                    continue;
                }
                None => {
                    // Unterminated quote: take the remainder as one field.
                    out.push(Cow::Borrowed(inner));
                    break;
                }
            }
        }

        match rest.find(delimiter) {
            Some(i) => {
                out.push(Cow::Borrowed(&rest[..i]));
                rest = &rest[i + delimiter.len_utf8()..];
            }
            None => {
                out.push(Cow::Borrowed(rest));
                break;
            }
        }
    }
    out
}

/// Read a quoted field's contents, returning it and the text after the closing
/// quote. `""` collapses to `"`.
fn scan_quoted(input: &str) -> Option<(Cow<'_, str>, &str)> {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut needs_unescape = false;

    while i < bytes.len() {
        if bytes[i] == b'"' {
            if bytes.get(i + 1) == Some(&b'"') {
                needs_unescape = true;
                i += 2;
                continue;
            }
            let raw = &input[..i];
            let value = if needs_unescape {
                Cow::Owned(raw.replace("\"\"", "\""))
            } else {
                Cow::Borrowed(raw)
            };
            return Some((value, &input[i + 1..]));
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positional_columns_are_indexed_from_zero() {
        let f = CsvDecoder::default().decode("a,b,c").unwrap().fields;
        assert_eq!(f.get_str("col.0"), Some("a"));
        assert_eq!(f.get_str("col.1"), Some("b"));
        assert_eq!(f.get_str("col.2"), Some("c"));
        assert_eq!(f.get("col.count").unwrap().as_int(), Some(3));
    }

    #[test]
    fn parses_a_pan_os_traffic_record_at_documented_positions() {
        // PAN-OS traffic log: field 1 is FUTURE_USE (empty), and the doc's
        // 1-based positions map to our 0-based col.N as N = pos - 1.
        // pos 8  Source Address      -> col.7
        // pos 9  Destination Address -> col.8
        // pos 25 Source Port         -> col.24
        // pos 26 Destination Port    -> col.25
        // pos 31 Action              -> col.30
        let record = concat!(
            ",2026/08/31 10:23:45,001801234567,TRAFFIC,end,2049,",
            "2026/08/31 10:23:44,10.2.4.7,8.8.8.8,203.0.113.9,8.8.8.8,",
            "allow-dns,,,dns,vsys1,trust,untrust,ethernet1/1,ethernet1/2,",
            "log-forwarding,,12345,1,53124,53,41234,53,0x400053,udp,allow,",
            "512,64,448,4,2026/08/31 10:23:40,0,dns"
        );
        let f = CsvDecoder::default().decode(record).unwrap().fields;

        assert_eq!(f.get_str("col.3"), Some("TRAFFIC"));
        assert_eq!(f.get_str("col.7"), Some("10.2.4.7"));
        assert_eq!(f.get_str("col.8"), Some("8.8.8.8"));
        assert_eq!(f.get_str("col.24"), Some("53124"));
        assert_eq!(f.get_str("col.25"), Some("53"));
        assert_eq!(f.get_str("col.30"), Some("allow"));
        // The leading FUTURE_USE column is empty, not missing.
        assert_eq!(f.get_str("col.0"), Some(""));
    }

    #[test]
    fn quoted_fields_may_contain_the_delimiter() {
        let f = CsvDecoder::default()
            .decode(r#"a,"b,c,d",e"#)
            .unwrap()
            .fields;
        assert_eq!(f.get_str("col.1"), Some("b,c,d"));
        assert_eq!(f.get_str("col.2"), Some("e"));
        assert_eq!(f.get("col.count").unwrap().as_int(), Some(3));
    }

    #[test]
    fn doubled_quotes_collapse_to_one() {
        let f = CsvDecoder::default()
            .decode(r#"a,"say ""hi""",c"#)
            .unwrap()
            .fields;
        assert_eq!(f.get_str("col.1"), Some(r#"say "hi""#));
        assert_eq!(f.get_str("col.2"), Some("c"));
    }

    #[test]
    fn headers_produce_named_fields_alongside_positions() {
        let d = CsvDecoder::with_headers(vec![
            "future_use".into(),
            "receive_time".into(),
            "serial".into(),
        ]);
        let f = d
            .decode(",2026/08/31 10:23:45,001801234567,TRAFFIC")
            .unwrap()
            .fields;
        assert_eq!(f.get_str("receive_time"), Some("2026/08/31 10:23:45"));
        assert_eq!(f.get_str("serial"), Some("001801234567"));
        // Positional access still works, so a pack can use either.
        assert_eq!(f.get_str("col.2"), Some("001801234567"));
        // Columns past the header list degrade to positional, not an error.
        assert_eq!(f.get_str("col.3"), Some("TRAFFIC"));
    }

    #[test]
    fn empty_trailing_field_is_preserved() {
        // "a,b," is three columns, the last empty — dropping it would shift
        // every positional mapping after it in a longer record.
        let f = CsvDecoder::default().decode("a,b,").unwrap().fields;
        assert_eq!(f.get("col.count").unwrap().as_int(), Some(3));
        assert_eq!(f.get_str("col.2"), Some(""));
    }

    #[test]
    fn consecutive_empty_fields_hold_their_positions() {
        let f = CsvDecoder::default().decode("a,,,d").unwrap().fields;
        assert_eq!(f.get("col.count").unwrap().as_int(), Some(4));
        assert_eq!(f.get_str("col.1"), Some(""));
        assert_eq!(f.get_str("col.2"), Some(""));
        assert_eq!(f.get_str("col.3"), Some("d"));
    }

    #[test]
    fn unterminated_quote_does_not_lose_the_record() {
        let f = CsvDecoder::default()
            .decode(r#"a,"unclosed,b,c"#)
            .unwrap()
            .fields;
        assert_eq!(f.get_str("col.0"), Some("a"));
        assert_eq!(f.get_str("col.1"), Some("unclosed,b,c"));
    }

    #[test]
    fn single_column_record_is_valid() {
        let f = CsvDecoder::default().decode("only").unwrap().fields;
        assert_eq!(f.get_str("col.0"), Some("only"));
        assert_eq!(f.get("col.count").unwrap().as_int(), Some(1));
    }

    #[test]
    fn empty_input_errors() {
        assert_eq!(
            CsvDecoder::default().decode("").unwrap_err(),
            DecodeError::Empty
        );
    }
}
