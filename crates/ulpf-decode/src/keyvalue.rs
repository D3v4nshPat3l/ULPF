//! `key=value` body decoding, as emitted by FortiGate, Sophos, Check Point and
//! most appliances that did not choose CSV.
//!
//! The awkward part is not the pairs, it is the values: they may be bare
//! (`srcip=10.2.4.7`), quoted with embedded spaces (`devname="FGT DEL 01"`),
//! quoted with embedded escapes, or empty (`user=`). A bare value ends at the
//! next space, but only if that space is not inside quotes — and a device that
//! forgets a closing quote must still yield the fields before it rather than
//! swallowing the rest of the line.

use std::borrow::Cow;

use ulpf_core::{FieldMap, Value};

use crate::{DecodeError, Decoded, Decoder, Result};

/// Decodes a `key=value` body into fields.
#[derive(Debug, Clone)]
pub struct KeyValueDecoder {
    /// Character separating a key from its value.
    pub separator: char,
    /// Character separating one pair from the next.
    pub delimiter: char,
    /// Strip surrounding quotes from values.
    pub unquote: bool,
}

impl Default for KeyValueDecoder {
    fn default() -> Self {
        Self {
            separator: '=',
            delimiter: ' ',
            unquote: true,
        }
    }
}

impl KeyValueDecoder {
    pub fn new(separator: char, delimiter: char) -> Self {
        Self {
            separator,
            delimiter,
            unquote: true,
        }
    }
}

impl Decoder for KeyValueDecoder {
    fn name(&self) -> &'static str {
        "keyvalue"
    }

    fn decode<'a>(&self, input: &'a str) -> Result<Decoded<'a>> {
        let input = input.trim();
        if input.is_empty() {
            return Err(DecodeError::Empty);
        }

        let mut fields = FieldMap::with_capacity(24);
        let mut rest = input;
        let mut found_any = false;

        while !rest.is_empty() {
            rest = rest.trim_start_matches(self.delimiter);
            if rest.is_empty() {
                break;
            }

            let Some(sep) = rest.find(self.separator) else {
                break; // trailing text with no pair in it
            };

            // The key is the last token before the separator. Devices routinely
            // prefix free text — `Traffic was logged srcip=10.0.0.1` — and the
            // words before `srcip` are prose, not part of the key. Taking the
            // whole span would both invent a junk field name and lose the pair.
            let key = rest[..sep]
                .rsplit(self.delimiter)
                .next()
                .unwrap_or("")
                .trim();
            let after = &rest[sep + self.separator.len_utf8()..];

            let (value, remainder) = self.take_value(after);

            if !key.is_empty() {
                found_any = true;
                fields.insert(Cow::Borrowed(key), value);
            }
            rest = remainder;
        }

        if !found_any {
            return Err(DecodeError::NotThisFormat {
                format: "keyvalue",
                detail: format!("no `{}` pairs found", self.separator),
            });
        }
        Ok(Decoded::terminal(fields))
    }
}

impl KeyValueDecoder {
    /// Split one value off the front, returning it and what follows.
    fn take_value<'a>(&self, input: &'a str) -> (Value<'a>, &'a str) {
        if self.unquote {
            if let Some(inner) = input.strip_prefix('"') {
                return match find_closing_quote(inner) {
                    Some(end) => {
                        let raw = &inner[..end];
                        let value = if raw.contains('\\') {
                            Value::owned(unescape(raw))
                        } else {
                            Value::borrowed(raw)
                        };
                        (value, &inner[end + 1..])
                    }
                    // Unterminated quote: take the rest of the line rather than
                    // dropping everything after it.
                    None => (Value::borrowed(inner), ""),
                };
            }
        }

        match input.find(self.delimiter) {
            Some(i) => (Value::borrowed(&input[..i]), &input[i..]),
            None => (Value::borrowed(input), ""),
        }
    }
}

fn find_closing_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn unescape(s: &str) -> String {
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
        KeyValueDecoder::default().decode(input).unwrap().fields
    }

    #[test]
    fn parses_a_real_fortigate_traffic_line() {
        let line = concat!(
            r#"date=2025-12-23 time=17:45:18 devname="ELA" devid="FG234234567890" "#,
            r#"logid="0000000045" type="traffic" subtype="forward" level="warning" "#,
            r#"vd="root" srcip=192.178.1.200 srcport=52341 srcintf="port1" "#,
            r#"dstip=8.8.8.8 dstport=443 dstintf="wan1" proto=6 action="accept" "#,
            r#"policyid=1 sessionid=10045 duration=30 sentbyte=2500 rcvdbyte=2200"#
        );
        let f = decode(line);

        assert_eq!(f.get_str("devname"), Some("ELA"));
        assert_eq!(f.get_str("srcip"), Some("192.178.1.200"));
        assert_eq!(f.get("srcport").unwrap().as_int(), Some(52341));
        assert_eq!(f.get_str("dstip"), Some("8.8.8.8"));
        assert_eq!(f.get("dstport").unwrap().as_int(), Some(443));
        assert_eq!(f.get_str("action"), Some("accept"));
        assert_eq!(f.get("sentbyte").unwrap().as_int(), Some(2500));
        assert_eq!(f.get_str("type"), Some("traffic"));
    }

    #[test]
    fn quoted_values_may_contain_spaces() {
        let f = decode(r#"devname="FGT DEL 01" srcip=10.0.0.1"#);
        assert_eq!(f.get_str("devname"), Some("FGT DEL 01"));
        assert_eq!(f.get_str("srcip"), Some("10.0.0.1"));
    }

    #[test]
    fn escaped_quotes_inside_values_are_handled() {
        let f = decode(r#"msg="he said \"hello\" loudly" action=accept"#);
        assert_eq!(f.get_str("msg"), Some(r#"he said "hello" loudly"#));
        assert_eq!(f.get_str("action"), Some("accept"));
    }

    #[test]
    fn unterminated_quote_keeps_earlier_fields() {
        // A truncated line must not cost us the fields that did arrive.
        let f = decode(r#"srcip=10.0.0.1 action=accept msg="truncated here"#);
        assert_eq!(f.get_str("srcip"), Some("10.0.0.1"));
        assert_eq!(f.get_str("action"), Some("accept"));
        assert_eq!(f.get_str("msg"), Some("truncated here"));
    }

    #[test]
    fn empty_values_are_kept_as_empty_not_dropped() {
        let f = decode("user= srcip=10.0.0.1");
        assert!(f.contains("user"));
        // Present but empty reads as absent for mapping purposes.
        assert!(f.get_present("user").is_none());
        assert_eq!(f.get_str("srcip"), Some("10.0.0.1"));
    }

    #[test]
    fn values_containing_equals_are_not_re_split() {
        let f = decode(r#"url="http://x/?a=b&c=d" action=block"#);
        assert_eq!(f.get_str("url"), Some("http://x/?a=b&c=d"));
        assert_eq!(f.get_str("action"), Some("block"));
    }

    #[test]
    fn free_text_before_pairs_does_not_create_junk_keys() {
        let f = decode("Traffic was logged srcip=10.0.0.1 action=accept");
        assert_eq!(f.get_str("srcip"), Some("10.0.0.1"));
        assert!(!f.keys().any(|k| k.contains(' ')));
    }

    #[test]
    fn a_body_with_no_pairs_is_rejected_so_the_pack_can_fall_through() {
        let err = KeyValueDecoder::default()
            .decode("Built outbound TCP connection for outside")
            .unwrap_err();
        assert!(matches!(err, DecodeError::NotThisFormat { .. }));
    }

    #[test]
    fn custom_separator_and_delimiter() {
        let d = KeyValueDecoder::new(':', ';');
        let f = d
            .decode("src:10.0.0.1;dst:8.8.8.8;port:443")
            .unwrap()
            .fields;
        assert_eq!(f.get_str("src"), Some("10.0.0.1"));
        assert_eq!(f.get_str("port"), Some("443"));
    }

    #[test]
    fn duplicate_keys_keep_the_last_value() {
        let f = decode("action=accept srcip=1.1.1.1 action=deny");
        assert_eq!(f.get_str("action"), Some("deny"));
    }

    #[test]
    fn empty_input_errors() {
        assert_eq!(
            KeyValueDecoder::default().decode("   ").unwrap_err(),
            DecodeError::Empty
        );
    }
}
