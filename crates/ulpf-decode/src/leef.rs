//! IBM QRadar LEEF (Log Event Extended Format) decoder.
//!
//! LEEF is structurally similar to CEF but uses a different header layout.
//! Format: `LEEF:version|vendor|product|version|eventID|delimiter?|key=value...`
//!
//! LEEF 1.0 has no delimiter field (tab-separated extensions).
//! LEEF 2.0 has an explicit delimiter field after eventID.
//!
//! Common sources: IBM QRadar, Symantec Endpoint Protection, some SIEM exports.

use std::borrow::Cow;

use ulpf_core::{FieldMap, Value};

use crate::{DecodeError, Decoded, Decoder, Result};

#[derive(Debug, Clone, Copy)]
pub struct LeefDecoder;

impl Decoder for LeefDecoder {
    fn name(&self) -> &'static str {
        "leef"
    }

    fn decode<'a>(&self, input: &'a str) -> Result<Decoded<'a>> {
        let input = input.trim();
        if input.is_empty() {
            return Err(DecodeError::Empty);
        }

        // Must start with LEEF:
        let rest = input
            .strip_prefix("LEEF:")
            .ok_or(DecodeError::NotThisFormat {
                format: "leef",
                detail: "input does not start with 'LEEF:'".to_string(),
            })?;

        // Split header fields by pipe: version|vendor|product|prodversion|eventID|...
        let mut pipes = Vec::new();
        for (i, b) in rest.bytes().enumerate() {
            if b == b'|' {
                pipes.push(i);
                if pipes.len() >= 5 {
                    // After 5 pipes we have all header fields for LEEF 2.0
                    // For LEEF 1.0 we need only 4 pipes
                    break;
                }
            }
        }

        if pipes.len() < 4 {
            return Err(DecodeError::Malformed {
                format: "leef",
                offset: 0,
                detail: format!("expected at least 4 pipe separators, found {}", pipes.len()),
            });
        }

        let version = &rest[..pipes[0]];
        let vendor = &rest[pipes[0] + 1..pipes[1]];
        let product = &rest[pipes[1] + 1..pipes[2]];
        let prod_version = &rest[pipes[2] + 1..pipes[3]];

        let mut fields = FieldMap::with_capacity(24);
        fields.push_unchecked("leef.version", Value::borrowed(version));
        fields.push_unchecked("leef.vendor", Value::borrowed(vendor));
        fields.push_unchecked("leef.product", Value::borrowed(product));
        fields.push_unchecked("leef.product_version", Value::borrowed(prod_version));

        // Determine LEEF version and parse accordingly
        let (_event_id, _extensions) = if version.starts_with('2') && pipes.len() >= 5 {
            // LEEF 2.0: version|vendor|product|prodversion|eventID|delimiter|extensions
            let event_id = &rest[pipes[3] + 1..pipes[4]];
            let after_delim = &rest[pipes[4] + 1..];
            // The delimiter character is the first char after the 5th pipe,
            // but often the delimiter field itself specifies the separator.
            // If the delimiter field is a single char followed by |, use it.
            // Otherwise default to tab.
            let (delimiter, ext_start) = if let Some(pipe6) = after_delim.find('|') {
                let delim_str = &after_delim[..pipe6];
                if delim_str.len() == 1 {
                    (delim_str.chars().next().unwrap(), &after_delim[pipe6 + 1..])
                } else if delim_str == "0x09" || delim_str.is_empty() {
                    ('\t', &after_delim[pipe6 + 1..])
                } else {
                    ('\t', after_delim)
                }
            } else {
                ('\t', after_delim)
            };
            fields.push_unchecked("leef.event_id", Value::borrowed(event_id));
            parse_extensions(ext_start, delimiter, &mut fields);
            (event_id, ext_start)
        } else {
            // LEEF 1.0: version|vendor|product|prodversion|eventID|tab-separated extensions
            let event_id_and_rest = &rest[pipes[3] + 1..];
            if let Some(tab_or_pipe) = event_id_and_rest.find(['\t', '|']) {
                let event_id = &event_id_and_rest[..tab_or_pipe];
                let extensions = &event_id_and_rest[tab_or_pipe + 1..];
                fields.push_unchecked("leef.event_id", Value::borrowed(event_id));
                parse_extensions(extensions, '\t', &mut fields);
                (event_id, extensions)
            } else {
                let event_id = event_id_and_rest;
                fields.push_unchecked("leef.event_id", Value::borrowed(event_id));
                (event_id, "")
            }
        };

        Ok(Decoded::terminal(fields))
    }
}

/// Parse `key=value` pairs separated by the given delimiter.
fn parse_extensions<'a>(input: &'a str, delimiter: char, fields: &mut FieldMap<'a>) {
    for pair in input.split(delimiter) {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some(eq) = pair.find('=') {
            let key = pair[..eq].trim();
            let value = pair[eq + 1..].trim();
            if !key.is_empty() {
                fields.insert(Cow::Owned(key.to_string()), Value::borrowed(value));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(input: &str) -> FieldMap<'_> {
        LeefDecoder.decode(input).unwrap().fields
    }

    #[test]
    fn leef_1_0_basic() {
        let f = decode(
            "LEEF:1.0|Symantec|SEP|14.0|Malware|\tsrc=10.0.0.1\tdst=8.8.8.8\tproto=TCP\tsev=5",
        );
        assert_eq!(f.get_str("leef.version"), Some("1.0"));
        assert_eq!(f.get_str("leef.vendor"), Some("Symantec"));
        assert_eq!(f.get_str("leef.product"), Some("SEP"));
        assert_eq!(f.get_str("leef.event_id"), Some("Malware"));
        assert_eq!(f.get_str("src"), Some("10.0.0.1"));
        assert_eq!(f.get_str("dst"), Some("8.8.8.8"));
        assert_eq!(f.get_str("proto"), Some("TCP"));
    }

    #[test]
    fn leef_2_0_with_delimiter() {
        let f = decode(
            "LEEF:2.0|IBM|QRadar|7.3|Login|^|src=10.0.0.5^dst=192.168.1.1^usrName=admin^action=success"
        );
        assert_eq!(f.get_str("leef.version"), Some("2.0"));
        assert_eq!(f.get_str("leef.vendor"), Some("IBM"));
        assert_eq!(f.get_str("leef.event_id"), Some("Login"));
        assert_eq!(f.get_str("src"), Some("10.0.0.5"));
        assert_eq!(f.get_str("usrName"), Some("admin"));
        assert_eq!(f.get_str("action"), Some("success"));
    }

    #[test]
    fn non_leef_is_rejected() {
        assert!(LeefDecoder
            .decode("CEF:0|vendor|product|1.0|100|name|5|src=1.2.3.4")
            .is_err());
        assert!(LeefDecoder.decode("just plain text").is_err());
        assert!(LeefDecoder.decode("").is_err());
    }

    #[test]
    fn too_few_pipes_is_malformed() {
        assert!(LeefDecoder.decode("LEEF:1.0|only|two").is_err());
    }
}
