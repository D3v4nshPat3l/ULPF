//! Minimal XML element/attribute decoder.
//!
//! Real-world security logs from Check Point SmartConsole and Windows Event
//! Forwarding arrive as simple XML documents with shallow nesting. This decoder
//! extracts element text content and attributes into dotted keys without pulling
//! in a full XML library — the typical event is a single `<Event>` element with
//! a few nested `<Data Name="key">value</Data>` children, not a recursive tree.
//!
//! The parser is deliberately tolerant: it skips processing instructions,
//! comments, and CDATA markers, treating the latter as plain text. Malformed
//! XML that would choke a standards-compliant parser still yields whatever
//! fields can be extracted.

use std::borrow::Cow;

use ulpf_core::{FieldMap, Value};

use crate::{DecodeError, Decoded, Decoder, Result};

#[derive(Debug, Clone, Copy)]
pub struct XmlDecoder;

impl Decoder for XmlDecoder {
    fn name(&self) -> &'static str {
        "xml"
    }

    fn decode<'a>(&self, input: &'a str) -> Result<Decoded<'a>> {
        let input = input.trim();
        if input.is_empty() {
            return Err(DecodeError::Empty);
        }
        if !input.starts_with('<') {
            return Err(DecodeError::NotThisFormat {
                format: "xml",
                detail: "input does not start with '<'".to_string(),
            });
        }

        let mut fields = FieldMap::with_capacity(32);
        parse_elements(input, "", &mut fields);

        if fields.is_empty() {
            return Err(DecodeError::NotThisFormat {
                format: "xml",
                detail: "no elements or attributes extracted".to_string(),
            });
        }

        Ok(Decoded::terminal(fields))
    }
}

/// Walk XML text and extract elements, text content, and attributes into
/// dotted field keys. This is not a full XML parser — it handles the common
/// shapes found in security event logs.
fn parse_elements(input: &str, prefix: &str, fields: &mut FieldMap<'static>) {
    let mut rest = input;
    // How many times each element name has appeared among these siblings. The
    // index goes on the *element*, not the leaf, so a repeated element carries
    // its whole subtree — attributes and text alike — under one consistent
    // prefix.
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    while let Some(open) = rest.find('<') {
        let after_open = &rest[open + 1..];

        // Skip comments: <!-- ... -->
        if after_open.starts_with("!--") {
            if let Some(end) = after_open.find("-->") {
                rest = &after_open[end + 3..];
                continue;
            }
            break;
        }

        // Skip processing instructions: <?...?>
        if after_open.starts_with('?') {
            if let Some(end) = after_open.find("?>") {
                rest = &after_open[end + 2..];
                continue;
            }
            break;
        }

        // Skip CDATA: <![CDATA[...]]>
        if after_open.starts_with("![CDATA[") {
            if let Some(end) = after_open.find("]]>") {
                rest = &after_open[end + 3..];
                continue;
            }
            break;
        }

        // Skip closing tags
        if after_open.starts_with('/') {
            if let Some(close) = after_open.find('>') {
                rest = &after_open[close + 1..];
                continue;
            }
            break;
        }

        // Find the end of this opening tag
        let Some(tag_end) = after_open.find('>') else {
            break;
        };

        let tag_content = &after_open[..tag_end];
        let self_closing = tag_content.ends_with('/');
        let tag_content = tag_content.trim_end_matches('/');

        // Split tag name from attributes
        let (tag_name, attrs_str) = match tag_content.find(|c: char| c.is_whitespace()) {
            Some(i) => (&tag_content[..i], tag_content[i..].trim()),
            None => (tag_content, ""),
        };

        if tag_name.is_empty() || tag_name.starts_with('!') {
            rest = &after_open[tag_end + 1..];
            continue;
        }

        let base = if prefix.is_empty() {
            tag_name.to_string()
        } else {
            format!("{prefix}.{tag_name}")
        };
        let occurrence = seen.entry(base.clone()).or_insert(0);
        let key = if *occurrence == 0 {
            base.clone()
        } else {
            format!("{base}.{occurrence}")
        };
        *occurrence += 1;

        // Extract attributes
        extract_attributes(attrs_str, &key, fields);

        if self_closing {
            rest = &after_open[tag_end + 1..];
            continue;
        }

        // Find the matching closing tag
        let after_tag = &after_open[tag_end + 1..];
        if let Some(close_pos) = find_closing_tag(after_tag, tag_name) {
            let inner = &after_tag[..close_pos];
            let inner_trimmed = inner.trim();

            if inner_trimmed.contains('<') {
                // Nested elements — recurse
                parse_elements(inner, &key, fields);
            } else if !inner_trimmed.is_empty() {
                // Text content
                let text = decode_xml_entities(inner_trimmed);
                insert_unique(fields, key.clone(), Value::owned(text));
            }

            // Skip past "</tagname>"
            rest = &after_tag[close_pos + tag_name.len() + 3..];
        } else {
            rest = &after_open[tag_end + 1..];
        }
    }
}

/// Extract `key="value"` attribute pairs from a tag's attribute string.
fn extract_attributes(attrs: &str, prefix: &str, fields: &mut FieldMap<'static>) {
    let mut rest = attrs.trim();
    while !rest.is_empty() {
        // Find key=
        let Some(eq) = rest.find('=') else { break };
        let attr_name = rest[..eq].trim();
        let after_eq = rest[eq + 1..].trim();

        // Expect quoted value
        let (value, remaining) = if let Some(inner) = after_eq.strip_prefix('"') {
            match inner.find('"') {
                Some(end) => (&inner[..end], inner[end + 1..].trim()),
                None => break,
            }
        } else if let Some(inner) = after_eq.strip_prefix('\'') {
            match inner.find('\'') {
                Some(end) => (&inner[..end], inner[end + 1..].trim()),
                None => break,
            }
        } else {
            // Unquoted — take until whitespace
            match after_eq.find(char::is_whitespace) {
                Some(end) => (&after_eq[..end], after_eq[end..].trim()),
                None => (after_eq, ""),
            }
        };

        if !attr_name.is_empty() {
            let key = format!("{prefix}.@{attr_name}");
            insert_unique(fields, key, Value::owned(decode_xml_entities(value.trim())));
        }

        rest = remaining;
    }
}

/// Find the position of the closing tag, handling nested same-name elements.
///
/// Scanning is done over bytes rather than string slices. An earlier version
/// advanced a `usize` by one and then sliced `input[pos..]`, which panics the
/// moment `pos` lands inside a multi-byte character — so a single non-ASCII
/// character anywhere in an element body aborted the process. Byte comparison
/// cannot land mid-character, and every index returned points at an ASCII `<`,
/// so it is always a valid boundary for the caller to slice on.
fn find_closing_tag(input: &str, tag_name: &str) -> Option<usize> {
    let open_pat = format!("<{tag_name}");
    let close_pat = format!("</{tag_name}>");
    let bytes = input.as_bytes();
    let open = open_pat.as_bytes();
    let close = close_pat.as_bytes();

    let mut depth = 0usize;
    let mut pos = 0usize;

    while pos < bytes.len() {
        if bytes[pos..].starts_with(close) {
            if depth == 0 {
                return Some(pos);
            }
            depth -= 1;
            pos += close.len();
        } else if bytes[pos..].starts_with(open) {
            // `<Data` must be followed by a delimiter, or `<DataSet` would be
            // counted as a nested `<Data>`.
            let delimited = matches!(
                bytes.get(pos + open.len()),
                Some(b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/')
            );
            if delimited {
                depth += 1;
            }
            pos += open.len();
        } else {
            pos += 1;
        }
    }
    None
}

/// Insert a value without discarding a sibling that already claimed the key.
///
/// Repeated sibling elements are the normal shape of event XML — a Windows
/// Event Log record is a run of `<Data Name="…">` children — and a plain
/// insert kept only the last, silently losing every earlier field. The first
/// occurrence keeps the bare key so ordinary documents read naturally; later
/// ones carry their index.
fn insert_unique(fields: &mut FieldMap<'static>, key: String, value: Value<'static>) {
    if !fields.contains(&key) {
        fields.insert(Cow::Owned(key), value);
        return;
    }
    let mut n = 1usize;
    loop {
        let candidate = format!("{key}.{n}");
        if !fields.contains(&candidate) {
            fields.insert(Cow::Owned(candidate), value);
            return;
        }
        n += 1;
    }
}

/// Expand the five predefined XML entities.
///
/// `&amp;` is expanded last, on purpose. Replacing it first turns `&amp;lt;`
/// into `&lt;` and then into `<`, inventing markup the document never
/// contained — the classic double-decoding bug.
fn decode_xml_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(input: &str) -> FieldMap<'static> {
        XmlDecoder.decode(input).unwrap().fields.into_owned()
    }

    #[test]
    fn simple_element_text() {
        let f = decode("<Event><Action>allow</Action><Source>10.0.0.1</Source></Event>");
        assert_eq!(f.get_str("Event.Action"), Some("allow"));
        assert_eq!(f.get_str("Event.Source"), Some("10.0.0.1"));
    }

    #[test]
    fn attributes_are_extracted() {
        let f = decode(r#"<Data Name="TargetUserName" Type="string">admin</Data>"#);
        assert_eq!(f.get_str("Data.@Name"), Some("TargetUserName"));
        assert_eq!(f.get_str("Data"), Some("admin"));
    }

    #[test]
    fn nested_elements() {
        let f = decode("<Log><Src><IP>10.0.0.1</IP><Port>443</Port></Src></Log>");
        assert_eq!(f.get_str("Log.Src.IP"), Some("10.0.0.1"));
        assert_eq!(f.get_str("Log.Src.Port"), Some("443"));
    }

    #[test]
    fn self_closing_with_attributes() {
        let f = decode(r#"<Event><Data Name="LogonType" Value="3" /></Event>"#);
        assert_eq!(f.get_str("Event.Data.@Name"), Some("LogonType"));
        assert_eq!(f.get_str("Event.Data.@Value"), Some("3"));
    }

    #[test]
    fn xml_entities_are_decoded() {
        let f = decode("<Msg>&lt;script&gt;alert(&amp;xss)&lt;/script&gt;</Msg>");
        assert_eq!(f.get_str("Msg"), Some("<script>alert(&xss)</script>"));
    }

    #[test]
    fn non_xml_is_rejected() {
        assert!(XmlDecoder.decode("not xml at all").is_err());
        assert!(XmlDecoder.decode("").is_err());
    }

    #[test]
    fn non_ascii_content_does_not_panic() {
        // This aborted the collector: the scanner advanced one byte at a time
        // and then sliced, landing inside a multi-byte character.
        let f = decode("<Event><Msg>日本語</Msg></Event>");
        assert_eq!(f.get_str("Event.Msg"), Some("日本語"));
    }

    #[test]
    fn non_ascii_survives_everywhere_a_scanner_runs() {
        let f = decode(r#"<Event><User Name="Ωmega">उपयोगकर्ता अस्वीकृत</User></Event>"#);
        assert_eq!(f.get_str("Event.User.@Name"), Some("Ωmega"));
        assert_eq!(f.get_str("Event.User"), Some("उपयोगकर्ता अस्वीकृत"));
    }

    #[test]
    fn repeated_siblings_are_all_kept() {
        // The Windows Event Log shape. Every `<Data>` used to overwrite the
        // previous one, so a record kept exactly one of its fields.
        let f = decode(concat!(
            "<Event><EventData>",
            r#"<Data Name="TargetUserName">admin</Data>"#,
            r#"<Data Name="LogonType">3</Data>"#,
            r#"<Data Name="IpAddress">10.0.0.9</Data>"#,
            "</EventData></Event>"
        ));
        assert_eq!(
            f.get_str("Event.EventData.Data.@Name"),
            Some("TargetUserName")
        );
        assert_eq!(f.get_str("Event.EventData.Data"), Some("admin"));
        assert_eq!(f.get_str("Event.EventData.Data.1.@Name"), Some("LogonType"));
        assert_eq!(f.get_str("Event.EventData.Data.1"), Some("3"));
        assert_eq!(f.get_str("Event.EventData.Data.2.@Name"), Some("IpAddress"));
        assert_eq!(f.get_str("Event.EventData.Data.2"), Some("10.0.0.9"));
    }

    #[test]
    fn entities_are_not_decoded_twice() {
        // `&amp;lt;` is a literal "&lt;", not a "<". Expanding &amp; first
        // invents markup the document never carried.
        let f = decode("<Msg>&amp;lt;not-a-tag&amp;gt;</Msg>");
        assert_eq!(f.get_str("Msg"), Some("&lt;not-a-tag&gt;"));
    }

    #[test]
    fn a_similarly_named_child_does_not_close_its_parent() {
        let f = decode("<Data><DataSet>inner</DataSet></Data>");
        assert_eq!(f.get_str("Data.DataSet"), Some("inner"));
    }
}
