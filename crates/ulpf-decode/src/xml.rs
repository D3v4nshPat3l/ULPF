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

        let key = if prefix.is_empty() {
            tag_name.to_string()
        } else {
            format!("{prefix}.{tag_name}")
        };

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
                fields.insert(Cow::Owned(key.clone()), Value::owned(text));
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
            fields.insert(Cow::Owned(key), Value::owned(value.to_string()));
        }

        rest = remaining;
    }
}

/// Find the position of the closing tag, handling nested same-name elements.
fn find_closing_tag(input: &str, tag_name: &str) -> Option<usize> {
    let open_pat = format!("<{tag_name}");
    let close_pat = format!("</{tag_name}>");
    let mut depth = 0;
    let mut pos = 0;

    while pos < input.len() {
        if input[pos..].starts_with(&close_pat) {
            if depth == 0 {
                return Some(pos);
            }
            depth -= 1;
            pos += close_pat.len();
        } else if input[pos..].starts_with(&open_pat) {
            let after = &input[pos + open_pat.len()..];
            if after.starts_with(|c: char| c.is_whitespace() || c == '>' || c == '/') {
                depth += 1;
            }
            pos += open_pat.len();
        } else {
            pos += 1;
        }
    }
    None
}

fn decode_xml_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
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
}
