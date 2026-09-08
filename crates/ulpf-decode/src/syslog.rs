//! Syslog envelope decoding: RFC 3164 (BSD) and RFC 5424.
//!
//! The two formats share a `<PRI>` prefix and diverge immediately after, so one
//! decoder handles both and dispatches on what follows.
//!
//! Tolerance is the point here. RFC 3164 was written to describe what was
//! already deployed rather than to constrain it, and perimeter devices take
//! full advantage: FortiGate sends `<134>date=2026-08-31 time=...` with no
//! timestamp or hostname at all, Cisco emits its own `%ASA-6-302013` tag
//! instead of a program name, and plenty of appliances simply omit the
//! hostname. Every field after `<PRI>` is therefore optional, and anything that
//! does not match is left in the body for the next decoder rather than
//! rejected.

use ulpf_core::{FieldMap, Value};

use crate::{DecodeError, Decoded, Decoder, Result};

/// Which syslog dialects to accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Auto,
    Rfc3164,
    Rfc5424,
}

/// Decodes the syslog envelope, leaving the message body for the next decoder.
#[derive(Debug, Clone)]
pub struct SyslogDecoder {
    dialect: Dialect,
}

impl Default for SyslogDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SyslogDecoder {
    /// Accept either dialect, dispatching on what follows `<PRI>`.
    pub fn new() -> Self {
        Self {
            dialect: Dialect::Auto,
        }
    }

    pub fn rfc3164_only() -> Self {
        Self {
            dialect: Dialect::Rfc3164,
        }
    }

    pub fn rfc5424_only() -> Self {
        Self {
            dialect: Dialect::Rfc5424,
        }
    }
}

impl Decoder for SyslogDecoder {
    fn name(&self) -> &'static str {
        match self.dialect {
            Dialect::Auto => "syslog",
            Dialect::Rfc3164 => "syslog_rfc3164",
            Dialect::Rfc5424 => "syslog_rfc5424",
        }
    }

    fn decode<'a>(&self, input: &'a str) -> Result<Decoded<'a>> {
        let input = input.trim_end_matches(['\r', '\n', '\0']);
        if input.is_empty() {
            return Err(DecodeError::Empty);
        }

        let mut fields = FieldMap::with_capacity(8);
        let rest = match parse_pri(input) {
            Some((priority, rest)) => {
                fields.push_unchecked("syslog.priority", Value::Int(priority as i64));
                fields.push_unchecked("syslog.facility", Value::Int((priority / 8) as i64));
                fields.push_unchecked("syslog.severity", Value::Int((priority % 8) as i64));
                rest
            }
            None => {
                // A relay may strip the PRI, or the transport may deliver the
                // body alone. That is not a reason to lose the event.
                if self.dialect != Dialect::Auto {
                    return Err(DecodeError::NotThisFormat {
                        format: "syslog",
                        detail: "missing <PRI> prefix".to_string(),
                    });
                }
                input
            }
        };

        let use_5424 = match self.dialect {
            Dialect::Rfc5424 => true,
            Dialect::Rfc3164 => false,
            Dialect::Auto => looks_like_rfc5424(rest),
        };

        let body = if use_5424 {
            parse_5424(rest, &mut fields)?
        } else {
            parse_3164(rest, &mut fields)
        };

        Ok(Decoded::with_body(fields, body))
    }
}

/// Parse `<NNN>` and return the priority with the remainder.
fn parse_pri(input: &str) -> Option<(u16, &str)> {
    let rest = input.strip_prefix('<')?;
    let close = rest.find('>')?;
    // A priority is at most three digits; anything longer is a `<` that
    // happens to appear in a message, not a PRI.
    if close == 0 || close > 3 {
        return None;
    }
    let priority: u16 = rest[..close].parse().ok()?;
    if priority > 191 {
        return None;
    }
    Some((priority, &rest[close + 1..]))
}

/// RFC 5424 starts with a version number followed by a space.
fn looks_like_rfc5424(rest: &str) -> bool {
    let mut chars = rest.char_indices();
    let mut seen_digit = false;
    for (i, c) in &mut chars {
        if c.is_ascii_digit() {
            seen_digit = true;
            if i > 1 {
                return false; // version is 1..2 digits in practice
            }
        } else {
            return seen_digit && c == ' ';
        }
    }
    false
}

/// `VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [SP MSG]`
fn parse_5424<'a>(input: &'a str, fields: &mut FieldMap<'a>) -> Result<&'a str> {
    let mut rest = input;

    let (version, r) = take_token(rest);
    fields.push_unchecked("syslog.version", Value::borrowed(version));
    rest = r;

    for key in [
        "syslog.timestamp",
        "syslog.hostname",
        "syslog.appname",
        "syslog.procid",
        "syslog.msgid",
    ] {
        let (token, r) = take_token(rest);
        if !token.is_empty() && token != "-" {
            fields.push_unchecked(key, Value::borrowed(token));
        }
        rest = r;
    }

    // Structured data: either `-` or one or more `[id key="value" ...]` blocks.
    rest = if let Some(r) = rest.strip_prefix('-') {
        r.strip_prefix(' ').unwrap_or(r)
    } else if rest.starts_with('[') {
        let (sd, r) = take_structured_data(rest)?;
        parse_structured_data(sd, fields);
        r.strip_prefix(' ').unwrap_or(r)
    } else {
        rest
    };

    // RFC 5424 permits a UTF-8 BOM before the message.
    Ok(rest.strip_prefix('\u{feff}').unwrap_or(rest))
}

/// Split off the `[...]` structured-data section, honouring escapes.
fn take_structured_data(input: &str) -> Result<(&str, &str)> {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    let mut in_quotes = false;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_quotes => i += 1, // skip the escaped byte
            b'"' => in_quotes = !in_quotes,
            b'[' if !in_quotes => depth += 1,
            b']' if !in_quotes => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&input[..=i], &input[i + 1..]));
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err(DecodeError::Malformed {
        format: "syslog_rfc5424",
        offset: input.len(),
        detail: "unterminated structured data".to_string(),
    })
}

/// Extract `key="value"` pairs from structured data, namespaced by element id.
fn parse_structured_data<'a>(sd: &'a str, fields: &mut FieldMap<'a>) {
    let mut rest = sd;
    while let Some(open) = rest.find('[') {
        let inner_start = open + 1;
        let Ok((element, after)) = take_structured_data(&rest[open..]) else {
            return;
        };
        let inner = &element[1..element.len() - 1];
        let (id, mut params) = take_token(inner);
        if !id.is_empty() {
            fields.insert(
                std::borrow::Cow::Owned(format!("syslog.sd.{id}")),
                Value::borrowed(id),
            );
        }
        while let Some(eq) = params.find('=') {
            let key = params[..eq].trim();
            let after_eq = &params[eq + 1..];
            let Some(rest_q) = after_eq.strip_prefix('"') else {
                break;
            };
            let Some(end) = find_unescaped_quote(rest_q) else {
                break;
            };
            let value = &rest_q[..end];
            if !key.is_empty() {
                fields.insert(
                    std::borrow::Cow::Owned(format!("syslog.sd.{id}.{key}")),
                    Value::borrowed(value),
                );
            }
            params = rest_q[end + 1..].trim_start();
        }
        let _ = inner_start;
        rest = after;
    }
}

fn find_unescaped_quote(s: &str) -> Option<usize> {
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

/// `TIMESTAMP SP HOSTNAME SP TAG[PID]: MSG`, with every part optional.
///
/// Returns the message body. When the header does not match the RFC shape —
/// which is the common case for appliances — the whole input becomes the body,
/// and the pack's next decoder gets to see all of it.
fn parse_3164<'a>(input: &'a str, fields: &mut FieldMap<'a>) -> &'a str {
    let mut rest = input;

    if let Some((timestamp, r)) = take_3164_timestamp(rest) {
        fields.push_unchecked("syslog.timestamp", Value::borrowed(timestamp));
        rest = r;

        // A hostname is only plausible directly after a valid timestamp.
        let (candidate, after) = take_token(rest);
        if is_plausible_hostname(candidate) {
            fields.push_unchecked("syslog.hostname", Value::borrowed(candidate));
            rest = after;
        }
    }

    if let Some((tag, pid, r)) = take_3164_tag(rest) {
        fields.push_unchecked("syslog.appname", Value::borrowed(tag));
        if let Some(pid) = pid {
            fields.push_unchecked("syslog.procid", Value::borrowed(pid));
        }
        rest = r;
    }

    rest
}

/// `MMM d HH:MM:SS`, where the day may be space-padded (exactly 15
/// characters), or Cisco's own `MMM d YYYY HH:MM:SS` variant (20 characters)
/// emitted when `service timestamps log datetime year` is configured on ASA
/// and IOS devices — confirmed against a real ASA capture (Elastic's
/// `cisco_asa` integration test fixtures use exactly this shape, e.g.
/// `Oct 10 2018 12:34:56`). Without the second form, a device configured
/// this way loses its whole syslog header — timestamp, hostname and tag all
/// silently absent — because the fixed-width classic parse never matches.
fn take_3164_timestamp(input: &str) -> Option<(&str, &str)> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    if input.len() < 15 || !input.is_char_boundary(15) {
        return None;
    }
    if !MONTHS.contains(&&input[..3]) {
        return None;
    }
    let b = input.as_bytes();
    let day_ok = b[3] == b' '
        && (b[4].is_ascii_digit() || b[4] == b' ')
        && b[5].is_ascii_digit()
        && b[6] == b' ';
    if !day_ok {
        return None;
    }

    if is_hms(&input[7..15]) {
        let rest = input[15..].strip_prefix(' ').unwrap_or(&input[15..]);
        return Some((&input[..15], rest));
    }

    if input.len() >= 20 && input.is_char_boundary(20) {
        let year_ok = input.as_bytes()[7..11].iter().all(u8::is_ascii_digit) && b[11] == b' ';
        if year_ok && is_hms(&input[12..20]) {
            let rest = input[20..].strip_prefix(' ').unwrap_or(&input[20..]);
            return Some((&input[..20], rest));
        }
    }

    None
}

/// `HH:MM:SS`, exactly 8 bytes.
fn is_hms(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 8
        && b[2] == b':'
        && b[5] == b':'
        && b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b[4].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[7].is_ascii_digit()
}

/// Reject tokens that are obviously the start of a message body rather than a
/// hostname — the single most common way a tolerant 3164 parser goes wrong.
fn is_plausible_hostname(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 255
        && !token.contains('=')
        && !token.contains(':')
        && !token.contains('%')
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// `tag[pid]:` or `tag:`, where the tag is alphanumeric.
fn take_3164_tag(input: &str) -> Option<(&str, Option<&str>, &str)> {
    let colon = input.find(':')?;
    // The RFC caps the tag at 32 characters; a longer run to the first colon is
    // message text that happens to contain one.
    if colon == 0 || colon > 40 {
        return None;
    }
    let head = &input[..colon];
    let rest = input[colon + 1..]
        .strip_prefix(' ')
        .unwrap_or(&input[colon + 1..]);

    if let Some(open) = head.find('[') {
        let pid = head.get(open + 1..head.len().saturating_sub(1))?;
        if !head.ends_with(']') || !pid.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let tag = &head[..open];
        if tag.is_empty() || !is_tag_like(tag) {
            return None;
        }
        return Some((tag, Some(pid), rest));
    }

    if !is_tag_like(head) {
        return None;
    }
    Some((head, None, rest))
}

fn is_tag_like(s: &str) -> bool {
    !s.is_empty()
        && !s.contains(' ')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

/// Split off the next space-delimited token.
fn take_token(input: &str) -> (&str, &str) {
    match memchr::memchr(b' ', input.as_bytes()) {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => (input, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(input: &str) -> Decoded<'_> {
        SyslogDecoder::new().decode(input).unwrap()
    }

    #[test]
    fn priority_decomposes_into_facility_and_severity() {
        let d = decode("<134>Aug 31 10:23:45 fw-01 kernel: something happened");
        // 134 = facility 16 (local0) * 8 + severity 6 (informational)
        assert_eq!(d.fields.get("syslog.priority").unwrap().as_int(), Some(134));
        assert_eq!(d.fields.get("syslog.facility").unwrap().as_int(), Some(16));
        assert_eq!(d.fields.get("syslog.severity").unwrap().as_int(), Some(6));
    }

    #[test]
    fn parses_a_textbook_rfc3164_line() {
        let d = decode("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick");
        assert_eq!(
            d.fields.get_str("syslog.timestamp"),
            Some("Oct 11 22:14:15")
        );
        assert_eq!(d.fields.get_str("syslog.hostname"), Some("mymachine"));
        assert_eq!(d.fields.get_str("syslog.appname"), Some("su"));
        assert_eq!(d.body, Some("'su root' failed for lonvick"));
    }

    #[test]
    fn parses_a_space_padded_day() {
        // RFC 3164 pads single-digit days with a space, not a zero.
        let d = decode("<13>Aug  1 09:05:03 host app: msg");
        assert_eq!(
            d.fields.get_str("syslog.timestamp"),
            Some("Aug  1 09:05:03")
        );
        assert_eq!(d.fields.get_str("syslog.hostname"), Some("host"));
    }

    #[test]
    fn extracts_pid_from_the_tag() {
        let d = decode("<13>Aug  1 09:05:03 host sshd[1234]: Accepted password");
        assert_eq!(d.fields.get_str("syslog.appname"), Some("sshd"));
        assert_eq!(d.fields.get_str("syslog.procid"), Some("1234"));
        assert_eq!(d.body, Some("Accepted password"));
    }

    #[test]
    fn fortigate_style_line_keeps_its_whole_body() {
        // FortiGate omits timestamp, hostname and tag entirely. The key=value
        // body must survive intact for the next decoder in the chain.
        let line = "<134>date=2026-08-31 time=10:23:45 devname=\"FGT-01\" srcip=10.2.4.7";
        let d = decode(line);
        assert_eq!(d.fields.get("syslog.priority").unwrap().as_int(), Some(134));
        assert!(d.fields.get("syslog.hostname").is_none());
        assert_eq!(
            d.body,
            Some("date=2026-08-31 time=10:23:45 devname=\"FGT-01\" srcip=10.2.4.7")
        );
    }

    #[test]
    fn cisco_asa_year_timestamp_still_yields_a_hostname() {
        // `service timestamps log datetime year` shape, confirmed against
        // Elastic's cisco_asa integration test fixtures (a real ASA capture).
        let line = "<166>Oct 10 2018 12:34:56 localhost CiscoASA[999]: %ASA-6-302013: Built outbound TCP connection";
        let d = decode(line);
        assert_eq!(
            d.fields.get_str("syslog.timestamp"),
            Some("Oct 10 2018 12:34:56")
        );
        assert_eq!(d.fields.get_str("syslog.hostname"), Some("localhost"));
        assert_eq!(d.fields.get_str("syslog.appname"), Some("CiscoASA"));
        assert_eq!(d.fields.get_str("syslog.procid"), Some("999"));
        assert!(d.body.unwrap().starts_with("%ASA-6-302013"));
    }

    #[test]
    fn cisco_asa_year_timestamp_with_space_padded_day() {
        let line = "<166>Oct  1 2018 12:34:56 localhost CiscoASA[999]: %ASA-6-302013: Built";
        let d = decode(line);
        assert_eq!(
            d.fields.get_str("syslog.timestamp"),
            Some("Oct  1 2018 12:34:56")
        );
        assert_eq!(d.fields.get_str("syslog.hostname"), Some("localhost"));
    }

    #[test]
    fn cisco_asa_percent_tag_is_not_mistaken_for_a_hostname() {
        let line = "<166>Aug 31 10:23:45 %ASA-6-302013: Built outbound TCP connection";
        let d = decode(line);
        assert_eq!(
            d.fields.get_str("syslog.timestamp"),
            Some("Aug 31 10:23:45")
        );
        // `%ASA-6-302013` is message content, not a hostname.
        assert!(d.fields.get("syslog.hostname").is_none());
        assert!(d.body.unwrap().starts_with("%ASA-6-302013"));
    }

    #[test]
    fn parses_rfc5424_with_nil_structured_data() {
        let line = "<34>1 2026-08-31T22:14:15.003Z mymachine.example.com su - ID47 - msg here";
        let d = decode(line);
        assert_eq!(d.fields.get_str("syslog.version"), Some("1"));
        assert_eq!(
            d.fields.get_str("syslog.timestamp"),
            Some("2026-08-31T22:14:15.003Z")
        );
        assert_eq!(
            d.fields.get_str("syslog.hostname"),
            Some("mymachine.example.com")
        );
        assert_eq!(d.fields.get_str("syslog.appname"), Some("su"));
        // A bare `-` means absent and must not become the literal string "-".
        assert!(d.fields.get("syslog.procid").is_none());
        assert_eq!(d.fields.get_str("syslog.msgid"), Some("ID47"));
        assert_eq!(d.body, Some("msg here"));
    }

    #[test]
    fn parses_rfc5424_structured_data() {
        let line = concat!(
            r#"<165>1 2026-08-31T22:14:15.003Z host evntslog - ID47 "#,
            r#"[exampleSDID@32473 iut="3" eventSource="Application"] An application event"#
        );
        let d = decode(line);
        assert_eq!(
            d.fields.get_str("syslog.sd.exampleSDID@32473.iut"),
            Some("3")
        );
        assert_eq!(
            d.fields.get_str("syslog.sd.exampleSDID@32473.eventSource"),
            Some("Application")
        );
        assert_eq!(d.body, Some("An application event"));
    }

    #[test]
    fn structured_data_with_escaped_bracket_does_not_terminate_early() {
        let line = r#"<165>1 2026-08-31T22:14:15Z h app - - [id@1 msg="a\]b"] tail"#;
        let d = decode(line);
        assert_eq!(d.fields.get_str("syslog.sd.id@1.msg"), Some(r"a\]b"));
        assert_eq!(d.body, Some("tail"));
    }

    #[test]
    fn dialect_detection_prefers_5424_when_versioned() {
        assert!(looks_like_rfc5424("1 2026-08-31T22:14:15Z h a - - -"));
        // A 3164 timestamp must not be read as a version number.
        assert!(!looks_like_rfc5424("Aug 31 10:23:45 host app: msg"));
        assert!(!looks_like_rfc5424("date=2026-08-31 srcip=1.1.1.1"));
    }

    #[test]
    fn missing_pri_is_tolerated_in_auto_mode() {
        let d = decode("Aug 31 10:23:45 fw-01 kernel: no pri here");
        assert!(d.fields.get("syslog.priority").is_none());
        assert_eq!(d.fields.get_str("syslog.hostname"), Some("fw-01"));
        assert_eq!(d.body, Some("no pri here"));
    }

    #[test]
    fn missing_pri_is_rejected_when_a_dialect_is_pinned() {
        let err = SyslogDecoder::rfc5424_only()
            .decode("2026-08-31T22:14:15Z host app - - - msg")
            .unwrap_err();
        assert!(matches!(err, DecodeError::NotThisFormat { .. }));
    }

    #[test]
    fn out_of_range_priority_is_not_treated_as_pri() {
        // 999 exceeds the 0..191 range, so `<999>` is message text.
        let d = decode("<999>this is just text");
        assert!(d.fields.get("syslog.priority").is_none());
        assert_eq!(d.body, Some("<999>this is just text"));
    }

    #[test]
    fn trailing_newlines_and_nulls_are_stripped() {
        let d = decode("<134>Aug 31 10:23:45 host app: body\r\n\0");
        assert_eq!(d.body, Some("body"));
    }

    #[test]
    fn empty_input_errors() {
        assert_eq!(
            SyslogDecoder::new().decode("").unwrap_err(),
            DecodeError::Empty
        );
        assert_eq!(
            SyslogDecoder::new().decode("\n").unwrap_err(),
            DecodeError::Empty
        );
    }

    #[test]
    fn a_colon_deep_in_message_text_is_not_a_tag() {
        let line = "<134>Aug 31 10:23:45 host this is a long message with a colon: right here";
        let d = decode(line);
        assert!(d.fields.get("syslog.appname").is_none());
        assert!(d.body.unwrap().starts_with("this is a long message"));
    }

    #[test]
    fn utf8_message_bodies_survive() {
        let d = decode("<134>Aug 31 10:23:45 host app: उपयोगकर्ता अस्वीकृत");
        assert_eq!(d.body, Some("उपयोगकर्ता अस्वीकृत"));
    }
}
