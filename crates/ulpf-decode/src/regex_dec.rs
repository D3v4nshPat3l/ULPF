//! Regex extraction, for the structured-text formats that are not key-value.
//!
//! Plenty of perimeter devices write a fixed sentence rather than named pairs:
//! iptables puts the verdict in a message prefix (`INBOUND TCP:`), Snort writes
//! `[1:483:5] ICMP PING [Priority: 3]: {ICMP} 1.2.3.4 -> 5.6.7.8`, and Cisco
//! ASA leads with `%ASA-6-302013:`. None of that is addressable by the other
//! decoders, and all of it is trivially addressable by a named capture group.
//!
//! Two design choices make this composable rather than a replacement for the
//! other decoders:
//!
//! * **Extraction is additive, not consuming.** By default the whole input is
//!   passed on to the next decoder, so a pack can pull the prefix out with a
//!   regex and *still* run `keyvalue` over the same line. Name a group `body`
//!   to narrow what the next stage sees instead.
//! * **Patterns are tried in order.** A device with several message shapes gets
//!   one decoder step with several alternatives rather than several packs.
//!
//! Patterns are compiled once when the pack is compiled, never per event.

use std::borrow::Cow;

use regex::Regex;
use ulpf_core::{FieldMap, Value};

use crate::{DecodeError, Decoded, Decoder, Result};

/// Name of the capture group that, if present, becomes the body handed to the
/// next decoder in the chain.
const BODY_GROUP: &str = "body";

/// Extracts named capture groups into fields.
#[derive(Debug, Clone)]
pub struct RegexDecoder {
    patterns: Vec<Regex>,
    /// Emit the index of the pattern that matched, as `regex.matched`.
    ///
    /// Useful when a device has several message shapes and the mapping needs to
    /// branch on which one arrived.
    pub record_which: bool,
}

impl RegexDecoder {
    /// Compile a set of alternatives, tried in order.
    pub fn new(patterns: &[String]) -> std::result::Result<Self, regex::Error> {
        let compiled = patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Self {
            patterns: compiled,
            record_which: false,
        })
    }

    pub fn record_which(mut self, yes: bool) -> Self {
        self.record_which = yes;
        self
    }
}

impl Decoder for RegexDecoder {
    fn name(&self) -> &'static str {
        "regex"
    }

    fn decode<'a>(&self, input: &'a str) -> Result<Decoded<'a>> {
        let input = input.trim_end_matches(['\r', '\n']);
        if input.is_empty() {
            return Err(DecodeError::Empty);
        }

        for (i, re) in self.patterns.iter().enumerate() {
            let Some(caps) = re.captures(input) else {
                continue;
            };

            let mut fields = FieldMap::with_capacity(re.captures_len());
            let mut body: Option<&'a str> = None;

            for name in re.capture_names().flatten() {
                let Some(m) = caps.name(name) else { continue };
                // Borrow from the caller's buffer, not from `caps`, so the
                // extracted values carry the input's lifetime and cost nothing.
                let text = &input[m.start()..m.end()];
                if name == BODY_GROUP {
                    body = Some(text);
                    continue;
                }
                // The key is owned because capture names borrow from the
                // compiled pattern, not from the input. Values stay borrowed,
                // which is where the bytes actually are.
                fields.insert(Cow::Owned(name.to_string()), Value::borrowed(text));
            }

            if self.record_which {
                fields.insert(
                    Cow::Owned("regex.matched".to_string()),
                    Value::Int(i as i64),
                );
            }

            // Additive by default: hand the whole line onward so a later
            // decoder can still read it.
            return Ok(Decoded::with_body(fields, body.unwrap_or(input)));
        }

        Err(DecodeError::NotThisFormat {
            format: "regex",
            detail: format!("no pattern matched ({} tried)", self.patterns.len()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(patterns: &[&str]) -> RegexDecoder {
        RegexDecoder::new(&patterns.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn named_groups_become_fields() {
        let d = dec([r"^(?P<action>[A-Z ]+):"].as_slice());
        let out = d.decode("INBOUND TCP: SRC=1.2.3.4").unwrap();
        assert_eq!(out.fields.get_str("action"), Some("INBOUND TCP"));
    }

    #[test]
    fn extraction_is_additive_so_keyvalue_can_still_run() {
        // This is the property that lets one line be read by two decoders.
        let d = dec([r"^(?P<action>[A-Z ]+):"].as_slice());
        let line = "INBOUND TCP: SRC=1.2.3.4 DPT=445";
        let out = d.decode(line).unwrap();
        assert_eq!(out.body, Some(line), "whole line must pass through");
    }

    #[test]
    fn a_body_group_narrows_what_the_next_decoder_sees() {
        let d = dec([r"^(?P<action>[A-Z ]+):\s*(?P<body>.*)$"].as_slice());
        let out = d.decode("INBOUND TCP: SRC=1.2.3.4").unwrap();
        assert_eq!(out.fields.get_str("action"), Some("INBOUND TCP"));
        assert_eq!(out.body, Some("SRC=1.2.3.4"));
        // `body` is routing, not data: it must not also become a field.
        assert!(out.fields.get("body").is_none());
    }

    #[test]
    fn parses_a_real_snort_alert() {
        // Straight from the honeynet SotM34 capture.
        let d = dec([concat!(
            r"^\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<name>.+?)\s+",
            r"\[Classification:\s*(?P<classification>[^\]]+)\]\s+",
            r"\[Priority:\s*(?P<priority>\d+)\]:\s+",
            r"\{(?P<proto>\w+)\}\s+(?P<src>[\d.]+)(?::(?P<sport>\d+))?\s+->\s+",
            r"(?P<dst>[\d.]+)(?::(?P<dport>\d+))?"
        )]
        .as_slice());

        let line = "[1:2003:8] MS-SQL Worm propagation attempt \
                    [Classification: Misc Attack] [Priority: 2]: \
                    {UDP} 61.185.28.41:1067 -> 11.11.79.89:1434";
        let f = d.decode(line).unwrap().fields;
        assert_eq!(f.get_str("sid"), Some("2003"));
        assert_eq!(f.get_str("name"), Some("MS-SQL Worm propagation attempt"));
        assert_eq!(f.get_str("classification"), Some("Misc Attack"));
        assert_eq!(f.get_str("priority"), Some("2"));
        assert_eq!(f.get_str("proto"), Some("UDP"));
        assert_eq!(f.get_str("src"), Some("61.185.28.41"));
        assert_eq!(f.get_str("sport"), Some("1067"));
        assert_eq!(f.get_str("dst"), Some("11.11.79.89"));
        assert_eq!(f.get_str("dport"), Some("1434"));
    }

    #[test]
    fn optional_groups_that_do_not_match_are_simply_absent() {
        // ICMP Snort alerts carry no ports, and must not yield empty strings.
        let d = dec([r"(?P<src>[\d.]+)(?::(?P<sport>\d+))?\s+->\s+(?P<dst>[\d.]+)"].as_slice());
        let f = d
            .decode("{ICMP} 70.81.243.88 -> 11.11.79.100")
            .unwrap()
            .fields;
        assert_eq!(f.get_str("src"), Some("70.81.243.88"));
        assert_eq!(f.get_str("dst"), Some("11.11.79.100"));
        assert!(f.get("sport").is_none());
    }

    #[test]
    fn alternatives_are_tried_in_order() {
        let d = dec([r"^A(?P<v>\d+)", r"^B(?P<v>\d+)"].as_slice()).record_which(true);

        let a = d.decode("A42").unwrap().fields;
        assert_eq!(a.get_str("v"), Some("42"));
        assert_eq!(a.get("regex.matched").unwrap().as_int(), Some(0));

        let b = d.decode("B7").unwrap().fields;
        assert_eq!(b.get_str("v"), Some("7"));
        assert_eq!(b.get("regex.matched").unwrap().as_int(), Some(1));
    }

    #[test]
    fn no_match_is_reported_so_the_pack_can_fall_through() {
        let d = dec([r"^NOPE(?P<x>\d+)"].as_slice());
        let err = d.decode("something else").unwrap_err();
        assert!(matches!(err, DecodeError::NotThisFormat { .. }));
    }

    #[test]
    fn unnamed_groups_are_ignored() {
        // Only named captures become fields; positional groups are scaffolding.
        let d = dec([r"^(\w+)\s+(?P<kept>\w+)"].as_slice());
        let f = d.decode("dropped kept").unwrap().fields;
        assert_eq!(f.get_str("kept"), Some("kept"));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn an_invalid_pattern_fails_at_compile_time_not_per_event() {
        assert!(RegexDecoder::new(&["(unclosed".to_string()]).is_err());
    }

    #[test]
    fn empty_input_errors() {
        let d = dec([r"x"].as_slice());
        assert_eq!(d.decode("").unwrap_err(), DecodeError::Empty);
    }
}
