//! Built-in wire-format decoders.
//!
//! A decoder turns bytes into a [`FieldMap`] and, where the format has an
//! envelope, hands back the inner body for the next decoder in the chain. That
//! composition is what keeps the decoder count small: perimeter devices do not
//! each invent a format, they wrap one of about six bodies in one of about two
//! envelopes. A Source Pack names the chain — `syslog` then `keyvalue` for
//! FortiGate, `syslog` then `csv` for PAN-OS — rather than shipping a bespoke
//! parser per vendor.
//!
//! Every decoder here is deliberately tolerant. Real devices truncate lines,
//! omit hostnames, emit unpaired quotes and pad absent fields with `-`. A
//! decoder that rejects those loses the event; one that extracts what it can
//! and reports the rest keeps the pipeline lossless. Whatever cannot be
//! interpreted still reaches OCSF `unmapped`, and the bytes are in the vault
//! regardless.

pub mod cef;
pub mod csv;
pub mod json;
pub mod keyvalue;
pub mod leef;
pub mod regex_dec;
pub mod syslog;
pub mod xml;

use ulpf_core::FieldMap;

/// What a decoder produced.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded<'a> {
    /// Fields extracted from this layer.
    pub fields: FieldMap<'a>,
    /// The inner payload, for envelope formats. `None` means this decoder
    /// consumed the whole input.
    pub body: Option<&'a str>,
}

impl<'a> Decoded<'a> {
    pub fn terminal(fields: FieldMap<'a>) -> Self {
        Self { fields, body: None }
    }

    pub fn with_body(fields: FieldMap<'a>, body: &'a str) -> Self {
        Self {
            fields,
            body: Some(body),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("input is empty")]
    Empty,

    #[error("not {format}: {detail}")]
    NotThisFormat {
        format: &'static str,
        detail: String,
    },

    #[error("malformed {format} at byte {offset}: {detail}")]
    Malformed {
        format: &'static str,
        offset: usize,
        detail: String,
    },
}

pub type Result<T> = std::result::Result<T, DecodeError>;

/// A named, stateless decoder for one wire format.
pub trait Decoder: Send + Sync {
    /// Stable identifier, as written in a Source Pack's extraction plan.
    fn name(&self) -> &'static str;

    fn decode<'a>(&self, input: &'a str) -> Result<Decoded<'a>>;
}

/// Look up a built-in decoder by the name a pack uses.
pub fn builtin(name: &str) -> Option<Box<dyn Decoder>> {
    match name {
        "syslog" => Some(Box::new(syslog::SyslogDecoder::new())),
        "syslog_rfc3164" => Some(Box::new(syslog::SyslogDecoder::rfc3164_only())),
        "syslog_rfc5424" => Some(Box::new(syslog::SyslogDecoder::rfc5424_only())),
        "keyvalue" => Some(Box::new(keyvalue::KeyValueDecoder::default())),
        "csv" => Some(Box::new(csv::CsvDecoder::default())),
        "cef" => Some(Box::new(cef::CefDecoder)),
        "json" => Some(Box::new(json::JsonDecoder)),
        "xml" => Some(Box::new(xml::XmlDecoder)),
        "leef" => Some(Box::new(leef::LeefDecoder)),
        // `regex` needs patterns from the pack, so it has no zero-argument
        // form: a pack must construct it via its `patterns` field.
        "regex" => None,
        _ => None,
    }
}

/// Names of every built-in decoder, for `ulpf decoders` and pack validation.
pub const BUILTIN_NAMES: &[&str] = &[
    "syslog",
    "syslog_rfc3164",
    "syslog_rfc5424",
    "keyvalue",
    "csv",
    "cef",
    "json",
    "xml",
    "leef",
    "regex",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_advertised_decoder_resolves() {
        for name in BUILTIN_NAMES {
            // `regex` is parameterised and is built by the pack compiler.
            if *name == "regex" {
                continue;
            }
            let d = builtin(name).unwrap_or_else(|| panic!("`{name}` is advertised but missing"));
            assert_eq!(d.name(), *name);
        }
    }

    #[test]
    fn unknown_decoder_is_none() {
        assert!(builtin("protobuf").is_none());
    }
}
