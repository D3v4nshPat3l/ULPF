//! Core types shared across the ULPF pipeline.
//!
//! The pipeline moves an event through four representations:
//!
//! 1. [`RawEvent`]   — the exact bytes received, plus a receipt [`Envelope`].
//! 2. [`RawRef`]     — a durable pointer into the vault, once the bytes are stored.
//! 3. [`FieldMap`]   — flat named fields produced by a decoder chain.
//! 4. OCSF event     — the normalized form (see the `ulpf-ocsf` crate).
//!
//! Requirement (a) of PS 26156 is satisfied by never discarding step 1, and
//! requirement (d) by carrying the [`RawRef`] from step 2 through to step 4.

pub mod error;
pub mod field;

pub use error::{Error, Result};
pub use field::{FieldMap, Value};

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// How an event reached us. Recorded before any interpretation is attempted,
/// so it stays trustworthy even when parsing fails.
///
/// Only transports the collector actually accepts appear here. `SyslogTcp`,
/// `SyslogTls` and `Kafka` were listed once but nothing ever constructed them:
/// there is no TCP listener, no TLS listener and no Kafka consumer, so the
/// variants advertised capabilities the binary did not have. They belong back
/// here when the listeners exist, and not before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    SyslogUdp,
    File,
    Http,
    Stdin,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::SyslogUdp => "syslog-udp",
            Transport::File => "file",
            Transport::Http => "http",
            Transport::Stdin => "stdin",
        }
    }

    /// Whether the transport preserves message boundaries on its own.
    ///
    /// Datagram transports do; stream transports need framing, which is where
    /// truncation and splicing bugs normally hide.
    pub fn is_datagram(&self) -> bool {
        matches!(self, Transport::SyslogUdp)
    }
}

/// Receipt metadata captured at the moment bytes arrive.
///
/// `received_at` is our own clock, not anything parsed out of the payload.
/// Device clocks are routinely wrong or absent, so the receipt time is the
/// only timestamp we can attest to; the event's own time is mapped separately
/// into OCSF `time`, and this one lands in `metadata.logged_time`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Nanoseconds since the Unix epoch, on the receiving host's clock.
    pub received_at: i64,
    /// Peer that sent the event, when the transport exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<IpAddr>,
    /// Transport the event arrived on.
    pub transport: Transport,
    /// Identifier of the receiver instance, for multi-listener deployments.
    pub receiver_id: String,
    /// Source path or connection label, when meaningful (file tail, topic).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

impl Envelope {
    pub fn new(transport: Transport, receiver_id: impl Into<String>) -> Self {
        Self {
            received_at: now_nanos(),
            peer: None,
            transport,
            receiver_id: receiver_id.into(),
            origin: None,
        }
    }

    pub fn with_peer(mut self, peer: IpAddr) -> Self {
        self.peer = Some(peer);
        self
    }

    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }
}

/// Current wall-clock time in nanoseconds since the Unix epoch.
pub fn now_nanos() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64
}

/// An event as received: exact bytes, plus how they got here.
///
/// The bytes are owned rather than borrowed because the receiver's read buffer
/// is reused. Decoders borrow *from this* rather than copying again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvent {
    pub bytes: Vec<u8>,
    pub envelope: Envelope,
}

impl RawEvent {
    pub fn new(bytes: Vec<u8>, envelope: Envelope) -> Self {
        Self { bytes, envelope }
    }

    /// The payload as UTF-8, if it is valid UTF-8.
    ///
    /// Returns `None` rather than replacing invalid sequences: a decoder that
    /// wants lossy text must ask for it explicitly, so binary formats are never
    /// silently corrupted into "text that almost parses".
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }

    /// The payload as UTF-8 with invalid sequences replaced.
    pub fn as_str_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// A durable pointer to the exact bytes of an event in the raw vault.
///
/// This is what makes requirement (d) an O(1) lookup rather than a search:
/// a normalized event carries the segment, byte offset and length of its own
/// original, so retrieval is one seek and one read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RawRef {
    /// Monotonically increasing segment number within a vault.
    pub segment: u64,
    /// Byte offset of the record header within the *uncompressed* frame stream.
    pub offset: u64,
    /// Length in bytes of the original payload.
    pub len: u32,
}

impl RawRef {
    pub fn new(segment: u64, offset: u64, len: u32) -> Self {
        Self {
            segment,
            offset,
            len,
        }
    }

    /// Compact textual form, safe to embed in an OCSF string field.
    ///
    /// Fixed-width hex keeps these lexicographically sortable, which makes
    /// range scans over the index cheap.
    pub fn to_locator(&self) -> String {
        format!(
            "ulpf:raw:{:016x}:{:016x}:{:08x}",
            self.segment, self.offset, self.len
        )
    }

    /// Parse a locator produced by [`RawRef::to_locator`].
    pub fn from_locator(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix("ulpf:raw:")
            .ok_or_else(|| Error::BadLocator(s.to_string()))?;
        let mut parts = rest.split(':');
        let mut next = |what: &'static str| -> Result<u64> {
            let p = parts.next().ok_or(Error::LocatorField(what))?;
            u64::from_str_radix(p, 16).map_err(|_| Error::LocatorField(what))
        };
        let segment = next("segment")?;
        let offset = next("offset")?;
        let len = next("len")?;
        if parts.next().is_some() {
            return Err(Error::BadLocator(s.to_string()));
        }
        Ok(Self {
            segment,
            offset,
            len: u32::try_from(len).map_err(|_| Error::LocatorField("len"))?,
        })
    }
}

impl std::fmt::Display for RawRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_locator())
    }
}

/// Outcome of trying to interpret one raw event.
///
/// `Unparsed` is a routing decision, never a discard: the bytes are already in
/// the vault, and the event still becomes a minimal OCSF record carrying its
/// own raw text. The `reason` is what feeds the dead-letter clustering queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// A pack claimed the event and extraction succeeded.
    Parsed { pack_id: String },
    /// No pack matched.
    Unidentified,
    /// A pack matched but its extraction plan failed.
    ExtractFailed { pack_id: String, reason: String },
    /// Extraction succeeded but the result did not satisfy the OCSF schema.
    NormalizeFailed { pack_id: String, reason: String },
}

impl Disposition {
    pub fn is_parsed(&self) -> bool {
        matches!(self, Disposition::Parsed { .. })
    }

    pub fn pack_id(&self) -> Option<&str> {
        match self {
            Disposition::Parsed { pack_id }
            | Disposition::ExtractFailed { pack_id, .. }
            | Disposition::NormalizeFailed { pack_id, .. } => Some(pack_id),
            Disposition::Unidentified => None,
        }
    }

    /// Short stable label, used as a metrics dimension.
    pub fn label(&self) -> &'static str {
        match self {
            Disposition::Parsed { .. } => "parsed",
            Disposition::Unidentified => "unidentified",
            Disposition::ExtractFailed { .. } => "extract_failed",
            Disposition::NormalizeFailed { .. } => "normalize_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_round_trips() {
        let r = RawRef::new(7, 123_456, 512);
        let s = r.to_locator();
        assert_eq!(s, "ulpf:raw:0000000000000007:000000000001e240:00000200");
        assert_eq!(RawRef::from_locator(&s).unwrap(), r);
    }

    #[test]
    fn locator_sorts_by_position() {
        // Fixed-width hex must keep locators ordered the same way the bytes are.
        let a = RawRef::new(1, 9, 1).to_locator();
        let b = RawRef::new(1, 10, 1).to_locator();
        let c = RawRef::new(2, 0, 1).to_locator();
        assert!(a < b, "{a} should sort before {b}");
        assert!(b < c, "{b} should sort before {c}");
    }

    #[test]
    fn locator_rejects_junk() {
        assert!(RawRef::from_locator("nope").is_err());
        assert!(RawRef::from_locator("ulpf:raw:1:2").is_err());
        assert!(RawRef::from_locator("ulpf:raw:1:2:3:4").is_err());
        assert!(RawRef::from_locator("ulpf:raw:zz:2:3").is_err());
    }

    #[test]
    fn raw_event_rejects_invalid_utf8_but_offers_lossy() {
        let ev = RawEvent::new(
            vec![0xff, 0xfe, b'h', b'i'],
            Envelope::new(Transport::File, "r1"),
        );
        assert!(ev.as_str().is_none());
        assert!(ev.as_str_lossy().ends_with("hi"));
    }

    #[test]
    fn disposition_reports_pack() {
        let d = Disposition::Parsed {
            pack_id: "fortinet".into(),
        };
        assert!(d.is_parsed());
        assert_eq!(d.pack_id(), Some("fortinet"));
        assert_eq!(Disposition::Unidentified.pack_id(), None);
    }
}
