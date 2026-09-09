//! OCSF v1.9.0 event model, canonicalization, and record integrity.
//!
//! Three things live here, in dependency order:
//!
//! * [`jcs`] — RFC 8785 canonicalization. Deterministic bytes for any JSON
//!   document, which everything downstream hashes.
//! * [`event`] — the OCSF event document and a builder that refuses to emit an
//!   event missing a required base attribute.
//! * [`integrity`] — the `record_integrity` profile: per-event hash chaining
//!   and periodically signed checkpoints.
//!
//! The vendored schema in `schema/ocsf` is the reference for every constant and
//! enum in this crate. When bumping it, bump [`event::SCHEMA_VERSION`] and
//! re-check the enums in [`types`] — OCSF adds enum members between minor
//! versions, and a stale mapping produces valid-looking but wrong events.

pub mod event;
pub mod integrity;
pub mod jcs;
pub mod merkle;
pub mod types;

pub use event::{EventBuilder, OcsfEvent, SCHEMA_VERSION};
pub use integrity::{
    predecessor, verify_chain, verify_chain_from, verify_checkpoint, verify_checkpoint_segment,
    verify_event, Attestor, ChainLink, Checkpoint, IntegrityError,
};
pub use types::{
    Attestation, DigitalSignature, Fingerprint, HashAlgorithm, Metadata, Observable,
    ObservableType, PrevEvent, Product, Severity, StatusId,
};

/// Event class UIDs used by perimeter-device sources.
///
/// A `class_uid` is `category_uid * 1000 + class`, so Network Activity is
/// category 4 (Network Activity), class 1.
pub mod class {
    /// Base Event — the class for a record ULPF preserved and structured but
    /// could not identify.
    ///
    /// `schema/ocsf/events/base_event.json` declares `class_uid` with a single
    /// enum member, `0: Base Event`, and every other class inherits from it.
    /// It is the only honest class for an unclaimed record: it asserts that
    /// something happened and carries the evidence, without claiming to know
    /// what kind of thing it was.
    pub const BASE_EVENT: i64 = 0;
    /// Network Activity — the workhorse class for firewall, proxy and IDS logs.
    pub const NETWORK_ACTIVITY: i64 = 4001;
    /// HTTP Activity — proxies and WAFs that expose request detail.
    pub const HTTP_ACTIVITY: i64 = 4002;
    /// DNS Activity.
    pub const DNS_ACTIVITY: i64 = 4003;
    /// SSH Activity.
    pub const SSH_ACTIVITY: i64 = 4007;
    /// Authentication — VPN and admin logins on perimeter devices.
    pub const AUTHENTICATION: i64 = 3002;
    /// Detection Finding — IDS/IPS and WAF alerts.
    pub const DETECTION_FINDING: i64 = 2004;
}

/// `activity_id` values for [`class::NETWORK_ACTIVITY`].
pub mod network_activity {
    pub const UNKNOWN: i64 = 0;
    pub const OPEN: i64 = 1;
    pub const CLOSE: i64 = 2;
    /// Connection terminated by a middle device — how a firewall denial reads.
    pub const RESET: i64 = 3;
    pub const FAIL: i64 = 4;
    pub const REFUSE: i64 = 5;
    /// Periodic traffic report, the common case for firewall session logs.
    pub const TRAFFIC: i64 = 6;
    pub const LISTEN: i64 = 7;
    pub const OTHER: i64 = 99;
}
