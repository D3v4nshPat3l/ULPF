//! Typed OCSF v1.9.0 objects that ULPF constructs directly.
//!
//! Most of an event is assembled dynamically, because a Source Pack maps
//! arbitrary device fields onto arbitrary OCSF paths and static types would
//! fight that. The objects here are the exceptions: the framework builds them
//! itself on every event, so they get real types, real constructors, and
//! enum values checked at compile time rather than at validation time.

use serde::{Deserialize, Serialize};

/// `fingerprint.algorithm_id` — OCSF v1.9.0 dictionary.
///
/// BLAKE3 is deliberately absent from this enum upstream. Using it therefore
/// requires `Other` plus a free-text `algorithm`, which is legal but leaves an
/// external verifier guessing. That trade-off is the whole reason
/// [`HashAlgorithm`] exists rather than a hardcoded choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AlgorithmId {
    Unknown = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha256 = 3,
    Sha512 = 4,
    Other = 99,
}

/// `fingerprint.encoding_id` — how the digest bytes are rendered into `value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EncodingId {
    Unknown = 0,
    Hex = 1,
    Base64 = 2,
    Base64Url = 3,
    Other = 99,
}

/// `fingerprint.serialization_id` — how structured data became bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SerializationId {
    Unknown = 0,
    /// Raw bytes, no canonicalization. Correct for hashing an original log line.
    Flat = 1,
    /// RFC 8785 JSON Canonicalization Scheme. Correct for hashing an event.
    Jcs = 2,
    Jws = 3,
    Cose = 4,
    Dsse = 5,
    Other = 99,
}

/// The hash function used for fingerprints.
///
/// SHA-256 is the default because it is the only fast option OCSF names
/// explicitly, which means any third party can verify our attestations with a
/// stock library and no special knowledge. BLAKE3 is offered for throughput,
/// at the cost of `algorithm_id: Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Blake3,
}

impl HashAlgorithm {
    pub fn digest(&self, bytes: &[u8]) -> String {
        match self {
            HashAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(bytes);
                hex::encode(h.finalize())
            }
            HashAlgorithm::Blake3 => hex::encode(blake3::hash(bytes).as_bytes()),
        }
    }

    pub fn algorithm_id(&self) -> AlgorithmId {
        match self {
            HashAlgorithm::Sha256 => AlgorithmId::Sha256,
            HashAlgorithm::Blake3 => AlgorithmId::Other,
        }
    }

    /// Free-text algorithm name. Only emitted when `algorithm_id` is `Other`,
    /// per the OCSF convention for unmapped enum values.
    pub fn algorithm_name(&self) -> Option<&'static str> {
        match self {
            HashAlgorithm::Sha256 => None,
            HashAlgorithm::Blake3 => Some("BLAKE3"),
        }
    }
}

/// OCSF `fingerprint` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub algorithm_id: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    pub encoding_id: u8,
    pub serialization_id: u8,
    pub value: String,
}

impl Fingerprint {
    /// Fingerprint over an event's JCS canonical form.
    pub fn over_event(alg: HashAlgorithm, canonical: &[u8]) -> Self {
        Self {
            algorithm_id: alg.algorithm_id() as u8,
            algorithm: alg.algorithm_name().map(str::to_string),
            encoding_id: EncodingId::Hex as u8,
            serialization_id: SerializationId::Jcs as u8,
            value: alg.digest(canonical),
        }
    }

    /// Fingerprint over opaque bytes, such as an original log line.
    ///
    /// Uses `serialization_id: Flat` because no canonicalization was applied —
    /// the whole point of the raw vault is that the bytes are untouched.
    pub fn over_raw(alg: HashAlgorithm, raw: &[u8]) -> Self {
        Self {
            algorithm_id: alg.algorithm_id() as u8,
            algorithm: alg.algorithm_name().map(str::to_string),
            encoding_id: EncodingId::Hex as u8,
            serialization_id: SerializationId::Flat as u8,
            value: alg.digest(raw),
        }
    }
}

/// OCSF `prev_event` object — the backward link in a tamper-evident chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrevEvent {
    /// `metadata.uid` of the previous event. Required by the schema.
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_uid: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Fingerprint>,
}

/// `digital_signature.algorithm_id` — OCSF v1.9.0 dictionary.
///
/// The enum covers DSA, RSA and ECDSA plus three platform code-signing
/// schemes. EdDSA is absent, so Ed25519 signatures must declare `Other` and
/// name themselves in `algorithm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignatureAlgorithmId {
    Unknown = 0,
    Dsa = 1,
    Rsa = 2,
    Ecdsa = 3,
    Other = 99,
}

/// OCSF `digital_signature` object.
///
/// Note what this object does *not* have: anywhere to put the signature bytes.
/// It was designed to describe a signature found on a file — algorithm,
/// certificate, validity state — not to transport one. `digest` is a
/// `fingerprint` object naming what was signed, not the signature itself.
///
/// ULPF therefore does not attempt to smuggle signature bytes into an event.
/// Per-event integrity comes from the `fingerprint` and `prev_event` hash
/// chain; the signature that anchors that chain lives in a periodic
/// [`Checkpoint`], which is signed once per batch rather than once per event.
/// See the module docs on `integrity` for why that is also the faster choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigitalSignature {
    pub algorithm_id: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<i64>,
    /// Fingerprint of the content that was signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<Fingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serialization_id: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer_uid: Option<String>,
}

/// OCSF `attestation` object, from the `record_integrity` profile.
///
/// The schema is specific about what gets hashed: the entire event *including*
/// this object's `authority_uid`, `chain_uid` and `prev_event`, but *excluding*
/// its own `fingerprint` and `signatures`. Because `prev_event` sits inside the
/// hashed content, altering any earlier event invalidates every event after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event: Option<PrevEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Fingerprint>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub signatures: Vec<DigitalSignature>,
}

/// OCSF `product` object. Required inside `metadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Product {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature: Option<serde_json::Value>,
}

impl Product {
    pub fn new(vendor: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            vendor_name: Some(vendor.into()),
            version: None,
            feature: None,
        }
    }

    pub fn with_version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }
}

/// OCSF `metadata` object. `product` and `version` are schema-required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// OCSF schema version this event conforms to.
    pub version: String,
    pub product: Product,
    /// Our event identifier. UUIDv7, so it sorts by creation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The device's own identifier for the event, when it supplies one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_event_uid: Option<String>,
    /// The timestamp as the device wrote it, before normalization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_time: Option<String>,
    /// When ULPF received the bytes. Our clock, not the device's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logged_time: Option<i64>,
    /// When ULPF finished normalizing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_provider: Option<String>,
    /// Wire format of the original, e.g. `syslog-rfc3164`, `cef`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_version: Option<String>,
    /// Profiles in play on this event, e.g. `record_integrity`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub profiles: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub labels: Vec<String>,
}

impl Metadata {
    pub fn new(schema_version: impl Into<String>, product: Product) -> Self {
        Self {
            version: schema_version.into(),
            product,
            uid: None,
            original_event_uid: None,
            original_time: None,
            logged_time: None,
            processed_time: None,
            log_name: None,
            log_provider: None,
            log_format: None,
            log_version: None,
            profiles: Vec::new(),
            labels: Vec::new(),
        }
    }
}

/// `observable.type_id` values used by perimeter-device events.
///
/// Populating `observables` is what makes an event searchable by indicator
/// without knowing which field an IP happened to land in — the difference
/// between a schema that is merely valid and one that is useful for hunting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObservableType {
    Hostname = 1,
    IpAddress = 2,
    MacAddress = 3,
    UserName = 4,
    Email = 5,
    Url = 6,
    DomainName = 8,
    Port = 11,
    Fingerprint = 30,
}

/// OCSF `observable` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observable {
    /// Dotted path to the attribute this observable was taken from.
    pub name: String,
    pub type_id: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl Observable {
    pub fn new(name: impl Into<String>, ty: ObservableType, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_id: ty as u8,
            value: Some(value.into()),
        }
    }
}

/// OCSF severity, shared by every event class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum Severity {
    #[default]
    Unknown = 0,
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
    Fatal = 6,
    Other = 99,
}

/// OCSF `status_id`, used to record whether the device allowed or denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum StatusId {
    #[default]
    Unknown = 0,
    Success = 1,
    Failure = 2,
    Other = 99,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_the_standards_friendly_default() {
        let alg = HashAlgorithm::default();
        assert_eq!(alg, HashAlgorithm::Sha256);
        assert_eq!(alg.algorithm_id(), AlgorithmId::Sha256);
        // No free-text name needed, because the enum value is meaningful.
        assert_eq!(alg.algorithm_name(), None);
    }

    #[test]
    fn blake3_declares_itself_as_other() {
        // OCSF has no BLAKE3 enum member, so we must not invent one.
        let alg = HashAlgorithm::Blake3;
        assert_eq!(alg.algorithm_id(), AlgorithmId::Other);
        assert_eq!(alg.algorithm_name(), Some("BLAKE3"));
    }

    #[test]
    fn sha256_digest_matches_known_vector() {
        // Standard "abc" vector, so a reviewer can check this by hand.
        assert_eq!(
            HashAlgorithm::Sha256.digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn event_and_raw_fingerprints_declare_different_serializations() {
        let ev = Fingerprint::over_event(HashAlgorithm::Sha256, b"{}");
        let raw = Fingerprint::over_raw(HashAlgorithm::Sha256, b"{}");
        assert_eq!(ev.serialization_id, SerializationId::Jcs as u8);
        assert_eq!(raw.serialization_id, SerializationId::Flat as u8);
        // Same bytes, same digest — only the declared provenance differs.
        assert_eq!(ev.value, raw.value);
    }

    #[test]
    fn optional_fields_are_omitted_not_nulled() {
        // OCSF validators treat an explicit null as a present-but-invalid
        // value, so absent attributes must disappear from the JSON entirely.
        let m = Metadata::new("1.9.0", Product::new("Fortinet", "FortiGate"));
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("null"), "{json}");
        assert!(!json.contains("uid"));
        assert!(json.contains(r#""version":"1.9.0""#));
    }

    #[test]
    fn attestation_omits_empty_signature_list() {
        let a = Attestation {
            uid: None,
            authority_uid: Some("ulpf-node-1".into()),
            chain_uid: Some("chain-a".into()),
            prev_event: None,
            fingerprint: None,
            signatures: Vec::new(),
        };
        let json = serde_json::to_string(&a).unwrap();
        assert!(!json.contains("signatures"), "{json}");
    }
}
