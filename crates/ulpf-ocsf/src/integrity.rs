//! Record integrity: per-event hash chaining and signed checkpoints.
//!
//! This module is requirement (d) — traceability between a normalized event and
//! its original — expressed through OCSF v1.9.0's own `record_integrity`
//! profile rather than a scheme of our own invention.
//!
//! # What gets hashed
//!
//! The profile is precise about this, and getting it wrong makes every
//! attestation unverifiable by anyone else. The fingerprint covers the entire
//! event *including* the attestation's `authority_uid`, `chain_uid` and
//! `prev_event`, and *excluding* only the attestation's own `fingerprint` and
//! `signatures`. Because `prev_event` is inside the hashed content, altering
//! event N invalidates event N+1, and every event after it.
//!
//! # Why signatures are not per-event
//!
//! OCSF's `digital_signature` object has no attribute for signature bytes, so
//! there is nowhere standards-compliant to put a per-event signature. That
//! constraint pushes toward the design one would want anyway: an Ed25519
//! signature costs tens of microseconds, which at one signature per event would
//! cap a core in the low tens of thousands of events per second — the same
//! order as our entire throughput target, spent entirely on signing.
//!
//! Instead the chain is signed at checkpoints. Every event carries a
//! fingerprint and a backward link, making the chain tamper-*evident* on its
//! own; a [`Checkpoint`] then signs the chain head every N events, making it
//! tamper-*proof* back to the last checkpoint. Verification cost is identical,
//! the guarantee is the same, and signing drops by three orders of magnitude.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::event::OcsfEvent;
use crate::jcs;
use crate::types::{Attestation, Fingerprint, HashAlgorithm, PrevEvent};

#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    #[error("event has no metadata.uid; attestation requires a stable event identifier")]
    MissingEventUid,

    #[error("event carries no attestation_list")]
    NoAttestation,

    #[error("attestation carries no fingerprint")]
    NoFingerprint,

    #[error("fingerprint mismatch: event content has been altered")]
    FingerprintMismatch { expected: String, actual: String },

    #[error("chain broken at event `{uid}`: {detail}")]
    ChainBroken { uid: String, detail: String },

    #[error("checkpoint signature is not valid for the supplied key")]
    BadSignature,

    #[error("checkpoint does not describe the verified chain: {0}")]
    CheckpointMismatch(String),

    #[error("unsupported fingerprint algorithm_id {0}")]
    UnsupportedAlgorithm(u8),

    #[error(transparent)]
    Canonicalization(#[from] jcs::JcsError),

    #[error(transparent)]
    Event(#[from] crate::event::EventError),
}

pub type Result<T> = std::result::Result<T, IntegrityError>;

/// The tail of a chain: what the next event must point back to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLink {
    pub uid: String,
    pub type_uid: Option<i64>,
    pub fingerprint: Fingerprint,
}

/// A signed statement that a chain reached a particular head.
///
/// Emitted periodically and stored alongside the events. Verifying a chain
/// means walking the links and confirming the head matches a checkpoint whose
/// signature validates — so a tamperer must forge a signature, not just
/// recompute hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub chain_uid: String,
    pub authority_uid: String,
    /// Number of events attested in this chain up to and including the head.
    pub sequence: u64,
    /// Identifier and type of the head event, needed to resume safely.
    pub head_uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_type_uid: Option<i64>,
    /// Fingerprint of the head event.
    pub head: Fingerprint,
    /// Merkle tree head over every event fingerprint in this chain, hex.
    ///
    /// Signed alongside the chain head so an inclusion proof has something
    /// authenticated to verify against. Without this the tree would only prove
    /// internal consistency: anyone able to rebuild it could also forge a root
    /// to match whatever they wanted to claim.
    pub merkle_root: String,
    /// Number of leaves the root covers. A proof carries its own tree size, and
    /// it has to equal this one.
    pub tree_size: u64,
    /// Nanoseconds since the Unix epoch, on the attesting host's clock.
    pub created_time: i64,
    /// Ed25519 signature, hex-encoded, over the signing input.
    pub signature: String,
    /// Hex-encoded Ed25519 public key, so a checkpoint is self-describing.
    pub public_key: String,
}

impl Checkpoint {
    /// The exact bytes a signature covers.
    ///
    /// Built by canonicalizing the checkpoint's own fields with the signature
    /// omitted, so the input is unambiguous and reproducible by a third party
    /// holding nothing but this struct's JSON.
    ///
    /// Taking `&self` rather than the fields one by one keeps signing and
    /// verification reading from the same place: adding a field to the struct
    /// and forgetting to add it here would silently leave it unsigned.
    pub fn signing_input(&self) -> std::result::Result<Vec<u8>, jcs::JcsError> {
        let doc = serde_json::json!({
            "chain_uid": self.chain_uid,
            "authority_uid": self.authority_uid,
            "sequence": self.sequence,
            "head_uid": self.head_uid,
            "head_type_uid": self.head_type_uid,
            "head": self.head,
            "merkle_root": self.merkle_root,
            "tree_size": self.tree_size,
            "created_time": self.created_time,
        });
        jcs::canonicalize_bytes(&doc)
    }

    /// Verify the signature against the key embedded in the checkpoint.
    pub fn verify_self_signed(&self) -> Result<()> {
        let key_bytes: [u8; 32] = hex::decode(&self.public_key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(IntegrityError::BadSignature)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| IntegrityError::BadSignature)?;
        self.verify_with(&key)
    }

    /// Verify against a key supplied out of band, which is what a real
    /// deployment does — trusting the key inside the checkpoint proves only
    /// internal consistency.
    pub fn verify_with(&self, key: &VerifyingKey) -> Result<()> {
        let input = self.signing_input()?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(IntegrityError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        key.verify(&input, &sig)
            .map_err(|_| IntegrityError::BadSignature)
    }
}

/// Stamps events into a tamper-evident chain.
pub struct Attestor {
    authority_uid: String,
    chain_uid: String,
    hash: HashAlgorithm,
    signing_key: Option<SigningKey>,
    prev: Option<ChainLink>,
    sequence: u64,
    merkle: crate::merkle::MerkleLog,
}

impl Attestor {
    pub fn new(authority_uid: impl Into<String>, chain_uid: impl Into<String>) -> Self {
        Self {
            authority_uid: authority_uid.into(),
            chain_uid: chain_uid.into(),
            hash: HashAlgorithm::default(),
            signing_key: None,
            prev: None,
            sequence: 0,
            merkle: crate::merkle::MerkleLog::new(HashAlgorithm::default()),
        }
    }

    pub fn with_hash(mut self, hash: HashAlgorithm) -> Self {
        self.hash = hash;
        // The tree hashes with the same algorithm as the fingerprints it
        // covers; mixing the two would make a proof unverifiable by anyone who
        // only knows which algorithm the events declare.
        self.merkle = crate::merkle::MerkleLog::from_leaves(hash, self.merkle.leaves().to_vec());
        self
    }

    /// Restore the Merkle log after a restart, so the tree spans the whole
    /// chain rather than restarting at the first event of this run.
    pub fn resume_merkle(mut self, leaves: Vec<[u8; 32]>) -> Self {
        self.merkle = crate::merkle::MerkleLog::from_leaves(self.hash, leaves);
        self
    }

    pub fn merkle_root(&self) -> String {
        self.merkle.root_hex()
    }

    pub fn merkle_size(&self) -> u64 {
        self.merkle.len()
    }

    /// The leaf hashes, for callers that persist the tree across restarts.
    pub fn merkle_leaves(&self) -> &[[u8; 32]] {
        self.merkle.leaves()
    }

    /// Sibling path proving the event at `index` is in the tree.
    pub fn inclusion_proof(&self, index: u64) -> Option<crate::merkle::InclusionProof> {
        self.merkle.inclusion_proof(index)
    }

    pub fn with_signing_key(mut self, key: SigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Resume an existing chain after a restart.
    ///
    /// Without this the chain would silently fork on every process start, and
    /// a forensic gap at exactly the moment most worth explaining.
    pub fn resume_from(mut self, link: ChainLink, sequence: u64) -> Self {
        self.prev = Some(link);
        self.sequence = sequence;
        self
    }

    pub fn chain_uid(&self) -> &str {
        &self.chain_uid
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The current chain head, or `None` before the first event.
    pub fn head(&self) -> Option<&ChainLink> {
        self.prev.as_ref()
    }

    /// Attach an attestation to `event` and advance the chain.
    pub fn attest(&mut self, event: &mut OcsfEvent) -> Result<Fingerprint> {
        let uid = event
            .uid()
            .ok_or(IntegrityError::MissingEventUid)?
            .to_string();
        let type_uid = event.type_uid();

        // Stage one: the attestation without its fingerprint. Everything here
        // is inside the hashed content.
        let attestation = Attestation {
            uid: None,
            authority_uid: Some(self.authority_uid.clone()),
            chain_uid: Some(self.chain_uid.clone()),
            prev_event: self.prev.as_ref().map(|p| PrevEvent {
                uid: p.uid.clone(),
                type_uid: p.type_uid,
                fingerprint: Some(p.fingerprint.clone()),
            }),
            fingerprint: None,
            signatures: Vec::new(),
        };
        set_attestation(event, &attestation)?;
        declare_profile(event);

        // Stage two: hash the event as it now stands.
        let canonical = event.canonical_bytes()?;
        let fingerprint = Fingerprint::over_event(self.hash, &canonical);

        // Stage three: write the fingerprint back. It is excluded from its own
        // input, so this does not invalidate what we just computed.
        let attested = Attestation {
            fingerprint: Some(fingerprint.clone()),
            ..attestation
        };
        set_attestation(event, &attested)?;

        // The leaf is the fingerprint, not a second canonicalization of the
        // whole event: the fingerprint is already computed here, so the tree
        // costs nothing extra per event. A third party verifies in two steps
        // that each mean something on their own — recompute the fingerprint
        // from the event to prove the content is unaltered, then verify that
        // fingerprint's inclusion to prove it was actually logged.
        self.merkle.append(fingerprint.value.as_bytes());

        self.prev = Some(ChainLink {
            uid,
            type_uid,
            fingerprint: fingerprint.clone(),
        });
        self.sequence += 1;
        Ok(fingerprint)
    }

    /// Sign the current chain head.
    ///
    /// Returns `None` when no events have been attested yet, or when the
    /// attestor holds no signing key.
    pub fn checkpoint(&self, created_time: i64) -> Result<Option<Checkpoint>> {
        let (Some(key), Some(head)) = (&self.signing_key, &self.prev) else {
            return Ok(None);
        };
        // Build the checkpoint first with an empty signature, then sign what it
        // actually says. Assembling the signing input separately invited the
        // two to disagree.
        let mut checkpoint = Checkpoint {
            chain_uid: self.chain_uid.clone(),
            authority_uid: self.authority_uid.clone(),
            sequence: self.sequence,
            head_uid: head.uid.clone(),
            head_type_uid: head.type_uid,
            head: head.fingerprint.clone(),
            merkle_root: self.merkle.root_hex(),
            tree_size: self.merkle.len(),
            created_time,
            signature: String::new(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
        };
        let input = checkpoint.signing_input()?;
        checkpoint.signature = hex::encode(key.sign(&input).to_bytes());
        Ok(Some(checkpoint))
    }
}

fn set_attestation(event: &mut OcsfEvent, attestation: &Attestation) -> Result<()> {
    let value = serde_json::to_value(attestation).expect("Attestation serializes infallibly");
    event
        .as_map_mut()
        .insert("attestation_list".to_string(), Value::Array(vec![value]));
    Ok(())
}

/// Announce the profile in `metadata.profiles`, as OCSF expects of any event
/// using profile attributes.
fn declare_profile(event: &mut OcsfEvent) {
    let Some(metadata) = event
        .as_map_mut()
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    let profiles = metadata
        .entry("profiles".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(list) = profiles {
        let already = list.iter().any(|v| v.as_str() == Some("record_integrity"));
        if !already {
            list.push(Value::String("record_integrity".to_string()));
        }
    }
}

/// Recompute an event's fingerprint and compare it with the one it carries.
///
/// This is the whole tamper check: strip the fingerprint, canonicalize what
/// remains, hash it, and see whether the result matches.
pub fn verify_event(event: &OcsfEvent) -> Result<Fingerprint> {
    let attestation = read_attestation(event)?;
    let claimed = attestation
        .fingerprint
        .clone()
        .ok_or(IntegrityError::NoFingerprint)?;

    let alg = match claimed.algorithm_id {
        3 => HashAlgorithm::Sha256,
        99 if claimed.algorithm.as_deref() == Some("BLAKE3") => HashAlgorithm::Blake3,
        other => return Err(IntegrityError::UnsupportedAlgorithm(other)),
    };

    let mut stripped = event.clone();
    let bare = Attestation {
        fingerprint: None,
        signatures: Vec::new(),
        ..attestation
    };
    set_attestation(&mut stripped, &bare)?;

    let canonical = stripped.canonical_bytes()?;
    let actual = Fingerprint::over_event(alg, &canonical);

    if actual.value != claimed.value {
        return Err(IntegrityError::FingerprintMismatch {
            expected: claimed.value,
            actual: actual.value,
        });
    }
    Ok(actual)
}

/// Verify a contiguous run of events: each one's own fingerprint, and each
/// link back to its predecessor.
///
/// `events` must be in chain order. Returns the head link on success.
pub fn verify_chain(events: &[OcsfEvent]) -> Result<Option<ChainLink>> {
    verify_chain_from(events, None)
}

/// Verify a contiguous chain segment, optionally anchored to the immediately
/// preceding event. The anchor is what lets bounded consoles and restarted
/// collectors verify their retained window without pretending it is genesis.
pub fn verify_chain_from(
    events: &[OcsfEvent],
    anchor: Option<&ChainLink>,
) -> Result<Option<ChainLink>> {
    let mut expected_prev = anchor.cloned();
    let mut expected_chain_uid: Option<String> = None;
    let mut expected_authority_uid: Option<String> = None;

    for event in events {
        let uid = event.uid().unwrap_or("<no-uid>").to_string();
        let fingerprint = verify_event(event)?;
        let attestation = read_attestation(event)?;

        let chain_uid =
            attestation
                .chain_uid
                .clone()
                .ok_or_else(|| IntegrityError::ChainBroken {
                    uid: uid.clone(),
                    detail: "attestation has no chain_uid".into(),
                })?;
        let authority_uid =
            attestation
                .authority_uid
                .clone()
                .ok_or_else(|| IntegrityError::ChainBroken {
                    uid: uid.clone(),
                    detail: "attestation has no authority_uid".into(),
                })?;
        if let Some(expected) = &expected_chain_uid {
            if &chain_uid != expected {
                return Err(IntegrityError::ChainBroken {
                    uid: uid.clone(),
                    detail: format!("chain_uid changed from `{expected}` to `{chain_uid}`"),
                });
            }
        } else {
            expected_chain_uid = Some(chain_uid);
        }
        if let Some(expected) = &expected_authority_uid {
            if &authority_uid != expected {
                return Err(IntegrityError::ChainBroken {
                    uid: uid.clone(),
                    detail: format!("authority_uid changed from `{expected}` to `{authority_uid}`"),
                });
            }
        } else {
            expected_authority_uid = Some(authority_uid);
        }

        match (&expected_prev, &attestation.prev_event) {
            (None, None) => {} // genesis event
            (Some(expected), Some(actual)) => {
                if actual.uid != expected.uid {
                    return Err(IntegrityError::ChainBroken {
                        uid,
                        detail: format!(
                            "prev_event.uid is `{}`, expected `{}`",
                            actual.uid, expected.uid
                        ),
                    });
                }
                let actual_fp =
                    actual
                        .fingerprint
                        .as_ref()
                        .ok_or_else(|| IntegrityError::ChainBroken {
                            uid: uid.clone(),
                            detail: "prev_event carries no fingerprint".to_string(),
                        })?;
                if actual_fp.value != expected.fingerprint.value {
                    return Err(IntegrityError::ChainBroken {
                        uid,
                        detail: "prev_event.fingerprint does not match the previous event"
                            .to_string(),
                    });
                }
                if actual.type_uid != expected.type_uid {
                    return Err(IntegrityError::ChainBroken {
                        uid,
                        detail: "prev_event.type_uid does not match the previous event".into(),
                    });
                }
            }
            (Some(_), None) => {
                return Err(IntegrityError::ChainBroken {
                    uid,
                    detail: "event has no prev_event, but is not the first in the chain"
                        .to_string(),
                })
            }
            (None, Some(_)) => {
                return Err(IntegrityError::ChainBroken {
                    uid,
                    detail: "first event unexpectedly references a predecessor".to_string(),
                })
            }
        }

        expected_prev = Some(ChainLink {
            uid: event.uid().unwrap_or_default().to_string(),
            type_uid: event.type_uid(),
            fingerprint,
        });
    }

    Ok(expected_prev)
}

/// Verify a complete chain and bind it to a signed checkpoint.
pub fn verify_checkpoint(events: &[OcsfEvent], checkpoint: &Checkpoint) -> Result<ChainLink> {
    checkpoint.verify_self_signed()?;
    let head = verify_chain(events)?
        .ok_or_else(|| IntegrityError::CheckpointMismatch("the event stream is empty".into()))?;
    if checkpoint.sequence != events.len() as u64 {
        return Err(IntegrityError::CheckpointMismatch(format!(
            "checkpoint sequence is {}, stream contains {} events",
            checkpoint.sequence,
            events.len()
        )));
    }
    if checkpoint.head_uid != head.uid
        || checkpoint.head_type_uid != head.type_uid
        || checkpoint.head != head.fingerprint
    {
        return Err(IntegrityError::CheckpointMismatch(
            "checkpoint head does not match the verified final event".into(),
        ));
    }
    Ok(head)
}

/// Verify an output or retained segment and bind its final event to a signed
/// checkpoint. A segment may begin after genesis when a collector resumed or
/// a bounded console evicted older rows.
pub fn verify_checkpoint_segment(
    events: &[OcsfEvent],
    checkpoint: &Checkpoint,
) -> Result<ChainLink> {
    checkpoint.verify_self_signed()?;
    let anchor = events.first().map(predecessor).transpose()?.flatten();
    let head = verify_chain_from(events, anchor.as_ref())?
        .ok_or_else(|| IntegrityError::CheckpointMismatch("the event stream is empty".into()))?;
    if checkpoint.sequence < events.len() as u64 {
        return Err(IntegrityError::CheckpointMismatch(format!(
            "checkpoint sequence {} is smaller than the {}-event segment",
            checkpoint.sequence,
            events.len()
        )));
    }
    if checkpoint.head_uid != head.uid
        || checkpoint.head_type_uid != head.type_uid
        || checkpoint.head != head.fingerprint
    {
        return Err(IntegrityError::CheckpointMismatch(
            "checkpoint head does not match the verified final event".into(),
        ));
    }
    Ok(head)
}

/// Return the chain link an event declares as its predecessor.
pub fn predecessor(event: &OcsfEvent) -> Result<Option<ChainLink>> {
    let Some(prev) = read_attestation(event)?.prev_event else {
        return Ok(None);
    };
    let fingerprint = prev
        .fingerprint
        .ok_or_else(|| IntegrityError::ChainBroken {
            uid: event.uid().unwrap_or("<no-uid>").to_string(),
            detail: "prev_event carries no fingerprint".into(),
        })?;
    Ok(Some(ChainLink {
        uid: prev.uid,
        type_uid: prev.type_uid,
        fingerprint,
    }))
}

fn read_attestation(event: &OcsfEvent) -> Result<Attestation> {
    let list = event
        .as_map()
        .get("attestation_list")
        .and_then(Value::as_array)
        .ok_or(IntegrityError::NoAttestation)?;
    let first = list.first().ok_or(IntegrityError::NoAttestation)?;
    serde_json::from_value(first.clone()).map_err(|_| IntegrityError::NoAttestation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventBuilder, SCHEMA_VERSION};
    use crate::types::{Metadata, Product, Severity};
    use serde_json::json;

    fn event(uid: &str, srcip: &str) -> OcsfEvent {
        let mut metadata = Metadata::new(SCHEMA_VERSION, Product::new("Fortinet", "FortiGate"));
        metadata.uid = Some(uid.to_string());
        EventBuilder::new()
            .class(4001)
            .activity(6)
            .time(1_756_636_800_000_000_000)
            .severity(Severity::Informational)
            .metadata(metadata)
            .set("src_endpoint.ip", json!(srcip))
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn an_event_proves_inclusion_against_the_signed_checkpoint() {
        // The property the whole feature exists for: hand someone one event and
        // a short proof, and they can confirm it was logged — without seeing
        // any other event in the chain.
        use crate::merkle::verify_inclusion;
        use rand::rngs::OsRng;

        let key = SigningKey::generate(&mut OsRng);
        let public = key.verifying_key();
        let mut attestor = Attestor::new("ulpf-test", "chain-a").with_signing_key(key);

        let mut fingerprints = Vec::new();
        for i in 0..50 {
            let mut ev = event(&format!("uid-{i}"), &format!("10.0.0.{i}"));
            fingerprints.push(attestor.attest(&mut ev).unwrap());
        }

        let checkpoint = attestor
            .checkpoint(1_756_636_800_000_000_000)
            .unwrap()
            .unwrap();
        // The root has to be signed, or a tamperer could simply publish a root
        // that matches whatever they wanted to claim.
        checkpoint.verify_with(&public).unwrap();
        assert_eq!(checkpoint.tree_size, 50);

        // Every event proves inclusion against that signed root.
        for (i, fp) in fingerprints.iter().enumerate() {
            let proof = attestor.inclusion_proof(i as u64).expect("proof exists");
            assert_eq!(proof.tree_size, checkpoint.tree_size);
            assert!(
                verify_inclusion(
                    HashAlgorithm::default(),
                    fp.value.as_bytes(),
                    &proof,
                    &checkpoint.merkle_root,
                ),
                "event {i} failed to prove inclusion"
            );
        }
    }

    #[test]
    fn a_fingerprint_that_was_never_attested_has_no_valid_proof() {
        use crate::merkle::verify_inclusion;
        use rand::rngs::OsRng;

        let key = SigningKey::generate(&mut OsRng);
        let mut attestor = Attestor::new("ulpf-test", "chain-a").with_signing_key(key);
        for i in 0..16 {
            let mut ev = event(&format!("uid-{i}"), &format!("10.0.0.{i}"));
            attestor.attest(&mut ev).unwrap();
        }
        let checkpoint = attestor.checkpoint(1).unwrap().unwrap();
        let proof = attestor.inclusion_proof(3).unwrap();

        // A fingerprint the log never saw cannot borrow another event's proof.
        assert!(!verify_inclusion(
            HashAlgorithm::default(),
            b"0000000000000000000000000000000000000000000000000000000000000000",
            &proof,
            &checkpoint.merkle_root,
        ));
    }

    #[test]
    fn altering_the_signed_root_breaks_the_checkpoint_signature() {
        use rand::rngs::OsRng;

        let key = SigningKey::generate(&mut OsRng);
        let public = key.verifying_key();
        let mut attestor = Attestor::new("ulpf-test", "chain-a").with_signing_key(key);
        let mut ev = event("uid-0", "10.0.0.1");
        attestor.attest(&mut ev).unwrap();

        let mut checkpoint = attestor.checkpoint(1).unwrap().unwrap();
        checkpoint.verify_with(&public).unwrap();

        // Swapping in a root for a different set of events must not verify:
        // the root is inside the signed input, not beside it.
        checkpoint.merkle_root = "aa".repeat(32);
        assert!(checkpoint.verify_with(&public).is_err());
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn attested_event_verifies() {
        let mut a = Attestor::new("ulpf-node-1", "chain-1");
        let mut ev = event("e1", "10.0.0.1");
        a.attest(&mut ev).unwrap();
        assert!(verify_event(&ev).is_ok());
    }

    #[test]
    fn attestation_declares_the_profile() {
        let mut a = Attestor::new("ulpf-node-1", "chain-1");
        let mut ev = event("e1", "10.0.0.1");
        a.attest(&mut ev).unwrap();
        let profiles = ev
            .get_path("metadata.profiles")
            .unwrap()
            .as_array()
            .unwrap();
        assert!(profiles.iter().any(|v| v == "record_integrity"));
    }

    #[test]
    fn genesis_event_has_no_prev_event() {
        let mut a = Attestor::new("n", "c");
        let mut ev = event("e1", "10.0.0.1");
        a.attest(&mut ev).unwrap();
        let att = read_attestation(&ev).unwrap();
        assert!(att.prev_event.is_none());
        assert_eq!(att.chain_uid.as_deref(), Some("c"));
        assert_eq!(att.authority_uid.as_deref(), Some("n"));
    }

    #[test]
    fn subsequent_events_link_backwards() {
        let mut a = Attestor::new("n", "c");
        let mut e1 = event("e1", "10.0.0.1");
        let fp1 = a.attest(&mut e1).unwrap();
        let mut e2 = event("e2", "10.0.0.2");
        a.attest(&mut e2).unwrap();

        let att2 = read_attestation(&e2).unwrap();
        let prev = att2.prev_event.unwrap();
        assert_eq!(prev.uid, "e1");
        assert_eq!(prev.fingerprint.unwrap().value, fp1.value);
    }

    #[test]
    fn tampering_with_a_field_is_detected() {
        let mut a = Attestor::new("n", "c");
        let mut ev = event("e1", "10.0.0.1");
        a.attest(&mut ev).unwrap();

        // Flip the source IP, exactly what an intruder covering tracks would do.
        ev.set_path("src_endpoint.ip", json!("10.0.0.99")).unwrap();

        match verify_event(&ev) {
            Err(IntegrityError::FingerprintMismatch { .. }) => {}
            other => panic!("tampering went undetected: {other:?}"),
        }
    }

    #[test]
    fn tampering_with_raw_data_is_detected() {
        let mut a = Attestor::new("n", "c");
        let mut ev = event("e1", "10.0.0.1");
        ev.as_map_mut()
            .insert("raw_data".into(), json!("original line"));
        a.attest(&mut ev).unwrap();

        ev.as_map_mut()
            .insert("raw_data".into(), json!("doctored line"));
        assert!(matches!(
            verify_event(&ev),
            Err(IntegrityError::FingerprintMismatch { .. })
        ));
    }

    #[test]
    fn a_valid_chain_verifies_end_to_end() {
        let mut a = Attestor::new("n", "c");
        let mut events = Vec::new();
        for i in 0..5 {
            let mut ev = event(&format!("e{i}"), &format!("10.0.0.{i}"));
            a.attest(&mut ev).unwrap();
            events.push(ev);
        }
        let head = verify_chain(&events).unwrap().unwrap();
        assert_eq!(head.uid, "e4");
        assert_eq!(a.sequence(), 5);
    }

    #[test]
    fn deleting_a_middle_event_breaks_the_chain() {
        // The forensically interesting attack: not altering an event, but
        // removing one and hoping the rest still reads as continuous.
        let mut a = Attestor::new("n", "c");
        let mut events = Vec::new();
        for i in 0..5 {
            let mut ev = event(&format!("e{i}"), &format!("10.0.0.{i}"));
            a.attest(&mut ev).unwrap();
            events.push(ev);
        }
        events.remove(2);

        match verify_chain(&events) {
            Err(IntegrityError::ChainBroken { uid, .. }) => assert_eq!(uid, "e3"),
            other => panic!("deletion went undetected: {other:?}"),
        }
    }

    #[test]
    fn reordering_events_breaks_the_chain() {
        let mut a = Attestor::new("n", "c");
        let mut events = Vec::new();
        for i in 0..4 {
            let mut ev = event(&format!("e{i}"), &format!("10.0.0.{i}"));
            a.attest(&mut ev).unwrap();
            events.push(ev);
        }
        events.swap(1, 2);
        assert!(matches!(
            verify_chain(&events),
            Err(IntegrityError::ChainBroken { .. })
        ));
    }

    #[test]
    fn checkpoint_signs_and_verifies() {
        let mut a = Attestor::new("n", "c").with_signing_key(key());
        let mut ev = event("e1", "10.0.0.1");
        a.attest(&mut ev).unwrap();

        let cp = a.checkpoint(1_756_636_800_000_000_000).unwrap().unwrap();
        assert_eq!(cp.sequence, 1);
        cp.verify_self_signed().unwrap();
        cp.verify_with(&key().verifying_key()).unwrap();
    }

    #[test]
    fn checkpoint_rejects_a_forged_head() {
        let mut a = Attestor::new("n", "c").with_signing_key(key());
        let mut ev = event("e1", "10.0.0.1");
        a.attest(&mut ev).unwrap();
        let mut cp = a.checkpoint(1).unwrap().unwrap();

        cp.head.value = "0".repeat(64);
        assert!(matches!(
            cp.verify_self_signed(),
            Err(IntegrityError::BadSignature)
        ));
    }

    #[test]
    fn checkpoint_rejects_a_wrong_key() {
        let mut a = Attestor::new("n", "c").with_signing_key(key());
        let mut ev = event("e1", "10.0.0.1");
        a.attest(&mut ev).unwrap();
        let cp = a.checkpoint(1).unwrap().unwrap();

        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(matches!(
            cp.verify_with(&other.verifying_key()),
            Err(IntegrityError::BadSignature)
        ));
    }

    #[test]
    fn no_key_means_no_checkpoint_rather_than_a_fake_one() {
        let mut a = Attestor::new("n", "c");
        let mut ev = event("e1", "10.0.0.1");
        a.attest(&mut ev).unwrap();
        assert!(a.checkpoint(1).unwrap().is_none());
    }

    #[test]
    fn chain_resumes_across_a_restart() {
        let mut a = Attestor::new("n", "c");
        let mut e1 = event("e1", "10.0.0.1");
        a.attest(&mut e1).unwrap();
        let head = a.head().unwrap().clone();

        // Process restarts; a fresh attestor picks up where the old one stopped.
        let mut b = Attestor::new("n", "c").resume_from(head, a.sequence());
        let mut e2 = event("e2", "10.0.0.2");
        b.attest(&mut e2).unwrap();

        assert_eq!(b.sequence(), 2);
        verify_chain(&[e1, e2]).unwrap();
    }

    #[test]
    fn blake3_attestation_round_trips() {
        let mut a = Attestor::new("n", "c").with_hash(HashAlgorithm::Blake3);
        let mut ev = event("e1", "10.0.0.1");
        a.attest(&mut ev).unwrap();

        let att = read_attestation(&ev).unwrap();
        let fp = att.fingerprint.unwrap();
        assert_eq!(fp.algorithm_id, 99);
        assert_eq!(fp.algorithm.as_deref(), Some("BLAKE3"));
        verify_event(&ev).unwrap();
    }

    #[test]
    fn unattested_event_reports_missing_attestation() {
        let ev = event("e1", "10.0.0.1");
        assert!(matches!(
            verify_event(&ev),
            Err(IntegrityError::NoAttestation)
        ));
    }
}
