//! Produce and check inclusion proofs for a single event.
//!
//! The chain proves a whole stream is intact, but only by replaying it. These
//! two commands prove one record instead, in `ceil(log2 n)` hashes, against a
//! signed Merkle root.
//!
//! The point is what the verifier does *not* need. `verify-proof` reads the
//! proof, the signed checkpoint and a trusted public key — no vault, no chain,
//! no other event. So an extract from a log that cannot itself be shared can
//! still be shown to be genuine, and nothing about the rest of the log leaks
//! with it.

use std::path::Path;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use ulpf_ocsf::merkle::{verify_inclusion, InclusionProof, MerkleLog};
use ulpf_ocsf::{Checkpoint, HashAlgorithm, OcsfEvent};

use crate::integrity_state;

/// A self-contained proof bundle.
///
/// Carries the chain it belongs to and the root it should reproduce so a
/// reader can see what is being claimed, but `verify-proof` deliberately takes
/// the root it checks against from the signed checkpoint rather than from
/// here — a root quoted by the thing being verified proves nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    pub chain_uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_uid: Option<String>,
    /// The record hashed into the leaf: this event's attestation fingerprint.
    pub leaf_record: String,
    pub leaf_index: u64,
    pub tree_size: u64,
    /// Sibling hashes, leaf upward.
    pub path: Vec<String>,
    /// What the path should reproduce. Informational.
    pub claimed_root: String,
    pub hash_algorithm: String,
    /// The signed checkpoint this proof was made against.
    ///
    /// Carried inside the bundle because the collector overwrites its
    /// checkpoint file every few seconds, and a proof is worthless once the
    /// checkpoint it names is gone. Embedding it costs under a kilobyte and
    /// makes the bundle genuinely self-contained: a verifier needs this file
    /// and a trusted public key, nothing else.
    ///
    /// It is not trusted on its own. The signature is checked against a key
    /// supplied out of band, exactly as it would be if read from disk.
    pub checkpoint: Checkpoint,
}

impl ProofBundle {
    fn inclusion(&self) -> InclusionProof {
        InclusionProof {
            leaf_index: self.leaf_index,
            tree_size: self.tree_size,
            path: self.path.clone(),
        }
    }
}

fn algorithm_from_name(name: &str) -> anyhow::Result<HashAlgorithm> {
    match name.to_ascii_lowercase().as_str() {
        "sha256" | "sha-256" => Ok(HashAlgorithm::Sha256),
        "blake3" => Ok(HashAlgorithm::Blake3),
        other => bail!("unknown hash algorithm in proof: {other}"),
    }
}

fn algorithm_name(hash: HashAlgorithm) -> &'static str {
    match hash {
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Blake3 => "blake3",
    }
}

/// Read one OCSF event from a JSON file.
fn read_event(path: &Path) -> anyhow::Result<OcsfEvent> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading event from {}", path.display()))?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(text.trim())
        .with_context(|| format!("{} is not a single JSON object", path.display()))?;
    Ok(OcsfEvent::from_map(map))
}

/// Where a chain's two state files live.
pub struct ChainFiles {
    pub checkpoint: std::path::PathBuf,
    pub leaves: std::path::PathBuf,
}

pub fn chain_files(integrity_dir: &Path, chain: &str) -> ChainFiles {
    let stem = integrity_state::safe_name(chain);
    ChainFiles {
        checkpoint: integrity_dir.join(format!("{stem}.checkpoint.json")),
        leaves: integrity_dir.join(format!("{stem}.merkle-leaves.bin")),
    }
}

/// Build a proof that `fingerprint` is in the tree the checkpoint signed.
///
/// The leaf index is found by hashing rather than stored on the event: a leaf
/// is `H(0x00 || fingerprint)`, so the fingerprint alone identifies its
/// position. That keeps a proof addressable by something the event already
/// carries, with no extra field to keep in step with the tree.
///
/// Pure so the CLI and the console share one implementation; a second copy is
/// how the two would come to disagree about what a valid proof is.
pub fn build_bundle(
    hash: HashAlgorithm,
    checkpoint: &Checkpoint,
    leaves: Vec<[u8; 32]>,
    fingerprint: &str,
    event_uid: Option<String>,
) -> anyhow::Result<ProofBundle> {
    let log = MerkleLog::from_leaves(hash, leaves);
    if log.root_hex() != checkpoint.merkle_root {
        bail!(
            "the leaf file does not reproduce the signed root; refusing to issue a proof from it"
        );
    }

    let wanted = log.leaf_hash(fingerprint.as_bytes());
    let index = log
        .leaves()
        .iter()
        .position(|leaf| leaf == &wanted)
        .with_context(|| {
            // Only leaves the last checkpoint committed to are loaded, so an
            // event received seconds ago is legitimately absent. Reporting that
            // as "not in this chain" reads as an integrity failure when nothing
            // is wrong.
            format!(
                "fingerprint {fingerprint} is not among the {} leaves the last signed checkpoint of chain `{}` commits to. If this event arrived recently, wait for the next checkpoint; otherwise it was never in this log",
                checkpoint.tree_size, checkpoint.chain_uid
            )
        })? as u64;

    let proof = log
        .inclusion_proof(index)
        .context("the leaf index is inside the tree but produced no path")?;

    Ok(ProofBundle {
        chain_uid: checkpoint.chain_uid.clone(),
        event_uid,
        leaf_record: fingerprint.to_string(),
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_size,
        path: proof.path,
        claimed_root: checkpoint.merkle_root.clone(),
        hash_algorithm: algorithm_name(hash).to_string(),
        checkpoint: checkpoint.clone(),
    })
}

/// What a successful check established, so callers can render it themselves.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyOutcome {
    pub chain_uid: String,
    pub event_uid: Option<String>,
    pub leaf_index: u64,
    pub tree_size: u64,
    pub path_len: usize,
    pub signed_root: String,
    /// How far the checkpoint signature was actually trusted.
    pub key_source: String,
    pub trusted_key: bool,
}

/// Check a bundle against a signed checkpoint.
///
/// Every step that can fail is reported separately: "the signature is bad" and
/// "this record was not in the log" are very different findings and a caller
/// should not have to guess which happened.
pub fn check_bundle(
    bundle: &ProofBundle,
    checkpoint: &Checkpoint,
    trusted_key: Option<&ed25519_dalek::VerifyingKey>,
    key_label: Option<&str>,
) -> anyhow::Result<VerifyOutcome> {
    let hash = algorithm_from_name(&bundle.hash_algorithm)?;

    // 1. The checkpoint has to be signed by a key the verifier already trusts.
    //    Falling back to the key inside the checkpoint proves only that the
    //    file agrees with itself, so that is reported as the weaker result.
    let (key_source, trusted) = match trusted_key {
        Some(key) => {
            checkpoint
                .verify_with(key)
                .context("the checkpoint is not signed by the supplied public key")?;
            (
                format!(
                    "verified against {}",
                    key_label.unwrap_or("the supplied key")
                ),
                true,
            )
        }
        None => {
            checkpoint
                .verify_self_signed()
                .context("the checkpoint signature does not match its own embedded key")?;
            (
                "self-signed only - supply a trusted public key for a real check".to_string(),
                false,
            )
        }
    };

    // 2. The proof must be about the tree this checkpoint signed. Without this
    //    a proof from a smaller, earlier tree would pass against a root it was
    //    never part of.
    if bundle.tree_size != checkpoint.tree_size {
        bail!(
            "proof is for a tree of {} leaves but the checkpoint signs {}",
            bundle.tree_size,
            checkpoint.tree_size
        );
    }
    if bundle.chain_uid != checkpoint.chain_uid {
        bail!(
            "proof is for chain `{}` but the checkpoint is for `{}`",
            bundle.chain_uid,
            checkpoint.chain_uid
        );
    }

    // 3. The path must rebuild the signed root from this leaf.
    if !verify_inclusion(
        hash,
        bundle.leaf_record.as_bytes(),
        &bundle.inclusion(),
        &checkpoint.merkle_root,
    ) {
        bail!(
            "the proof does not reproduce the signed root: this record is not in the log the checkpoint describes"
        );
    }

    Ok(VerifyOutcome {
        chain_uid: checkpoint.chain_uid.clone(),
        event_uid: bundle.event_uid.clone(),
        leaf_index: bundle.leaf_index,
        tree_size: bundle.tree_size,
        path_len: bundle.path.len(),
        signed_root: checkpoint.merkle_root.clone(),
        key_source,
        trusted_key: trusted,
    })
}

/// Confirm an event is the one a bundle proves.
pub fn event_matches_bundle(event: &OcsfEvent, bundle: &ProofBundle) -> anyhow::Result<()> {
    let fp =
        ulpf_ocsf::verify_event(event).context("the event failed its own fingerprint check")?;
    if fp.value != bundle.leaf_record {
        bail!(
            "the event fingerprints to {} but the proof is for {}",
            fp.value,
            bundle.leaf_record
        );
    }
    Ok(())
}

pub fn cmd_prove(
    integrity_dir: &Path,
    chain: &str,
    event_path: Option<&Path>,
    fingerprint: Option<&str>,
    blake3: bool,
) -> anyhow::Result<()> {
    let hash = if blake3 {
        HashAlgorithm::Blake3
    } else {
        HashAlgorithm::Sha256
    };

    let (target, event_uid) = match (event_path, fingerprint) {
        (Some(path), _) => {
            let event = read_event(path)?;
            let fp = ulpf_ocsf::verify_event(&event).with_context(|| {
                format!(
                    "{} does not carry a valid attestation, so it cannot be proved",
                    path.display()
                )
            })?;
            (fp.value, event.uid().map(str::to_string))
        }
        (None, Some(fp)) => (fp.trim().to_ascii_lowercase(), None),
        (None, None) => bail!("supply either --event or --fingerprint"),
    };

    let files = chain_files(integrity_dir, chain);
    let checkpoint = integrity_state::read_checkpoint(&files.checkpoint)?;
    let leaves = integrity_state::load_leaves(&files.leaves, checkpoint.tree_size as usize)?;
    let bundle = build_bundle(hash, &checkpoint, leaves, &target, event_uid)?;

    println!("{}", serde_json::to_string_pretty(&bundle)?);
    eprintln!(
        "proof for event {} of {}: {} hashes, {} bytes",
        bundle.leaf_index + 1,
        bundle.tree_size,
        bundle.path.len(),
        bundle.path.len() * 32
    );
    Ok(())
}

pub fn cmd_verify_proof(
    proof_path: &Path,
    checkpoint_path: Option<&Path>,
    public_key_path: Option<&Path>,
    event_path: Option<&Path>,
) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(proof_path)
        .with_context(|| format!("reading proof from {}", proof_path.display()))?;
    let bundle: ProofBundle = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a proof bundle", proof_path.display()))?;
    // Prefer a checkpoint the verifier supplies; fall back to the one carried
    // in the bundle. Either way its signature is checked against the trusted
    // key, so the embedded copy is a convenience, not a shortcut.
    let checkpoint: Checkpoint = match checkpoint_path {
        Some(path) => integrity_state::read_checkpoint(path)?,
        None => bundle.checkpoint.clone(),
    };

    let key = match public_key_path {
        Some(path) => Some(integrity_state::read_public_key(path)?),
        None => None,
    };
    let label = public_key_path.map(|p| p.display().to_string());
    let outcome = check_bundle(&bundle, &checkpoint, key.as_ref(), label.as_deref())?;

    let event_line = match event_path {
        Some(path) => {
            let event = read_event(path)?;
            event_matches_bundle(&event, &bundle)
                .with_context(|| format!("checking {}", path.display()))?;
            Some(format!(
                "{} fingerprints to the proved leaf",
                path.display()
            ))
        }
        None => None,
    };

    println!("PROOF VALID");
    println!("  chain:            {}", outcome.chain_uid);
    if let Some(uid) = &outcome.event_uid {
        println!("  event uid:        {uid}");
    }
    println!(
        "  position:         {} of {}",
        outcome.leaf_index + 1,
        outcome.tree_size
    );
    println!("  proof size:       {} hashes", outcome.path_len);
    println!("  signed root:      {}", outcome.signed_root);
    println!("  checkpoint:       {}", outcome.key_source);
    if let Some(line) = event_line {
        println!("  event matches:    {line}");
    }
    println!();
    println!("This record was in the log when the checkpoint was signed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use ulpf_ocsf::{Attestor, EventBuilder, Metadata, Product, Severity};

    /// A chain of `n` attested events, plus its signed checkpoint.
    fn chain(n: usize) -> (Attestor, Checkpoint, Vec<String>) {
        let key = SigningKey::generate(&mut OsRng);
        let mut attestor = Attestor::new("ulpf-test", "unit").with_signing_key(key);
        let mut fingerprints = Vec::new();
        for i in 0..n {
            let mut metadata =
                Metadata::new(ulpf_ocsf::SCHEMA_VERSION, Product::new("Acme", "Firewall"));
            metadata.uid = Some(format!("uid-{i}"));
            let mut event = EventBuilder::new()
                .class(4001)
                .activity(6)
                .time(1_756_636_800_000_000_000)
                .severity(Severity::Informational)
                .metadata(metadata)
                .set("src_endpoint.ip", serde_json::json!(format!("10.0.0.{i}")))
                .unwrap()
                .build()
                .unwrap();
            fingerprints.push(attestor.attest(&mut event).unwrap().value);
        }
        let checkpoint = attestor.checkpoint(1).unwrap().unwrap();
        (attestor, checkpoint, fingerprints)
    }

    fn bundle_for(
        attestor: &Attestor,
        checkpoint: &Checkpoint,
        index: u64,
        fingerprint: &str,
    ) -> ProofBundle {
        let proof = attestor.inclusion_proof(index).expect("proof exists");
        ProofBundle {
            chain_uid: checkpoint.chain_uid.clone(),
            event_uid: None,
            leaf_record: fingerprint.to_string(),
            leaf_index: proof.leaf_index,
            tree_size: proof.tree_size,
            path: proof.path,
            claimed_root: checkpoint.merkle_root.clone(),
            hash_algorithm: "sha256".into(),
            checkpoint: checkpoint.clone(),
        }
    }

    /// The check `cmd_verify_proof` performs, minus the file and key handling.
    fn holds(bundle: &ProofBundle, checkpoint: &Checkpoint) -> bool {
        bundle.tree_size == checkpoint.tree_size
            && bundle.chain_uid == checkpoint.chain_uid
            && verify_inclusion(
                HashAlgorithm::Sha256,
                bundle.leaf_record.as_bytes(),
                &bundle.inclusion(),
                &checkpoint.merkle_root,
            )
    }

    #[test]
    fn every_event_in_the_chain_proves_against_the_signed_root() {
        let (attestor, checkpoint, fps) = chain(40);
        for (i, fp) in fps.iter().enumerate() {
            let bundle = bundle_for(&attestor, &checkpoint, i as u64, fp);
            assert!(holds(&bundle, &checkpoint), "event {i} failed to prove");
        }
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_event() {
        let (attestor, checkpoint, fps) = chain(16);
        let mut bundle = bundle_for(&attestor, &checkpoint, 5, &fps[5]);
        bundle.leaf_record = fps[6].clone();
        assert!(!holds(&bundle, &checkpoint));
    }

    #[test]
    fn a_tampered_path_does_not_verify() {
        let (attestor, checkpoint, fps) = chain(16);
        let mut bundle = bundle_for(&attestor, &checkpoint, 5, &fps[5]);
        bundle.path[0] = "00".repeat(32);
        assert!(!holds(&bundle, &checkpoint));
    }

    #[test]
    fn a_fingerprint_that_was_never_logged_does_not_verify() {
        let (attestor, checkpoint, fps) = chain(16);
        let mut bundle = bundle_for(&attestor, &checkpoint, 5, &fps[5]);
        bundle.leaf_record = "aa".repeat(32);
        assert!(!holds(&bundle, &checkpoint));
    }

    /// A proof made against an earlier, smaller tree must not pass as a proof
    /// against the larger one, even though the leaf really is in both.
    #[test]
    fn a_proof_from_an_earlier_tree_is_refused() {
        let key = SigningKey::generate(&mut OsRng);
        let mut attestor = Attestor::new("ulpf-test", "unit").with_signing_key(key);
        let mut fps = Vec::new();
        for i in 0..8 {
            let mut metadata =
                Metadata::new(ulpf_ocsf::SCHEMA_VERSION, Product::new("Acme", "Firewall"));
            metadata.uid = Some(format!("uid-{i}"));
            let mut event = EventBuilder::new()
                .class(4001)
                .activity(6)
                .time(1)
                .severity(Severity::Informational)
                .metadata(metadata)
                .build()
                .unwrap();
            fps.push(attestor.attest(&mut event).unwrap().value);
        }
        let early = attestor.checkpoint(1).unwrap().unwrap();
        let early_bundle = bundle_for(&attestor, &early, 3, &fps[3]);

        for i in 8..16 {
            let mut metadata =
                Metadata::new(ulpf_ocsf::SCHEMA_VERSION, Product::new("Acme", "Firewall"));
            metadata.uid = Some(format!("uid-{i}"));
            let mut event = EventBuilder::new()
                .class(4001)
                .activity(6)
                .time(1)
                .severity(Severity::Informational)
                .metadata(metadata)
                .build()
                .unwrap();
            attestor.attest(&mut event).unwrap();
        }
        let later = attestor.checkpoint(2).unwrap().unwrap();

        assert!(
            holds(&early_bundle, &early),
            "should hold against its own tree"
        );
        assert!(
            !holds(&early_bundle, &later),
            "a proof for an 8-leaf tree must not pass against a 16-leaf root"
        );
    }

    #[test]
    fn a_proof_from_another_chain_is_refused() {
        let (attestor, checkpoint, fps) = chain(16);
        let mut bundle = bundle_for(&attestor, &checkpoint, 2, &fps[2]);
        bundle.chain_uid = "some-other-chain".into();
        assert!(!holds(&bundle, &checkpoint));
    }

    #[test]
    fn hash_algorithm_names_round_trip() {
        for hash in [HashAlgorithm::Sha256, HashAlgorithm::Blake3] {
            assert_eq!(algorithm_from_name(algorithm_name(hash)).unwrap(), hash);
        }
        assert!(algorithm_from_name("md5").is_err());
    }
}
