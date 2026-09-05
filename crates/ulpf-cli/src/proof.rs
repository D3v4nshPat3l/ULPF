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
use ulpf_ocsf::merkle::{
    verify_consistency, verify_inclusion, ConsistencyProof, InclusionProof, MerkleLog,
};
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

/// Build a proof that `--event` (or `--fingerprint`) is in the chain's tree.
///
/// The leaf index is found by hashing rather than stored on the event: a leaf
/// is `H(0x00 || fingerprint)`, so the fingerprint alone identifies its
/// position. That keeps the proof addressable by something the event already
/// carries, with no extra field to keep in step.
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

    let (checkpoint, log) = open_chain(integrity_dir, chain, hash)?;

    let wanted = log.leaf_hash(target.as_bytes());
    let index = log
        .leaves()
        .iter()
        .position(|leaf| leaf == &wanted)
        .with_context(|| {
            // Only leaves the last checkpoint committed to are loaded, so a
            // freshly received event is legitimately absent for a few seconds.
            // Saying "not in this chain" for that case reads as an integrity
            // failure when nothing is wrong.
            format!(
                "fingerprint {target} is not among the {} leaves the last signed checkpoint of chain `{chain}` commits to. If this event arrived recently, wait for the next checkpoint; otherwise it was never in this log",
                checkpoint.tree_size
            )
        })? as u64;

    let proof = log
        .inclusion_proof(index)
        .context("the leaf index is inside the tree but produced no path")?;

    let bundle = ProofBundle {
        chain_uid: checkpoint.chain_uid.clone(),
        event_uid,
        leaf_record: target,
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_size,
        path: proof.path,
        claimed_root: checkpoint.merkle_root.clone(),
        hash_algorithm: algorithm_name(hash).to_string(),
    };

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

/// A proof that the tree an older proof was issued against is a prefix of the
/// tree signed by a later checkpoint.
///
/// Kept in its own file rather than folded into [`ProofBundle`] because the two
/// travel separately: the inclusion proof is handed over once, and a bridge to
/// the current root is fetched whenever it is time to check it again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyBundle {
    pub chain_uid: String,
    pub first_size: u64,
    /// The root the older proof was issued against.
    pub first_root: String,
    pub second_size: u64,
    /// The root the current checkpoint signs.
    pub second_root: String,
    pub path: Vec<String>,
    pub hash_algorithm: String,
}

impl ConsistencyBundle {
    fn consistency(&self) -> ConsistencyProof {
        ConsistencyProof {
            first_size: self.first_size,
            second_size: self.second_size,
            path: self.path.clone(),
        }
    }
}

/// Bridge an older tree size to the one the current checkpoint signs.
///
/// An inclusion proof only ever reproduces the root it was issued under, so a
/// log that keeps growing would otherwise strand every proof it has handed out.
/// This emits the `O(log n)` hashes that show the older tree is an unmodified
/// prefix of today's, which is what lets `verify-proof` accept the old proof
/// against the current signed root.
pub fn cmd_consistency(
    integrity_dir: &Path,
    chain: &str,
    from: u64,
    blake3: bool,
) -> anyhow::Result<()> {
    let hash = if blake3 {
        HashAlgorithm::Blake3
    } else {
        HashAlgorithm::Sha256
    };
    let (checkpoint, log) = open_chain(integrity_dir, chain, hash)?;

    if from > checkpoint.tree_size {
        bail!(
            "cannot bridge from {from} leaves: the last signed checkpoint of chain `{chain}` covers only {}",
            checkpoint.tree_size
        );
    }

    let proof = log
        .consistency_proof(from)
        .context("the tree size is within the log but produced no proof")?;
    let first_root =
        MerkleLog::from_leaves(hash, log.leaves()[..from as usize].to_vec()).root_hex();

    let bundle = ConsistencyBundle {
        chain_uid: checkpoint.chain_uid.clone(),
        first_size: from,
        first_root,
        second_size: proof.second_size,
        second_root: checkpoint.merkle_root.clone(),
        path: proof.path,
        hash_algorithm: algorithm_name(hash).to_string(),
    };

    println!("{}", serde_json::to_string_pretty(&bundle)?);
    eprintln!(
        "bridge from {} leaves to {}: {} hashes, {} bytes",
        bundle.first_size,
        bundle.second_size,
        bundle.path.len(),
        bundle.path.len() * 32
    );
    Ok(())
}

/// Read a chain's signed checkpoint and rebuild its tree from the leaf file.
///
/// The leaf file is data on disk, not an attestation, so it is only trusted
/// once it reproduces the root the checkpoint signs.
fn open_chain(
    integrity_dir: &Path,
    chain: &str,
    hash: HashAlgorithm,
) -> anyhow::Result<(Checkpoint, MerkleLog)> {
    let checkpoint_path = integrity_dir.join(format!(
        "{}.checkpoint.json",
        integrity_state::safe_name(chain)
    ));
    let leaves_path = integrity_dir.join(format!(
        "{}.merkle-leaves.bin",
        integrity_state::safe_name(chain)
    ));
    let checkpoint = integrity_state::read_checkpoint(&checkpoint_path)?;
    let leaves = integrity_state::load_leaves(&leaves_path, checkpoint.tree_size as usize)?;
    let log = MerkleLog::from_leaves(hash, leaves);
    if log.root_hex() != checkpoint.merkle_root {
        bail!(
            "the leaf file does not reproduce the signed root; refusing to issue a proof from it"
        );
    }
    Ok((checkpoint, log))
}

/// Check a proof against a signed checkpoint.
///
/// Reads nothing but the three files it is given. Every step that could fail
/// is reported separately, because "the signature is bad" and "the event was
/// not in this log" are very different findings.
pub fn cmd_verify_proof(
    proof_path: &Path,
    checkpoint_path: &Path,
    public_key_path: Option<&Path>,
    event_path: Option<&Path>,
    consistency_path: Option<&Path>,
) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(proof_path)
        .with_context(|| format!("reading proof from {}", proof_path.display()))?;
    let bundle: ProofBundle = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a proof bundle", proof_path.display()))?;
    let checkpoint: Checkpoint = integrity_state::read_checkpoint(checkpoint_path)?;
    let hash = algorithm_from_name(&bundle.hash_algorithm)?;

    // 1. The checkpoint has to be signed by a key the verifier already trusts.
    //    Falling back to the key inside the checkpoint proves only that the
    //    file is internally consistent, so it is reported as the weaker result
    //    it is.
    let key_source = match public_key_path {
        Some(path) => {
            let key = integrity_state::read_public_key(path)?;
            checkpoint
                .verify_with(&key)
                .context("the checkpoint is not signed by the supplied public key")?;
            format!("verified against {}", path.display())
        }
        None => {
            checkpoint
                .verify_self_signed()
                .context("the checkpoint signature does not match its own embedded key")?;
            "self-signed only - supply --public-key for a real check".to_string()
        }
    };

    // 2. The proof reproduces the root of the tree it was issued against, and
    //    that root has to be one this checkpoint vouches for. When the sizes
    //    match it is the signed root directly. When the log has grown since,
    //    a consistency proof has to bridge the two — without one the old proof
    //    could only be checked against a root nobody publishes any more.
    if bundle.chain_uid != checkpoint.chain_uid {
        bail!(
            "proof is for chain `{}` but the checkpoint is for `{}`",
            bundle.chain_uid,
            checkpoint.chain_uid
        );
    }

    let (root_to_check, bridge_line) = match consistency_path {
        None => {
            if bundle.tree_size != checkpoint.tree_size {
                bail!(
                    "proof is for a tree of {} leaves but the checkpoint signs {}. The log grew \
                     after the proof was issued, so bridge the two:\n  \
                     ulpf consistency --chain {} --from {} > bridge.json\n  \
                     ulpf verify-proof --proof {} --checkpoint {} --consistency bridge.json",
                    bundle.tree_size,
                    checkpoint.tree_size,
                    checkpoint.chain_uid,
                    bundle.tree_size,
                    proof_path.display(),
                    checkpoint_path.display()
                );
            }
            (checkpoint.merkle_root.clone(), None)
        }
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading consistency proof from {}", path.display()))?;
            let bridge: ConsistencyBundle = serde_json::from_str(&text)
                .with_context(|| format!("{} is not a consistency proof", path.display()))?;

            if bridge.chain_uid != checkpoint.chain_uid {
                bail!(
                    "the consistency proof is for chain `{}` but the checkpoint is for `{}`",
                    bridge.chain_uid,
                    checkpoint.chain_uid
                );
            }
            if algorithm_from_name(&bridge.hash_algorithm)? != hash {
                bail!(
                    "the consistency proof hashes with {} but the inclusion proof uses {}",
                    bridge.hash_algorithm,
                    bundle.hash_algorithm
                );
            }
            if bridge.first_size != bundle.tree_size {
                bail!(
                    "the consistency proof starts at {} leaves but the inclusion proof was issued \
                     against a tree of {}",
                    bridge.first_size,
                    bundle.tree_size
                );
            }
            // The far end has to be exactly what this checkpoint signs, or the
            // bridge lands on a root no key ever attested to.
            if bridge.second_size != checkpoint.tree_size
                || !bridge
                    .second_root
                    .eq_ignore_ascii_case(&checkpoint.merkle_root)
            {
                bail!(
                    "the consistency proof ends at {} leaves / root {} but the checkpoint signs \
                     {} / {}",
                    bridge.second_size,
                    bridge.second_root,
                    checkpoint.tree_size,
                    checkpoint.merkle_root
                );
            }
            if !verify_consistency(
                hash,
                &bridge.first_root,
                &checkpoint.merkle_root,
                &bridge.consistency(),
            ) {
                bail!(
                    "the tree of {} leaves is not a prefix of the signed tree of {}: this log did \
                     not simply grow, a record it had already committed to was changed",
                    bridge.first_size,
                    checkpoint.tree_size
                );
            }
            let line = format!(
                "bridged:          {} leaves to {} in {} hashes",
                bridge.first_size,
                bridge.second_size,
                bridge.path.len()
            );
            (bridge.first_root.clone(), Some(line))
        }
    };

    // 3. The path must rebuild that root from this leaf.
    let included = verify_inclusion(
        hash,
        bundle.leaf_record.as_bytes(),
        &bundle.inclusion(),
        &root_to_check,
    );
    if !included {
        bail!(
            "the proof does not reproduce the root it claims: this record is not \
             in the log the checkpoint describes"
        );
    }

    // 4. Optionally, that the event supplied is the one the leaf stands for.
    let event_line = match event_path {
        Some(path) => {
            let event = read_event(path)?;
            let fp = ulpf_ocsf::verify_event(&event)
                .with_context(|| format!("{} failed its own fingerprint check", path.display()))?;
            if fp.value != bundle.leaf_record {
                bail!(
                    "the event in {} fingerprints to {} but the proof is for {}",
                    path.display(),
                    fp.value,
                    bundle.leaf_record
                );
            }
            Some(format!(
                "event matches:      {} fingerprints to the proved leaf",
                path.display()
            ))
        }
        None => None,
    };

    println!("PROOF VALID");
    println!("  chain:            {}", checkpoint.chain_uid);
    if let Some(uid) = &bundle.event_uid {
        println!("  event uid:        {uid}");
    }
    println!(
        "  position:         {} of {}",
        bundle.leaf_index + 1,
        bundle.tree_size
    );
    println!("  proof size:       {} hashes", bundle.path.len());
    println!("  signed root:      {}", checkpoint.merkle_root);
    if let Some(line) = bridge_line {
        println!("  {line}");
        println!("  proof root:       {root_to_check}");
    }
    println!("  checkpoint:       {key_source}");
    if let Some(line) = event_line {
        println!("  {line}");
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

    /// The bridged check `cmd_verify_proof` performs when `--consistency` is
    /// supplied: the bridge must land exactly on the signed root, and the
    /// inclusion proof is then checked against the older root it authenticates.
    fn holds_with_bridge(
        bundle: &ProofBundle,
        checkpoint: &Checkpoint,
        bridge: &ConsistencyBundle,
    ) -> bool {
        bridge.chain_uid == checkpoint.chain_uid
            && bundle.chain_uid == checkpoint.chain_uid
            && bridge.first_size == bundle.tree_size
            && bridge.second_size == checkpoint.tree_size
            && bridge
                .second_root
                .eq_ignore_ascii_case(&checkpoint.merkle_root)
            && verify_consistency(
                HashAlgorithm::Sha256,
                &bridge.first_root,
                &checkpoint.merkle_root,
                &bridge.consistency(),
            )
            && verify_inclusion(
                HashAlgorithm::Sha256,
                bundle.leaf_record.as_bytes(),
                &bundle.inclusion(),
                &bridge.first_root,
            )
    }

    fn bridge_for(attestor: &Attestor, checkpoint: &Checkpoint, from: u64) -> ConsistencyBundle {
        let leaves = attestor.merkle_leaves().to_vec();
        let log = MerkleLog::from_leaves(HashAlgorithm::Sha256, leaves);
        let proof = log.consistency_proof(from).unwrap();
        let first_root = MerkleLog::from_leaves(
            HashAlgorithm::Sha256,
            log.leaves()[..from as usize].to_vec(),
        )
        .root_hex();
        ConsistencyBundle {
            chain_uid: checkpoint.chain_uid.clone(),
            first_size: from,
            first_root,
            second_size: proof.second_size,
            second_root: checkpoint.merkle_root.clone(),
            path: proof.path,
            hash_algorithm: "sha256".to_string(),
        }
    }

    /// The complement of `a_proof_from_an_earlier_tree_is_refused`: refusing it
    /// outright would strand every proof the collector has ever handed out, so
    /// a consistency proof has to be able to rescue exactly that case.
    #[test]
    fn a_bridge_lets_an_older_proof_verify_against_a_later_checkpoint() {
        let (mut attestor, early, fps) = chain(5);
        let early_bundle = bundle_for(&attestor, &early, 2, &fps[2]);

        for i in 5..20 {
            let mut metadata =
                Metadata::new(ulpf_ocsf::SCHEMA_VERSION, Product::new("Acme", "Firewall"));
            metadata.uid = Some(format!("later-{i}"));
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
            !holds(&early_bundle, &later),
            "unbridged, an older proof must still be refused"
        );

        let bridge = bridge_for(&attestor, &later, early.tree_size);
        assert!(
            holds_with_bridge(&early_bundle, &later, &bridge),
            "with a bridge, the older proof must verify against the later root"
        );
    }

    /// A bridge that does not actually terminate at the signed root buys
    /// nothing, however well-formed it looks on its own.
    #[test]
    fn a_bridge_to_an_unsigned_root_is_refused() {
        let (mut attestor, early, fps) = chain(5);
        let early_bundle = bundle_for(&attestor, &early, 2, &fps[2]);

        for i in 5..12 {
            let mut metadata =
                Metadata::new(ulpf_ocsf::SCHEMA_VERSION, Product::new("Acme", "Firewall"));
            metadata.uid = Some(format!("mid-{i}"));
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
        let mid = attestor.checkpoint(2).unwrap().unwrap();
        let mut bridge = bridge_for(&attestor, &mid, early.tree_size);

        // Same shape, a root nobody signed.
        bridge.second_root = "ab".repeat(32);
        assert!(!holds_with_bridge(&early_bundle, &mid, &bridge));

        // And a first_root the prover simply asserted.
        let mut forged = bridge_for(&attestor, &mid, early.tree_size);
        forged.first_root = "cd".repeat(32);
        assert!(!holds_with_bridge(&early_bundle, &mid, &forged));
    }
}
