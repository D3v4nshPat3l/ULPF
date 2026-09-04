//! A Merkle log over event fingerprints, and inclusion proofs against it.
//!
//! The per-event hash chain in [`crate::integrity`] answers "has this stream
//! been altered?" — but only by replaying it. Proving one record out of a
//! million means handing over all million, which is impractical and, for a log
//! that is itself sensitive, often not permitted at all.
//!
//! A Merkle tree answers the same question for a single record with
//! `ceil(log2(n))` hashes. For a million events that is twenty hashes, a few
//! hundred bytes, verifiable against one signed root by someone who never sees
//! any other event in the log. That property — proving membership while
//! disclosing nothing else — is what makes an extract from a classified log
//! shareable.
//!
//! The construction follows RFC 6962 (Certificate Transparency), including its
//! domain separation: leaves are hashed with a `0x00` prefix and interior nodes
//! with `0x01`, so no interior node can ever be mistaken for a leaf. That
//! prefix is not decoration — without it, an attacker can present an interior
//! node as though it were a record and produce a proof for data that was never
//! logged.
//!
//! The chain and the tree coexist: the chain gives cheap sequential
//! tamper-evidence at write time, the tree gives cheap selective proof at read
//! time. Neither replaces the other.

use serde::{Deserialize, Serialize};

use crate::types::HashAlgorithm;

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// An append-only Merkle log.
///
/// Holds one 32-byte hash per appended record. Callers that outlive a single
/// run persist the leaf hashes and rebuild; see `ulpf-cli`'s integrity state.
#[derive(Debug, Clone)]
pub struct MerkleLog {
    hash: HashAlgorithm,
    leaves: Vec<[u8; 32]>,
}

/// A proof that one leaf sits at `leaf_index` in a tree of `tree_size` leaves.
///
/// Self-describing on purpose: a verifier needs the index and the size to know
/// which side each sibling belongs on, and carrying them means the proof can
/// travel alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    /// Sibling hashes from the leaf upward, hex-encoded.
    pub path: Vec<String>,
}

impl MerkleLog {
    pub fn new(hash: HashAlgorithm) -> Self {
        Self {
            hash,
            leaves: Vec::new(),
        }
    }

    /// Rebuild from previously persisted leaf hashes.
    pub fn from_leaves(hash: HashAlgorithm, leaves: Vec<[u8; 32]>) -> Self {
        Self { hash, leaves }
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Hash a record into a leaf and append it. Returns the leaf's index.
    pub fn append(&mut self, record: &[u8]) -> u64 {
        let leaf = self.leaf_hash(record);
        self.leaves.push(leaf);
        self.leaves.len() as u64 - 1
    }

    /// `H(0x00 || record)`.
    pub fn leaf_hash(&self, record: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(record.len() + 1);
        buf.push(LEAF_PREFIX);
        buf.extend_from_slice(record);
        self.hash.digest_bytes(&buf)
    }

    /// `H(0x01 || left || right)`.
    fn node_hash(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 65];
        buf[0] = NODE_PREFIX;
        buf[1..33].copy_from_slice(left);
        buf[33..65].copy_from_slice(right);
        self.hash.digest_bytes(&buf)
    }

    /// The Merkle tree head over every leaf appended so far.
    ///
    /// An empty log hashes the empty string, per RFC 6962, so "nothing has been
    /// logged" is still a well-defined, signable statement rather than a
    /// special case the caller has to handle.
    pub fn root(&self) -> [u8; 32] {
        self.root_of(&self.leaves)
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    fn root_of(&self, leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            0 => self.hash.digest_bytes(&[]),
            1 => leaves[0],
            n => {
                let k = split_point(n);
                let left = self.root_of(&leaves[..k]);
                let right = self.root_of(&leaves[k..]);
                self.node_hash(&left, &right)
            }
        }
    }

    /// Sibling path proving `index` is in the tree, leaf upward.
    pub fn inclusion_proof(&self, index: u64) -> Option<InclusionProof> {
        if index >= self.len() {
            return None;
        }
        let mut path = Vec::new();
        self.path_into(&self.leaves, index as usize, &mut path);
        Some(InclusionProof {
            leaf_index: index,
            tree_size: self.len(),
            path: path.iter().map(hex::encode).collect(),
        })
    }

    fn path_into(&self, leaves: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
        if leaves.len() <= 1 {
            return;
        }
        let k = split_point(leaves.len());
        if index < k {
            self.path_into(&leaves[..k], index, out);
            out.push(self.root_of(&leaves[k..]));
        } else {
            self.path_into(&leaves[k..], index - k, out);
            out.push(self.root_of(&leaves[..k]));
        }
    }
}

/// Largest power of two strictly less than `n`, for `n > 1`.
///
/// RFC 6962 splits there rather than in the middle, which keeps every left
/// subtree perfect and makes the tree's shape depend only on its size.
fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Recompute the root from a record and its proof, and compare.
///
/// This is the verification algorithm from RFC 6962 section 2.1.1. It consumes
/// the path leaf-upward, which is the order [`MerkleLog::inclusion_proof`]
/// produces: `fn`/`sn` track the node's index and the last index at the
/// current level, and their low bits say whether the sibling sits left or
/// right. An earlier attempt here descended from the root instead and
/// concatenated siblings the wrong way round for any tree that was not a
/// perfect power of two — the tests below caught it at three leaves.
///
/// Takes the original record rather than a leaf hash so a caller cannot
/// accidentally verify an interior node as though it were a logged event.
pub fn verify_inclusion(
    hash: HashAlgorithm,
    record: &[u8],
    proof: &InclusionProof,
    expected_root_hex: &str,
) -> bool {
    if proof.tree_size == 0 || proof.leaf_index >= proof.tree_size {
        return false;
    }

    let log = MerkleLog::new(hash);
    let mut node = log.leaf_hash(record);
    let mut fnode = proof.leaf_index;
    let mut snode = proof.tree_size - 1;

    for sibling_hex in &proof.path {
        // Ran out of tree before running out of path: the proof is longer than
        // this tree size admits.
        if snode == 0 {
            return false;
        }
        let Some(sibling) = decode32(sibling_hex) else {
            return false;
        };

        if fnode & 1 == 1 || fnode == snode {
            node = log.node_hash(&sibling, &node);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            node = log.node_hash(&node, &sibling);
        }
        fnode >>= 1;
        snode >>= 1;
    }

    // Path exhausted before reaching the root: truncated proof.
    if snode != 0 {
        return false;
    }

    // Constant-time comparison is unnecessary: the expected root is public and
    // the attacker already knows it.
    hex::encode(node) == expected_root_hex.to_ascii_lowercase()
}

fn decode32(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_of(n: usize) -> MerkleLog {
        let mut log = MerkleLog::new(HashAlgorithm::Sha256);
        for i in 0..n {
            log.append(format!("event-{i}").as_bytes());
        }
        log
    }

    #[test]
    fn empty_tree_is_the_hash_of_nothing() {
        // RFC 6962: MTH({}) = HASH(). For SHA-256 that is the well-known digest
        // of the empty string, so an empty log has a defined, checkable head.
        let log = MerkleLog::new(HashAlgorithm::Sha256);
        assert_eq!(
            log.root_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn single_leaf_root_is_the_leaf_hash() {
        let mut log = MerkleLog::new(HashAlgorithm::Sha256);
        log.append(b"only");
        assert_eq!(log.root(), log.leaf_hash(b"only"));
    }

    #[test]
    fn leaf_and_node_hashing_are_domain_separated() {
        // Without the prefixes, H(left||right) of two leaves would be
        // indistinguishable from a leaf whose record happened to be those
        // bytes, which is exactly the second-preimage attack RFC 6962 avoids.
        let log = MerkleLog::new(HashAlgorithm::Sha256);
        let a = log.leaf_hash(b"a");
        let b = log.leaf_hash(b"b");
        let node = log.node_hash(&a, &b);

        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&a);
        concatenated.extend_from_slice(&b);
        assert_ne!(node, log.leaf_hash(&concatenated));
    }

    #[test]
    fn every_leaf_proves_inclusion_at_every_tree_size() {
        for n in 1..=33usize {
            let log = log_of(n);
            let root = log.root_hex();
            for i in 0..n {
                let proof = log.inclusion_proof(i as u64).expect("proof exists");
                assert!(
                    verify_inclusion(
                        HashAlgorithm::Sha256,
                        format!("event-{i}").as_bytes(),
                        &proof,
                        &root,
                    ),
                    "leaf {i} of {n} failed to verify"
                );
            }
        }
    }

    #[test]
    fn proof_is_logarithmic() {
        let log = log_of(1024);
        let proof = log.inclusion_proof(500).unwrap();
        assert_eq!(proof.path.len(), 10);
    }

    #[test]
    fn a_record_that_was_never_logged_does_not_verify() {
        let log = log_of(16);
        let root = log.root_hex();
        let proof = log.inclusion_proof(7).unwrap();
        assert!(!verify_inclusion(
            HashAlgorithm::Sha256,
            b"event-7-tampered",
            &proof,
            &root
        ));
    }

    #[test]
    fn a_proof_for_one_leaf_does_not_verify_another() {
        let log = log_of(16);
        let root = log.root_hex();
        let proof = log.inclusion_proof(7).unwrap();
        assert!(!verify_inclusion(
            HashAlgorithm::Sha256,
            b"event-8",
            &proof,
            &root
        ));
    }

    #[test]
    fn a_tampered_sibling_does_not_verify() {
        let log = log_of(16);
        let root = log.root_hex();
        let mut proof = log.inclusion_proof(7).unwrap();
        proof.path[0] = "00".repeat(32);
        assert!(!verify_inclusion(
            HashAlgorithm::Sha256,
            b"event-7",
            &proof,
            &root
        ));
    }

    #[test]
    fn a_truncated_path_does_not_verify() {
        let log = log_of(16);
        let root = log.root_hex();
        let mut proof = log.inclusion_proof(7).unwrap();
        proof.path.pop();
        assert!(!verify_inclusion(
            HashAlgorithm::Sha256,
            b"event-7",
            &proof,
            &root
        ));
    }

    #[test]
    fn root_changes_when_any_record_changes() {
        let before = log_of(8).root_hex();
        let mut altered = MerkleLog::new(HashAlgorithm::Sha256);
        for i in 0..8 {
            if i == 3 {
                altered.append(b"event-3-altered");
            } else {
                altered.append(format!("event-{i}").as_bytes());
            }
        }
        assert_ne!(before, altered.root_hex());
    }

    #[test]
    fn out_of_range_index_has_no_proof() {
        let log = log_of(4);
        assert!(log.inclusion_proof(4).is_none());
    }

    #[test]
    fn blake3_trees_work_and_differ_from_sha256() {
        let mut a = MerkleLog::new(HashAlgorithm::Blake3);
        let mut b = MerkleLog::new(HashAlgorithm::Sha256);
        for i in 0..8 {
            a.append(format!("event-{i}").as_bytes());
            b.append(format!("event-{i}").as_bytes());
        }
        assert_ne!(a.root_hex(), b.root_hex());

        let proof = a.inclusion_proof(5).unwrap();
        assert!(verify_inclusion(
            HashAlgorithm::Blake3,
            b"event-5",
            &proof,
            &a.root_hex()
        ));
        // A proof from the BLAKE3 tree must not verify under SHA-256.
        assert!(!verify_inclusion(
            HashAlgorithm::Sha256,
            b"event-5",
            &proof,
            &a.root_hex()
        ));
    }
}
