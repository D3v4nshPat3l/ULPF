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
    /// Roots of the perfect subtrees that tile the leaves, largest first.
    ///
    /// This is the binary decomposition of the leaf count: 22 leaves are
    /// covered by subtrees of 16, 4 and 2. Appending a leaf pushes a subtree
    /// of size one and merges equal-sized neighbours, which is the same
    /// carry a binary increment performs — amortised O(1) hashes per append,
    /// never more than log2(n).
    ///
    /// # Why this exists
    ///
    /// [`Self::root`] used to walk every leaf and rebuild the whole tree.
    /// That is O(n) per call, and a checkpoint calls it: `ulpf run`
    /// checkpoints every 8,192 events, so a run cost `(n / 8192) * O(n)`
    /// hashes — quadratic in the number of records.
    ///
    /// Measured on this machine before the change: 22,421 events/sec over a
    /// 40,000-record corpus, and roughly 2,460 events/sec over Blue Coat's
    /// 8,130,590. The pipeline had not slowed down; the tree was being
    /// rebuilt from scratch a thousand times. At the 22.7M-record Zeek
    /// corpus it was hours of Merkle recomputation alone, which made a
    /// framework claiming billions of events per day slower the longer it
    /// ran.
    ///
    /// The fringe folds to the same RFC 6962 root the recursive walk
    /// produced — the tests below check both against known vectors and
    /// against inclusion proofs — it just stops recomputing what has not
    /// changed.
    fringe: Vec<(u64, [u8; 32])>,
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
            fringe: Vec::new(),
        }
    }

    /// Rebuild from previously persisted leaf hashes.
    ///
    /// The fringe is rebuilt in one linear pass here, which is the only
    /// place that cost is paid — once at startup, not once per checkpoint.
    pub fn from_leaves(hash: HashAlgorithm, leaves: Vec<[u8; 32]>) -> Self {
        let mut log = Self {
            hash,
            leaves: Vec::new(),
            fringe: Vec::new(),
        };
        for leaf in leaves {
            log.leaves.push(leaf);
            log.absorb(leaf);
        }
        log
    }

    /// Add one already-hashed leaf to the fringe, merging equal-sized
    /// neighbours.
    fn absorb(&mut self, leaf: [u8; 32]) {
        self.fringe.push((1, leaf));
        while self.fringe.len() >= 2 {
            let (right_size, right) = self.fringe[self.fringe.len() - 1];
            let (left_size, left) = self.fringe[self.fringe.len() - 2];
            // Only perfect subtrees of equal size combine into a larger
            // perfect subtree; unequal neighbours are the tree's right edge
            // and stay separate until `root` folds them.
            if left_size != right_size {
                break;
            }
            let merged = self.node_hash(&left, &right);
            self.fringe.truncate(self.fringe.len() - 2);
            self.fringe.push((left_size + right_size, merged));
        }
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
        self.absorb(leaf);
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
    /// Fold the fringe right to left, which is the same shape the recursive
    /// walk produced: the tree splits at the largest power of two below the
    /// leaf count, so every subtree left of the split is perfect and the
    /// remainder hangs off the right edge.
    pub fn root(&self) -> [u8; 32] {
        let mut subtrees = self.fringe.iter().rev();
        let Some((_, rightmost)) = subtrees.next() else {
            // RFC 6962: the empty tree is the hash of the empty string, so
            // "nothing has been logged" stays a signable statement.
            return self.hash.digest_bytes(&[]);
        };
        let mut acc = *rightmost;
        for (_, left) in subtrees {
            acc = self.node_hash(left, &acc);
        }
        acc
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

    /// Prove the tree as it stood at `first_size` leaves is a prefix of the
    /// tree as it stands now.
    ///
    /// `None` when `first_size` exceeds the log: a tree cannot be a prefix of a
    /// smaller one, and saying so is more useful than an empty path that would
    /// verify as though it meant something.
    pub fn consistency_proof(&self, first_size: u64) -> Option<ConsistencyProof> {
        let n = self.len();
        if first_size > n {
            return None;
        }
        let mut out = Vec::new();
        // A tree is trivially a prefix of itself, and every tree extends the
        // empty one. Both carry no hashes rather than being special cases the
        // caller has to detect.
        if first_size > 0 && first_size < n {
            self.subproof(first_size as usize, &self.leaves, true, &mut out);
        }
        Some(ConsistencyProof {
            first_size,
            second_size: n,
            path: out.iter().map(hex::encode).collect(),
        })
    }

    /// RFC 6962 SUBPROOF.
    ///
    /// `on_path` marks the subtree still containing the old tree's right edge.
    /// Its root is one the verifier can already derive, so it is not sent —
    /// which is what keeps the proof logarithmic rather than linear.
    fn subproof(&self, m: usize, leaves: &[[u8; 32]], on_path: bool, out: &mut Vec<[u8; 32]>) {
        if m == leaves.len() {
            if !on_path {
                out.push(self.root_of(leaves));
            }
            return;
        }
        let k = split_point(leaves.len());
        if m <= k {
            self.subproof(m, &leaves[..k], on_path, out);
            out.push(self.root_of(&leaves[k..]));
        } else {
            self.subproof(m - k, &leaves[k..], false, out);
            out.push(self.root_of(&leaves[..k]));
        }
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

/// A proof that a tree of `first_size` leaves is a prefix of one of
/// `second_size` leaves.
///
/// An inclusion proof is only checkable against the exact root it was issued
/// under, so a log that keeps growing strands every proof it has already handed
/// out: the holder would have to keep the checkpoint from that moment and hope
/// a verifier still trusts a root nobody publishes any more. RFC 6962 answers
/// that with this — `O(log n)` hashes showing the old tree is an unmodified
/// prefix of the new one, which lets an old proof be checked against today's
/// signed root without weakening what it claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub first_size: u64,
    pub second_size: u64,
    /// Node hashes in RFC 6962 SUBPROOF order, hex-encoded.
    pub path: Vec<String>,
}

/// Check that the tree whose head is `first_root_hex` is a prefix of the tree
/// whose head is `second_root_hex`.
///
/// The algorithm is RFC 6962 section 2.1.3. It rebuilds *both* roots from the
/// same path rather than only reaching the new one: a verifier that recomputed
/// just the new root would accept any old root the prover cared to name, which
/// is precisely the substitution this exists to prevent.
pub fn verify_consistency(
    hash: HashAlgorithm,
    first_root_hex: &str,
    second_root_hex: &str,
    proof: &ConsistencyProof,
) -> bool {
    let first = proof.first_size;
    let second = proof.second_size;
    if first > second {
        return false;
    }
    // The same tree: the roots have to agree and there is nothing to send.
    if first == second {
        return proof.path.is_empty() && first_root_hex.eq_ignore_ascii_case(second_root_hex);
    }
    // Every tree extends the empty one, and there is no old root to rebuild.
    if first == 0 {
        return proof.path.is_empty();
    }
    if proof.path.is_empty() {
        return false;
    }

    let Some(path) = proof
        .path
        .iter()
        .map(|h| decode32(h))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };

    let log = MerkleLog::new(hash);
    let mut node = first - 1;
    let mut last = second - 1;

    // Climb out of every right-child position first. Those subtrees lie wholly
    // inside the old tree, so the verifier can already derive them and nothing
    // about them is sent.
    while node & 1 == 1 {
        node >>= 1;
        last >>= 1;
    }

    // If the old tree was perfectly balanced its root *is* the starting node
    // and the verifier already holds it; otherwise the starting node is the
    // first hash in the path.
    let mut idx = 0usize;
    let (mut first_hash, mut second_hash) = if node > 0 {
        idx = 1;
        (path[0], path[0])
    } else {
        let Some(root) = decode32(first_root_hex) else {
            return false;
        };
        (root, root)
    };

    while node > 0 {
        if node & 1 == 1 {
            // A right child: its left sibling stands in both trees.
            let Some(sibling) = path.get(idx) else {
                return false;
            };
            first_hash = log.node_hash(sibling, &first_hash);
            second_hash = log.node_hash(sibling, &second_hash);
            idx += 1;
        } else if node < last {
            // A left child whose right sibling exists only in the newer tree,
            // so it contributes to the new root and not the old one.
            let Some(sibling) = path.get(idx) else {
                return false;
            };
            second_hash = log.node_hash(&second_hash, sibling);
            idx += 1;
        }
        // node == last and even: a left child with no sibling in either tree.
        node >>= 1;
        last >>= 1;
    }

    if hex::encode(first_hash) != first_root_hex.to_ascii_lowercase() {
        return false;
    }

    // Whatever was appended past the old tree's right edge.
    while last > 0 {
        let Some(sibling) = path.get(idx) else {
            return false;
        };
        second_hash = log.node_hash(&second_hash, sibling);
        idx += 1;
        last >>= 1;
    }

    // Hashes left over means this is not the proof for this pair of sizes.
    idx == path.len() && hex::encode(second_hash) == second_root_hex.to_ascii_lowercase()
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
    fn the_incremental_root_matches_a_full_rebuild() {
        // `root` folds a fringe of perfect-subtree roots maintained on
        // append; `root_of` rebuilds the whole tree from the leaves. They are
        // the same RFC 6962 head, and this is what says so at every size
        // where the tree's shape changes -- powers of two and the awkward
        // sizes either side of them.
        for n in 0..=130usize {
            let mut log = MerkleLog::new(HashAlgorithm::Sha256);
            for i in 0..n {
                log.append(format!("record {i}").as_bytes());
            }
            assert_eq!(
                log.root(),
                log.root_of(&log.leaves),
                "incremental and rebuilt roots disagree at {n} leaves"
            );
        }
    }

    #[test]
    fn a_resumed_log_rebuilds_the_same_fringe() {
        // A restart reloads persisted leaf hashes through `from_leaves`. If
        // that rebuilt a different fringe, every proof issued after a restart
        // would verify against a root nobody signed.
        let mut original = MerkleLog::new(HashAlgorithm::Sha256);
        for i in 0..77 {
            original.append(format!("record {i}").as_bytes());
        }
        let resumed = MerkleLog::from_leaves(HashAlgorithm::Sha256, original.leaves().to_vec());
        assert_eq!(original.root(), resumed.root());
        assert_eq!(original.len(), resumed.len());
    }

    #[test]
    fn the_fringe_tiles_the_leaf_count_in_binary() {
        // 22 leaves decompose as 16 + 4 + 2, which is 10110 in binary. If
        // this ever stops holding, `root`'s right-to-left fold is folding
        // something other than the tree's perfect subtrees.
        let mut log = MerkleLog::new(HashAlgorithm::Sha256);
        for i in 0..22 {
            log.append(format!("record {i}").as_bytes());
        }
        let sizes: Vec<u64> = log.fringe.iter().map(|(size, _)| *size).collect();
        assert_eq!(sizes, vec![16, 4, 2]);
        assert_eq!(sizes.iter().sum::<u64>(), log.len());
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

    // ---- consistency proofs -------------------------------------------------

    /// The property that matters: every prefix of every tree verifies, at every
    /// size. Exhaustive up to 17 leaves, which covers both sides of the
    /// power-of-two boundaries where the seeding rule changes.
    #[test]
    fn every_prefix_is_consistent_with_every_later_size() {
        for n in 1..=17usize {
            let new = log_of(n);
            for m in 0..=n {
                let old = log_of(m);
                let proof = new
                    .consistency_proof(m as u64)
                    .expect("a prefix always has a proof");
                assert!(
                    verify_consistency(
                        HashAlgorithm::Sha256,
                        &old.root_hex(),
                        &new.root_hex(),
                        &proof
                    ),
                    "tree of {n} is not consistent with its prefix of {m}"
                );
            }
        }
    }

    #[test]
    fn a_forged_old_root_does_not_verify() {
        let new = log_of(12);
        let proof = new.consistency_proof(7).unwrap();
        // The root of a tree that shares no leaves with this one.
        let mut other = MerkleLog::new(HashAlgorithm::Sha256);
        for i in 0..7 {
            other.append(format!("forged-{i}").as_bytes());
        }
        assert!(!verify_consistency(
            HashAlgorithm::Sha256,
            &other.root_hex(),
            &new.root_hex(),
            &proof
        ));
    }

    #[test]
    fn a_forged_new_root_does_not_verify() {
        let old = log_of(7);
        let new = log_of(12);
        let proof = new.consistency_proof(7).unwrap();
        assert!(!verify_consistency(
            HashAlgorithm::Sha256,
            &old.root_hex(),
            &log_of(13).root_hex(),
            &proof
        ));
    }

    /// The case the whole thing exists to reject: a log that did not merely
    /// grow, but edited a record it had already committed to.
    #[test]
    fn a_rewritten_history_is_not_consistent() {
        let old = log_of(8);
        let mut rewritten = MerkleLog::new(HashAlgorithm::Sha256);
        for i in 0..12 {
            if i == 3 {
                rewritten.append(b"event-3-but-altered");
            } else {
                rewritten.append(format!("event-{i}").as_bytes());
            }
        }
        let proof = rewritten.consistency_proof(8).unwrap();
        assert!(!verify_consistency(
            HashAlgorithm::Sha256,
            &old.root_hex(),
            &rewritten.root_hex(),
            &proof
        ));
    }

    #[test]
    fn the_same_size_needs_no_path_and_the_roots_must_match() {
        let log = log_of(9);
        let proof = log.consistency_proof(9).unwrap();
        assert!(proof.path.is_empty());
        assert!(verify_consistency(
            HashAlgorithm::Sha256,
            &log.root_hex(),
            &log.root_hex(),
            &proof
        ));
        assert!(!verify_consistency(
            HashAlgorithm::Sha256,
            &log_of(8).root_hex(),
            &log.root_hex(),
            &proof
        ));
    }

    #[test]
    fn every_tree_extends_the_empty_one() {
        let log = log_of(6);
        let proof = log.consistency_proof(0).unwrap();
        assert!(proof.path.is_empty());
        assert!(verify_consistency(
            HashAlgorithm::Sha256,
            &MerkleLog::new(HashAlgorithm::Sha256).root_hex(),
            &log.root_hex(),
            &proof
        ));
    }

    #[test]
    fn a_first_size_beyond_the_tree_has_no_proof() {
        assert!(log_of(5).consistency_proof(6).is_none());
    }

    #[test]
    fn a_tampered_or_padded_path_does_not_verify() {
        let old = log_of(7);
        let new = log_of(12);
        let good = new.consistency_proof(7).unwrap();

        let mut tampered = good.clone();
        tampered.path[0] = "00".repeat(32);
        assert!(!verify_consistency(
            HashAlgorithm::Sha256,
            &old.root_hex(),
            &new.root_hex(),
            &tampered
        ));

        // Trailing hashes the algorithm never consumes must be rejected too,
        // otherwise a proof could carry arbitrary unchecked payload.
        let mut padded = good.clone();
        padded.path.push("11".repeat(32));
        assert!(!verify_consistency(
            HashAlgorithm::Sha256,
            &old.root_hex(),
            &new.root_hex(),
            &padded
        ));

        let mut truncated = good.clone();
        truncated.path.pop();
        assert!(!verify_consistency(
            HashAlgorithm::Sha256,
            &old.root_hex(),
            &new.root_hex(),
            &truncated
        ));
    }

    #[test]
    fn consistency_proof_is_logarithmic() {
        let log = log_of(1024);
        let proof = log.consistency_proof(500).unwrap();
        assert!(
            proof.path.len() <= 12,
            "1024 leaves should need ~10 hashes, got {}",
            proof.path.len()
        );
    }

    /// An old inclusion proof, checked against a root signed long after it was
    /// issued. This is the end-to-end property the CLI depends on.
    #[test]
    fn an_old_inclusion_proof_survives_the_log_growing() {
        let old = log_of(5);
        let inclusion = old.inclusion_proof(2).unwrap();
        let new = log_of(40);

        // Against the new root directly it must fail — the tree changed.
        assert!(!verify_inclusion(
            HashAlgorithm::Sha256,
            b"event-2",
            &inclusion,
            &new.root_hex()
        ));

        // With a consistency proof tying the old root to the new one, the old
        // proof still means what it meant.
        let bridge = new.consistency_proof(5).unwrap();
        assert!(verify_consistency(
            HashAlgorithm::Sha256,
            &old.root_hex(),
            &new.root_hex(),
            &bridge
        ));
        assert!(verify_inclusion(
            HashAlgorithm::Sha256,
            b"event-2",
            &inclusion,
            &old.root_hex()
        ));
    }
}
