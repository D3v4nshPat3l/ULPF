//! Diversity sampling for cluster demonstrations.
//!
//! When the generator drafts a pack it sees only a handful of a cluster's
//! records, and which handful decides how good the draft is. ULPF previously
//! took the first *k* — which is the worst available choice, because
//! consecutive lines in a log file are the most similar lines in it. Five
//! adjacent records from a firewall are usually the same session, so the
//! drafter learned one shape and produced a pack that matched only that shape.
//!
//! Two independent results converge on this being the lever that matters:
//!
//! * **LILAC** (FSE'24, [arXiv:2310.01796]) uses hierarchical candidate
//!   sampling to select demonstrations, reporting it as the component that
//!   makes in-context parsing work at scale.
//! * **MicLog** (2026, [arXiv:2601.07005]) replaces it with a weighted DBSCAN
//!   sampler for "diverse, representative subsets", reporting 97.6% parsing
//!   accuracy against 87.3% for the prior state of the art.
//!
//! Both papers spend that diversity on prompting a language model. The insight
//! is not about models: a *deterministic* generator drafting detectors and
//! field mappings needs to see the variation in a cluster for exactly the same
//! reason. So this module implements the idea in the form ULPF can use in an
//! air-gapped deployment with no GPU — greedy max-min selection over token
//! sets, no model, no training, and the same answer every time.
//!
//! # Method
//!
//! Greedy farthest-point traversal. Start from the shortest record — the one
//! carrying fewest optional fields, and so closest to the format's skeleton —
//! then repeatedly add whichever remaining record is *least* similar to
//! everything already chosen. Similarity is Jaccard overlap of token sets,
//! which is cheap, order-insensitive, and needs no tuning constant.
//!
//! Ties break on the record's index, so the selection is stable across runs.
//! That matters: a drafted pack's fixtures end up in a file a human reviews and
//! a CI job scores, and a set that reshuffled between runs would make the
//! score move for no reason.

use std::collections::BTreeSet;

/// Token set of one record, for overlap comparison.
fn tokens(line: &str) -> BTreeSet<&str> {
    line.split(|c: char| c.is_whitespace() || matches!(c, '|' | ',' | ';' | '=' | ':'))
        .filter(|t| !t.is_empty())
        .collect()
}

/// Jaccard similarity of two token sets: shared over combined.
fn similarity(a: &BTreeSet<&str>, b: &BTreeSet<&str>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let shared = a.intersection(b).count() as f64;
    let combined = a.union(b).count() as f64;
    if combined == 0.0 {
        0.0
    } else {
        shared / combined
    }
}

/// Choose up to `k` records covering as much of the cluster's variation as
/// possible, returning their indices in selection order.
///
/// Returns indices rather than records so a caller holding richer structs —
/// dead-letter entries with locators and receipt times — can select without
/// cloning them first.
pub fn diverse_indices(records: &[String], k: usize) -> Vec<usize> {
    if records.is_empty() || k == 0 {
        return Vec::new();
    }
    if records.len() <= k {
        return (0..records.len()).collect();
    }

    let sets: Vec<BTreeSet<&str>> = records.iter().map(|r| tokens(r)).collect();

    // Seed with the shortest record. A log line is at its most skeletal when
    // its optional fields are absent, so the shortest member of a cluster is
    // the closest thing to the format itself. Starting from an arbitrary
    // record instead makes the whole traversal depend on file order.
    let mut chosen = vec![records
        .iter()
        .enumerate()
        .min_by_key(|(i, r)| (r.len(), *i))
        .map(|(i, _)| i)
        .expect("records is non-empty")];

    while chosen.len() < k {
        // The next pick is whichever record is least similar to its nearest
        // already-chosen neighbour: farthest-point traversal.
        let mut best: Option<(usize, f64)> = None;
        for (i, set) in sets.iter().enumerate() {
            if chosen.contains(&i) {
                continue;
            }
            let nearest = chosen
                .iter()
                .map(|&c| similarity(set, &sets[c]))
                .fold(0.0f64, f64::max);
            // Strictly greater, so an equal score keeps the lower index and
            // the selection stays stable between runs.
            if best.is_none_or(|(_, score)| nearest < score) {
                best = Some((i, nearest));
            }
        }
        match best {
            Some((i, _)) => chosen.push(i),
            None => break,
        }
    }
    chosen
}

/// [`diverse_indices`], returning the records themselves.
pub fn diverse_samples(records: &[String], k: usize) -> Vec<String> {
    diverse_indices(records, k)
        .into_iter()
        .map(|i| records[i].clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cluster where the first records are near-identical and the variation
    /// sits later in the file. This is the ordinary shape of a log: sessions
    /// arrive in runs.
    fn cluster() -> Vec<String> {
        let mut v: Vec<String> = (0..20)
            .map(|i| format!("fw accept src=10.0.0.{i} dst=8.8.8.8 proto=tcp"))
            .collect();
        v.push("fw deny src=10.0.0.99 dst=1.1.1.1 proto=udp reason=policy".into());
        v.push("fw drop src=192.168.5.5 dst=9.9.9.9 proto=icmp ttl=1".into());
        v
    }

    #[test]
    fn selection_reaches_the_variation_that_take_n_would_miss() {
        let records = cluster();
        let picked = diverse_samples(&records, 3);
        // Taking the first three yields three `accept` lines and nothing else.
        assert!(
            picked.iter().any(|r| r.contains("deny")),
            "diverse selection missed the deny shape: {picked:?}"
        );
        assert!(
            picked.iter().any(|r| r.contains("drop")),
            "diverse selection missed the drop shape: {picked:?}"
        );
    }

    #[test]
    fn first_n_really_does_miss_it() {
        // Guards the premise: if adjacent records ever stopped being similar,
        // this module would be solving a problem that no longer exists.
        let records = cluster();
        let naive: Vec<&String> = records.iter().take(3).collect();
        assert!(naive.iter().all(|r| r.contains("accept")));
    }

    #[test]
    fn selection_is_stable_across_runs() {
        // Fixtures land in a reviewed file and a scored CI job; a set that
        // reshuffled would move the score for no reason.
        let records = cluster();
        let first = diverse_indices(&records, 5);
        for _ in 0..5 {
            assert_eq!(diverse_indices(&records, 5), first);
        }
    }

    #[test]
    fn asking_for_more_than_exists_returns_everything_once() {
        let records = vec!["a b c".to_string(), "d e f".to_string()];
        assert_eq!(diverse_samples(&records, 10), records);
    }

    #[test]
    fn handles_empty_and_degenerate_input() {
        assert!(diverse_samples(&[], 5).is_empty());
        assert!(diverse_samples(&["x".to_string()], 0).is_empty());
        let blanks = vec![String::new(), String::new(), String::new()];
        assert_eq!(diverse_samples(&blanks, 2).len(), 2);
    }

    #[test]
    fn identical_records_do_not_loop_or_duplicate() {
        let same: Vec<String> = std::iter::repeat_n("same line here".to_string(), 10).collect();
        let picked = diverse_indices(&same, 4);
        assert_eq!(picked.len(), 4);
        let unique: BTreeSet<usize> = picked.iter().copied().collect();
        assert_eq!(unique.len(), 4, "an index was selected twice");
    }
}
