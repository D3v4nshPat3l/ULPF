//! Template clustering for dead-letter records.
//!
//! Groups unparsed log lines into templates so the operator sees "4,812 lines
//! of this shape" rather than 4,812 rows, and can write the one pack that
//! covers the most traffic first.
//!
//! # What this is, and what it is not
//!
//! This is the first level of the Drain algorithm — bucket by token count,
//! then match within the bucket by positional similarity, generalising
//! disagreeing positions to a `<*>` wildcard. It is deliberately *not* the
//! full Drain parse tree: the deeper levels index on leading tokens, which
//! buys speed once a deployment carries thousands of distinct templates, and
//! costs accuracy on the perimeter logs this framework sees, where the leading
//! tokens are a syslog timestamp that differs on every line.
//!
//! An earlier version kept the tree's fields but never used them, scanning
//! every cluster on every line and never enforcing its own cluster cap. Both
//! are fixed here: the length bucket makes the scan proportional to clusters
//! of the *same shape*, and the cap is real, because an unbounded map fed by
//! unparsed traffic is a memory leak with a hostile input source.

use std::collections::HashMap;

/// One template and the records that matched it.
#[derive(Debug, Clone)]
pub struct Cluster {
    pub id: String,
    pub template: Vec<String>,
    pub count: usize,
    pub samples: Vec<String>,
}

/// Maximum sample lines retained per cluster.
///
/// The generator reads at most a handful; the rest are for the operator to
/// eyeball. Keeping every line would make the cluster map grow with traffic.
const SAMPLES_PER_CLUSTER: usize = 30;

pub struct Drain {
    /// Fraction of positions that must agree for a line to join a cluster.
    similarity: f64,
    /// Hard ceiling on distinct templates held in memory.
    max_clusters: usize,
    /// Cluster ids bucketed by token count — the first Drain tree level.
    by_length: HashMap<usize, Vec<String>>,
    clusters: HashMap<String, Cluster>,
    next_id: usize,
    /// Lines seen after the cap was reached, and so not clustered.
    overflow: usize,
}

impl Default for Drain {
    fn default() -> Self {
        Self::new()
    }
}

impl Drain {
    pub fn new() -> Self {
        Self::with_capacity(1000)
    }

    pub fn with_capacity(max_clusters: usize) -> Self {
        Self {
            similarity: 0.4,
            max_clusters: max_clusters.max(1),
            by_length: HashMap::new(),
            clusters: HashMap::new(),
            next_id: 1,
            overflow: 0,
        }
    }

    /// Lines dropped because the cluster cap was reached.
    ///
    /// Surfaced rather than hidden: an operator seeing a rising overflow knows
    /// the unparsed traffic is more varied than the cap allows, which is itself
    /// the signal that a pack is needed.
    pub fn overflow(&self) -> usize {
        self.overflow
    }

    pub fn len(&self) -> usize {
        self.clusters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clusters.is_empty()
    }

    /// Assign one raw line to a template, returning the cluster id.
    ///
    /// Returns `None` once the cap is reached and no existing template
    /// matches, rather than growing without bound.
    pub fn process(&mut self, raw: &str) -> Option<String> {
        let tokens: Vec<String> = raw.split_whitespace().map(str::to_string).collect();
        if tokens.is_empty() {
            return None;
        }
        let bucket = self.by_length.entry(tokens.len()).or_default();

        // Only clusters of the same token count can match, so the scan is over
        // this bucket rather than every template ever seen.
        let mut best: Option<(String, f64)> = None;
        for id in bucket.iter() {
            let Some(cluster) = self.clusters.get(id) else {
                continue;
            };
            let score = similarity(&tokens, &cluster.template);
            if score >= self.similarity && best.as_ref().is_none_or(|(_, b)| score > *b) {
                best = Some((id.clone(), score));
            }
        }

        if let Some((id, _)) = best {
            let cluster = self
                .clusters
                .get_mut(&id)
                .expect("id came from the bucket index");
            cluster.count += 1;
            if cluster.samples.len() < SAMPLES_PER_CLUSTER {
                cluster.samples.push(raw.to_string());
            }
            // Generalise the positions that disagree.
            for (slot, token) in cluster.template.iter_mut().zip(tokens.iter()) {
                if slot != token && slot != "<*>" {
                    *slot = "<*>".to_string();
                }
            }
            return Some(id);
        }

        if self.clusters.len() >= self.max_clusters {
            self.overflow += 1;
            return None;
        }

        let id = format!("C{:04}", self.next_id);
        self.next_id += 1;
        self.by_length
            .entry(tokens.len())
            .or_default()
            .push(id.clone());
        self.clusters.insert(
            id.clone(),
            Cluster {
                id: id.clone(),
                template: tokens,
                count: 1,
                samples: vec![raw.to_string()],
            },
        );
        Some(id)
    }

    /// Templates, most frequent first.
    pub fn ranked_clusters(&self) -> Vec<Cluster> {
        let mut sorted: Vec<Cluster> = self.clusters.values().cloned().collect();
        // Count descending, then id ascending so equal-volume clusters hold a
        // stable order between refreshes of the console.
        sorted.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.id.cmp(&b.id)));
        sorted
    }
}

/// Fraction of positions where the line agrees with the template.
fn similarity(tokens: &[String], template: &[String]) -> f64 {
    if tokens.is_empty() {
        return 0.0;
    }
    let matched = tokens
        .iter()
        .zip(template.iter())
        .filter(|(t, slot)| t == slot || slot.as_str() == "<*>")
        .count();
    matched as f64 / tokens.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_lines_share_one_cluster() {
        let mut d = Drain::new();
        let line = "kernel: INBOUND TCP SRC=1.2.3.4 DPT=445";
        let a = d.process(line).unwrap();
        let b = d.process(line).unwrap();
        assert_eq!(a, b);
        assert_eq!(d.len(), 1);
        assert_eq!(d.ranked_clusters()[0].count, 2);
    }

    #[test]
    fn varying_positions_generalise_to_a_wildcard() {
        let mut d = Drain::new();
        d.process("kernel: INBOUND TCP SRC=1.2.3.4 DPT=445");
        d.process("kernel: INBOUND TCP SRC=5.6.7.8 DPT=445");
        let template = &d.ranked_clusters()[0].template;
        assert_eq!(template[3], "<*>", "the source address varies");
        assert_eq!(template[4], "DPT=445", "the port does not");
    }

    #[test]
    fn different_token_counts_never_share_a_cluster() {
        let mut d = Drain::new();
        d.process("a b c").unwrap();
        d.process("a b c d").unwrap();
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn the_cluster_cap_is_enforced() {
        // The cap existed as a field and was never checked, so unparsed
        // traffic from a varied source grew the map without limit.
        let mut d = Drain::with_capacity(3);
        for i in 0..50 {
            // Distinct token counts, so nothing can merge.
            d.process(&"x ".repeat(i + 1));
        }
        assert_eq!(d.len(), 3, "must not exceed the cap");
        assert!(
            d.overflow() > 0,
            "dropped lines must be counted, not hidden"
        );
    }

    #[test]
    fn ranking_is_stable_for_equal_counts() {
        let mut d = Drain::new();
        d.process("a b c");
        d.process("d e f");
        let first = d.ranked_clusters();
        let second = d.ranked_clusters();
        let ids: Vec<&str> = first.iter().map(|c| c.id.as_str()).collect();
        let again: Vec<&str> = second.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, again);
    }

    #[test]
    fn samples_are_bounded() {
        let mut d = Drain::new();
        for _ in 0..100 {
            d.process("kernel: INBOUND TCP SRC=1.2.3.4 DPT=445");
        }
        let cluster = &d.ranked_clusters()[0];
        assert_eq!(cluster.count, 100);
        assert_eq!(cluster.samples.len(), SAMPLES_PER_CLUSTER);
    }

    #[test]
    fn blank_input_creates_nothing() {
        let mut d = Drain::new();
        assert!(d.process("   ").is_none());
        assert!(d.is_empty());
    }
}
