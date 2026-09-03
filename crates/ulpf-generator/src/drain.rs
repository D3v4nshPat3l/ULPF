//! Drain clustering algorithm implementation.
//!
//! Groups raw log lines into templates based on token length and similarity,
//! allowing the pack generator to tackle the highest-volume unknown logs first.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Cluster {
    pub id: String,
    pub template: Vec<String>,
    pub count: usize,
    pub samples: Vec<String>,
}

#[allow(dead_code)]
pub struct Drain {
    depth: usize,
    sim_th: f64,
    max_children: usize,
    max_clusters: usize,
    root: Node,
    clusters: HashMap<String, Cluster>,
    next_id: usize,
}

#[derive(Default)]
#[allow(dead_code)]
struct Node {
    children: HashMap<String, Node>,
    cluster_ids: Vec<String>,
}

impl Default for Drain {
    fn default() -> Self {
        Self::new()
    }
}

impl Drain {
    pub fn new() -> Self {
        Self {
            depth: 4,
            sim_th: 0.4,
            max_children: 100,
            max_clusters: 1000,
            root: Node::default(),
            clusters: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn process(&mut self, raw: &str) -> String {
        let tokens: Vec<String> = raw.split_whitespace().map(|s| s.to_string()).collect();
        let len = tokens.len();

        // Match against existing
        let mut best_match: Option<(String, f64)> = None;
        for cluster in self.clusters.values() {
            if cluster.template.len() == len {
                let sim = self.similarity(&tokens, &cluster.template);
                if sim >= self.sim_th {
                    if let Some((_, best_sim)) = best_match {
                        if sim > best_sim {
                            best_match = Some((cluster.id.clone(), sim));
                        }
                    } else {
                        best_match = Some((cluster.id.clone(), sim));
                    }
                }
            }
        }

        if let Some((id, _)) = best_match {
            let cluster = self.clusters.get_mut(&id).unwrap();
            cluster.count += 1;
            if cluster.samples.len() < 30 {
                cluster.samples.push(raw.to_string());
            }
            self.update_template(id.clone(), tokens);
            id
        } else {
            let id = format!("C{:04}", self.next_id);
            self.next_id += 1;
            let cluster = Cluster {
                id: id.clone(),
                template: tokens,
                count: 1,
                samples: vec![raw.to_string()],
            };
            self.clusters.insert(id.clone(), cluster);
            id
        }
    }

    fn similarity(&self, tokens: &[String], template: &[String]) -> f64 {
        let mut match_count = 0;
        for (t, temp) in tokens.iter().zip(template.iter()) {
            if t == temp || temp == "<*>" {
                match_count += 1;
            }
        }
        match_count as f64 / tokens.len() as f64
    }

    fn update_template(&mut self, id: String, tokens: Vec<String>) {
        let cluster = self.clusters.get_mut(&id).unwrap();
        for (temp, token) in cluster.template.iter_mut().zip(tokens.iter()) {
            if temp != "<*>" && temp != token {
                *temp = "<*>".to_string();
            }
        }
    }

    pub fn ranked_clusters(&self) -> Vec<Cluster> {
        let mut sorted: Vec<_> = self.clusters.values().cloned().collect();
        sorted.sort_by_key(|a| std::cmp::Reverse(a.count));
        sorted
    }
}
