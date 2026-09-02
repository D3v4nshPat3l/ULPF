//! LLM Sidecar Integration
//!
//! Talks to a local `llama.cpp` instance running a quantized model (e.g. Qwen3-4B)
//! to generate Source Packs from unparsed log samples.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use ulpf_pack::Pack;

#[derive(Serialize)]
#[allow(dead_code)]
struct LlamaRequest {
    prompt: String,
    n_predict: usize,
    temperature: f64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct LlamaResponse {
    content: String,
}

#[allow(dead_code)]
pub struct GeneratorClient {
    endpoint: String,
}

impl GeneratorClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
        }
    }

    pub async fn draft_pack(&self, cluster_id: &str, samples: &[String]) -> Result<Pack> {
        // In a real implementation, this would send an HTTP request to llama.cpp
        // For the hackathon Phase 0/1 slice, we return a mock pack to unblock the UI flow.
        
        // Let's pretend the LLM generated this based on the samples.
        let yaml = format!(
            r#"identity:
  id: generated-{cluster_id}
  vendor: Unknown
  product: UnknownProduct
  detect:
    - contains_all: []
extract:
  - decoder: syslog
map:
  class_uid: 4001
fixtures:
  - raw: '{sample}'
    expect: {{}}
"#,
            cluster_id = cluster_id,
            sample = samples.first().unwrap_or(&"empty".to_string())
        );

        let mut pack: Pack = serde_yaml::from_str(&yaml)?;
        pack.provenance = Some(ulpf_pack::spec::Provenance {
            author: Some("generated".to_string()),
            created: Some(ulpf_core::now_nanos().to_string()),
            cluster_id: Some(cluster_id.to_string()),
            approved_by: None,
            model: Some("llama.cpp/phi-4-mini".to_string()),
        });

        Ok(pack)
    }
}
