//! LLM Sidecar Integration
//!
//! Talks to a local `llama.cpp` instance running a quantized model (e.g. Qwen3-4B)
//! to generate Source Packs from unparsed log samples.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use ulpf_pack::Pack;

#[derive(Serialize)]
struct LlamaRequest {
    prompt: String,
    n_predict: usize,
    temperature: f64,
    grammar: String,
}

#[derive(Deserialize)]
struct LlamaResponse {
    content: String,
}

#[derive(Clone)]
pub struct GeneratorClient {
    endpoint: String,
    client: reqwest::Client,
}

impl GeneratorClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn draft_pack(&self, cluster_id: &str, samples: &[String]) -> Result<Pack> {
        let grammar = r#"
root ::= "identity:\n  id: " id "\n  vendor: " string "\n  product: " string "\n  detect:\n    - contains_all: [" string_list "]\n" extract map fixtures
id ::= [a-z0-9_-]+
extract ::= "extract:\n" extract_list
extract_list ::= "  - decoder: " id "\n" | "  - decoder: " id "\n" extract_list
map ::= "map:\n" map_list
map_list ::= "  " id ": " string "\n" | "  " id ": " string "\n" map_list
fixtures ::= "fixtures:\n" fixture_list
fixture_list ::= fixture | fixture fixture_list
fixture ::= "  - raw: " string "\n    expect: {}\n"
string ::= "'" [^']* "'"
string_list ::= string | string ", " string_list
        "#.trim().to_string();

        let prompt = format!(
            "You are a cybersecurity expert. Create a valid Source Pack YAML for these log samples:\n\n{}\n\nOutput only the YAML.",
            samples.join("\n")
        );

        let req = LlamaRequest {
            prompt,
            n_predict: 1024,
            temperature: 0.1,
            grammar,
        };

        let res = self.client
            .post(format!("{}/completion", self.endpoint))
            .json(&req)
            .send()
            .await?;

        if !res.status().is_success() {
            anyhow::bail!("LLM request failed: {}", res.status());
        }

        let resp: LlamaResponse = res.json().await?;
        let yaml = resp.content.trim().to_string();
        
        // Ensure the ID matches the cluster for the UI's sake
        if yaml.contains("id: ") {
            // We just let the parser handle it, and overwrite later
        }

        let mut pack: Pack = match serde_yaml::from_str(&yaml) {
            Ok(p) => p,
            Err(e) => {
                // Fallback to a mock pack if the LLM produced invalid YAML despite grammar
                tracing::warn!("LLM produced invalid YAML: {e}. Falling back to mock.");
                serde_yaml::from_str(&format!(
                    r#"identity:
  id: generated-{cluster_id}
  vendor: Unknown
  product: Unknown
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
                ))?
            }
        };

        pack.identity.id = format!("generated-{cluster_id}");
        pack.provenance = Some(ulpf_pack::spec::Provenance {
            author: Some("generated".to_string()),
            created: Some(ulpf_core::now_nanos().to_string()),
            cluster_id: Some(cluster_id.to_string()),
            approved_by: None,
            model: Some("llama.cpp".to_string()),
        });

        Ok(pack)
    }
}
