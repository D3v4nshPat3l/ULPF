//! Local model integration for drafting Source Packs.
//!
//! Talks to a model server running on the same host — Ollama by default, or a
//! `llama.cpp` server — so the whole loop stays inside the air gap.
//!
//! # Why the model is asked for a small JSON object, not a Pack
//!
//! A Source Pack is a large nested document, and a 1.5B-parameter model asked
//! to emit one verbatim will usually produce something that is *almost* valid
//! YAML. Instead the model is asked for a handful of decisions it is actually
//! good at — which vendor this looks like, which substrings identify it, which
//! decoders to chain, which source field maps to which OCSF attribute — and
//! this crate assembles the Pack from that in Rust. Structure is a job for
//! code; recognition is the job for the model.
//!
//! Ollama's `format: "json"` constrains decoding to syntactically valid JSON,
//! which removes the single largest failure mode.
//!
//! # No silent fallbacks
//!
//! If the model is unreachable or returns something unusable, this returns an
//! error saying so. An earlier version quietly substituted a hand-written
//! "mock" pack, which would have presented fabricated output as generated work.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use ulpf_pack::spec::{Detector, ExtractStep, Fixture, Identity, MapSpec, Pack, Provenance};

/// Which local model server to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Ollama: `POST /api/generate`, supports `format: "json"`.
    Ollama,
    /// llama.cpp server: `POST /completion`.
    LlamaCpp,
}

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434";
pub const DEFAULT_MODEL: &str = "qwen2.5:1.5b-instruct";

/// OCSF attributes the drafter may target. Keeping the list short keeps the
/// model on paths that actually exist in the schema, and lets an out-of-range
/// suggestion be rejected rather than compiled into a broken pack.
const ALLOWED_FIELDS: &[&str] = &[
    "src_endpoint.ip",
    "src_endpoint.port",
    "dst_endpoint.ip",
    "dst_endpoint.port",
    "connection_info.protocol_name",
    "device.hostname",
    "actor.user.name",
    "url",
    "message",
];

#[derive(Clone)]
pub struct GeneratorClient {
    endpoint: String,
    model: String,
    backend: Backend,
    client: reqwest::Client,
}

/// The small decision object the model is asked to fill in.
#[derive(Debug, Deserialize)]
struct DraftSpec {
    #[serde(default)]
    vendor: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    log_format: String,
    /// OCSF attribute path -> source field name produced by the decoders.
    #[serde(default)]
    fields: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct OllamaRequest<'a> {
    model: &'a str,
    prompt: String,
    stream: bool,
    format: &'a str,
    options: OllamaOptions,
}

#[derive(Serialize)]
struct OllamaOptions {
    temperature: f64,
    num_predict: u32,
    /// Penalise tokens seen recently. Without this a small model happily
    /// repeats one sentence until it runs out of budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    repeat_penalty: Option<f64>,
    /// How far back the penalty looks.
    #[serde(skip_serializing_if = "Option::is_none")]
    repeat_last_n: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f64>,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

/// Cut a reply short once it starts repeating itself.
///
/// Sampling penalties reduce looping but do not eliminate it on a 1.5B model.
/// If the same line comes back three times, everything from the second
/// occurrence onward is noise, so it is dropped rather than shown.
pub fn trim_degenerate_repetition(reply: &str) -> String {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    let mut kept: Vec<&str> = Vec::new();

    for line in reply.lines() {
        let key = line.trim();
        if key.len() > 25 {
            let count = seen.entry(key).or_insert(0);
            *count += 1;
            if *count >= 3 {
                break;
            }
        }
        kept.push(line);
    }

    let mut out = kept
        .join(
            "
",
        )
        .trim_end()
        .to_string();

    // Same collapse, but within a single unbroken paragraph.
    if let Some(trimmed) = trim_repeated_sentence(&out) {
        out = trimmed;
    }
    if out.trim().is_empty() {
        return reply.trim().chars().take(600).collect();
    }
    out
}

fn trim_repeated_sentence(text: &str) -> Option<String> {
    let sentences: Vec<&str> = text.split_inclusive(". ").collect();
    if sentences.len() < 4 {
        return None;
    }
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    let mut cut = None;
    for (i, s) in sentences.iter().enumerate() {
        let key = s.trim();
        if key.len() > 25 {
            let c = seen.entry(key).or_insert(0);
            *c += 1;
            if *c >= 3 {
                cut = Some(i);
                break;
            }
        }
    }
    cut.map(|i| sentences[..i].concat().trim_end().to_string())
}

/// One turn in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// `system`, `user` or `assistant`.
    pub role: String,
    pub content: String,
}

#[derive(Serialize)]
struct OllamaChatRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    stream: bool,
    options: OllamaOptions,
}

#[derive(Deserialize)]
struct OllamaChatResponse {
    message: ChatMessage,
}

#[derive(Serialize)]
struct LlamaCppRequest {
    prompt: String,
    n_predict: u32,
    temperature: f64,
}

#[derive(Deserialize)]
struct LlamaCppResponse {
    content: String,
}

/// How long to wait for the model server to answer a liveness check.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

impl GeneratorClient {
    pub fn new(endpoint: &str, model: &str, backend: Backend) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            model: model.to_string(),
            backend,
            client: reqwest::Client::new(),
        }
    }

    /// Build from the environment, so an operator can point at whatever model
    /// server the air-gapped host runs without a rebuild.
    ///
    /// `ULPF_LLM_ENDPOINT`, `ULPF_LLM_MODEL`, `ULPF_LLM_BACKEND`
    /// (`ollama` | `llamacpp`).
    pub fn from_env() -> Self {
        let endpoint =
            std::env::var("ULPF_LLM_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
        let model = std::env::var("ULPF_LLM_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());
        let backend = match std::env::var("ULPF_LLM_BACKEND").as_deref() {
            Ok("llamacpp") | Ok("llama.cpp") => Backend::LlamaCpp,
            _ => Backend::Ollama,
        };
        Self::new(&endpoint, &model, backend)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Cheap reachability check, so the console can say the model is offline
    /// instead of surfacing a 500 when someone presses Generate.
    pub async fn probe(&self) -> Result<()> {
        let url = match self.backend {
            Backend::Ollama => format!("{}/api/tags", self.endpoint),
            Backend::LlamaCpp => format!("{}/health", self.endpoint),
        };
        // Three seconds was too tight: Ollama answers /api/tags in milliseconds
        // when idle, but a request arriving while it is loading a model into
        // memory would time out and the console would report the server as
        // unreachable when it was merely busy.
        let res = self
            .client
            .get(&url)
            .timeout(PROBE_TIMEOUT)
            .send()
            .await
            .map_err(|error| {
                // "Unreachable" and "too slow to answer" need different fixes,
                // so they get different messages.
                if error.is_timeout() {
                    anyhow::anyhow!(
                        "the model server at {} did not respond within {}s; it may be loading a model",
                        self.endpoint,
                        PROBE_TIMEOUT.as_secs()
                    )
                } else {
                    anyhow::anyhow!("no model server reachable at {}: {error}", self.endpoint)
                }
            })?;
        if !res.status().is_success() {
            bail!(
                "model server at {} returned {}",
                self.endpoint,
                res.status()
            );
        }
        Ok(())
    }

    /// Free-form multi-turn conversation.
    ///
    /// Uses the chat endpoint rather than raw completion so the model keeps
    /// the thread of the conversation instead of answering each message cold.
    pub async fn chat(&self, messages: &[ChatMessage]) -> Result<String> {
        match self.backend {
            Backend::Ollama => {
                let req = OllamaChatRequest {
                    model: &self.model,
                    messages,
                    stream: false,
                    options: OllamaOptions {
                        // Higher than pack drafting: this is conversation, not
                        // structured extraction, and 0.1 makes it wooden.
                        temperature: 0.6,
                        // Capped deliberately. A 1.5B model given a long budget
                        // will pad rather than stop, and padding turns into
                        // verbatim repetition.
                        num_predict: 420,
                        repeat_penalty: Some(1.18),
                        repeat_last_n: Some(256),
                        top_p: Some(0.9),
                    },
                };
                let res = self
                    .client
                    .post(format!("{}/api/chat", self.endpoint))
                    .json(&req)
                    .timeout(std::time::Duration::from_secs(180))
                    .send()
                    .await
                    .with_context(|| {
                        format!("could not reach the model server at {}", self.endpoint)
                    })?;
                if !res.status().is_success() {
                    bail!("model server returned {}", res.status());
                }
                let reply = res.json::<OllamaChatResponse>().await?.message.content;
                Ok(trim_degenerate_repetition(&reply))
            }
            Backend::LlamaCpp => {
                // llama.cpp's completion endpoint has no chat role handling, so
                // flatten the thread into a transcript.
                let transcript = messages
                    .iter()
                    .map(|m| format!("{}: {}", m.role, m.content))
                    .collect::<Vec<_>>()
                    .join(
                        "
",
                    );
                self.complete(format!(
                    "{transcript}
assistant:"
                ))
                .await
            }
        }
    }

    async fn complete(&self, prompt: String) -> Result<String> {
        match self.backend {
            Backend::Ollama => {
                let req = OllamaRequest {
                    model: &self.model,
                    prompt,
                    stream: false,
                    format: "json",
                    options: OllamaOptions {
                        temperature: 0.1,
                        num_predict: 700,
                        repeat_penalty: Some(1.1),
                        repeat_last_n: Some(64),
                        top_p: None,
                    },
                };
                let res = self
                    .client
                    .post(format!("{}/api/generate", self.endpoint))
                    .json(&req)
                    .timeout(std::time::Duration::from_secs(120))
                    .send()
                    .await
                    .with_context(|| {
                        format!("could not reach the model server at {}", self.endpoint)
                    })?;
                if !res.status().is_success() {
                    bail!("model server returned {}", res.status());
                }
                Ok(res.json::<OllamaResponse>().await?.response)
            }
            Backend::LlamaCpp => {
                let req = LlamaCppRequest {
                    prompt,
                    n_predict: 700,
                    temperature: 0.1,
                };
                let res = self
                    .client
                    .post(format!("{}/completion", self.endpoint))
                    .json(&req)
                    .timeout(std::time::Duration::from_secs(120))
                    .send()
                    .await
                    .with_context(|| {
                        format!("could not reach the model server at {}", self.endpoint)
                    })?;
                if !res.status().is_success() {
                    bail!("model server returned {}", res.status());
                }
                Ok(res.json::<LlamaCppResponse>().await?.content)
            }
        }
    }

    /// Draft a candidate pack for one dead-letter cluster.
    ///
    /// The result is a *candidate*. It is never activated here; the caller
    /// scores it against the samples and a human approves it.
    pub async fn draft_pack(&self, cluster_id: &str, samples: &[String]) -> Result<Pack> {
        if samples.is_empty() {
            bail!("cluster {cluster_id} has no samples to learn from");
        }

        let shown: Vec<&String> = samples.iter().take(5).collect();
        // Extract the field names that genuinely exist in this format and give
        // the model a closed list. Asked open-endedly, a 1.5B model answers
        // with the *value* it saw ("10.2.4.7") rather than the name
        // ("src_addr"); turning generation into selection removes that failure.
        let available = available_field_names(samples);
        let prompt = build_prompt(&shown, &available);
        let raw = self.complete(prompt).await?;

        let spec: DraftSpec = parse_json_object(&raw)
            .with_context(|| format!("model did not return a usable JSON object: {raw:.400}"))?;

        Ok(assemble_pack(cluster_id, spec, samples, &self.model))
    }
}

fn build_prompt(samples: &[&String], available: &[String]) -> String {
    // The log lines go LAST, and no filled-in example is shown. An earlier
    // version put a complete FortiGate example in the prompt and a 1.5B model
    // simply copied it back — emitting `devname=` and `srcip` for an Apache
    // log. Describing the value types instead of demonstrating them removes
    // anything worth copying.
    format!(
        "You analyse security log formats. Answer ONLY with a JSON object.

         Keys and the value each must hold:
         \"vendor\": the vendor that most likely produced these lines, else \"Unknown\"
         \"product\": the product name, else \"Unknown\"
         \"log_format\": a short hyphenated label describing the shape you see
         \"fields\": object mapping an OCSF attribute to ONE name from the          AVAILABLE NAMES list. Use the name itself, never the value it holds.          Omit an attribute if no name fits. Allowed attributes: {fields}

         AVAILABLE NAMES (choose only from these): {available}

         LOG LINES:
{lines}",
        fields = ALLOWED_FIELDS.join(", "),
        available = available.join(", "),
        lines = samples
            .iter()
            .map(|s| format!("- {s}"))
            .collect::<Vec<_>>()
            .join("
"),
    )
}

/// Pull the first JSON object out of a model reply.
///
/// `format: "json"` makes Ollama emit bare JSON, but llama.cpp and chattier
/// models still wrap it in prose or a code fence.
fn parse_json_object(raw: &str) -> Result<DraftSpec> {
    let text = raw.trim();
    let start = text.find('{').context("no JSON object in reply")?;
    let end = text.rfind('}').context("no closing brace in reply")?;
    if end <= start {
        bail!("malformed JSON object in reply");
    }
    Ok(serde_json::from_str(&text[start..=end])?)
}

/// Reject detector literals that would only ever match the sample they came
/// from. This is the same failure that made an earlier drafter emit detectors
/// containing a wall-clock time, which can never match future traffic.
///
/// Public because `ulpf draft` needs exactly this test and had none: its
/// detectors were built from any token shared across a cluster, so a
/// single-record cluster contributed its whole timestamped line and the
/// resulting pack could never match a second event.
pub fn is_stable_literal(s: &str) -> bool {
    let t = s.trim();
    if t.len() < 3 || t.len() > 40 {
        return false;
    }
    // Any run of digits long enough to be a time, date, port or address makes
    // the literal volatile.
    let longest_digit_run = t
        .split(|c: char| !c.is_ascii_digit())
        .map(str::len)
        .max()
        .unwrap_or(0);
    if longest_digit_run >= 3 {
        return false;
    }
    // Clock- and date-shaped fragments.
    if t.contains(':') && t.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    // Month abbreviations and bare weekday names look stable inside one
    // capture but rotate with the calendar, and a single hostname does not
    // generalise past the box it came from. Require some structure -
    // punctuation or a separator - which is what real format markers have.
    const CALENDAR: &[&str] = &[
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec", "mon",
        "tue", "wed", "thu", "fri", "sat", "sun",
    ];
    if CALENDAR.contains(&t.to_ascii_lowercase().as_str()) {
        return false;
    }
    // Either the token carries format punctuation (`devname=`, `zephyrfw:`),
    // or it is long enough to be a distinctive product string rather than a
    // short host label: "MyAppClient" identifies a source, "gw01" identifies
    // one box.
    let has_structure = t.contains(|c: char| "=:[]/\"|_".contains(c));
    (has_structure || t.len() >= 8) && t.chars().any(|c| c.is_ascii_alphabetic())
}

/// Decide the decoder chain from the shape of the samples.
pub fn infer_decoders(samples: &[String]) -> Vec<&'static str> {
    let joined = samples.join(
        "
",
    );
    let first = samples.first().map(String::as_str).unwrap_or("");

    let mut chain = Vec::new();

    // A syslog envelope wraps the body; strip it before reading the body.
    let syslog_framed = first.starts_with('<')
        || first
            .split_whitespace()
            .next()
            .map(|t| {
                matches!(
                    t.to_ascii_lowercase().as_str(),
                    "jan"
                        | "feb"
                        | "mar"
                        | "apr"
                        | "may"
                        | "jun"
                        | "jul"
                        | "aug"
                        | "sep"
                        | "oct"
                        | "nov"
                        | "dec"
                )
            })
            .unwrap_or(false);
    if syslog_framed {
        chain.push("syslog");
    }

    if joined.contains("CEF:") {
        chain.push("cef");
    } else if joined.contains("LEEF:") {
        chain.push("leef");
    } else if first.trim_start().starts_with('{') {
        chain.push("json");
    } else if first.trim_start().starts_with('<') && first.contains("</") {
        chain.push("xml");
    } else if count_kv_pairs(&joined) >= 2 {
        chain.push("keyvalue");
    } else if first.matches(',').count() >= 5 {
        chain.push("csv");
    }

    if chain.is_empty() {
        chain.push("keyvalue");
    }
    chain
}

/// Count `key=value` pairs, ignoring `=` inside quotes.
fn count_kv_pairs(text: &str) -> usize {
    text.split_whitespace()
        .filter(|t| {
            t.split_once('=')
                .map(|(k, _)| {
                    !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                })
                .unwrap_or(false)
        })
        .count()
}

fn assemble_pack(cluster_id: &str, spec: DraftSpec, samples: &[String], model: &str) -> Pack {
    // Detectors are derived from the samples themselves rather than taken on
    // the model's word. A literal that does not occur in every sample cannot
    // identify the source, and a model that hallucinates one would produce a
    // pack that silently matches nothing.
    let detect = derive_detectors(samples);

    // Which decoders a body needs is decided by looking at the bytes, not by
    // asking the model. A 1.5B model offered "cef" for a plain key=value body;
    // the shape of the text answers this question exactly.
    let decoders: Vec<ExtractStep> = infer_decoders(samples)
        .into_iter()
        .map(|d| ExtractStep {
            decoder: d.to_string(),
            sep: None,
            delim: None,
            headers: Vec::new(),
            patterns: Vec::new(),
            // A drafted chain is a guess; a step that does not fit should not
            // sink the record.
            optional: true,
        })
        .collect();

    let mut map: BTreeMap<String, MapSpec> = BTreeMap::new();
    map.insert(
        "class_uid".into(),
        MapSpec::Literal(serde_json::json!(4001)),
    );
    map.insert("activity_id".into(), MapSpec::Literal(serde_json::json!(6)));
    map.insert("severity_id".into(), MapSpec::Literal(serde_json::json!(1)));
    // Convention-based mapping first: it is deterministic and correct far more
    // often than a small model's guess.
    let available = available_field_names(samples);
    for (ocsf_path, source) in infer_field_map(&available) {
        let cast = if ocsf_path.ends_with(".port") {
            Some(ulpf_pack::spec::Cast::Int)
        } else {
            None
        };
        map.insert(
            ocsf_path,
            MapSpec::Field(ulpf_pack::spec::FieldSpec {
                from: ulpf_pack::spec::OneOrMany::One(source),
                cast,
                format: None,
                enum_table: None,
                default: None,
                observable: None,
            }),
        );
    }

    // Anything the model suggested that convention missed, if it survives
    // validation, fills the remaining gaps.
    for (ocsf_path, source) in spec.fields {
        if !ALLOWED_FIELDS.contains(&ocsf_path.as_str())
            || source.trim().is_empty()
            || map.contains_key(&ocsf_path)
        {
            continue;
        }
        // A positional format such as an Apache access line has no named
        // fields, and a small model asked for one tends to answer with the
        // *value* it saw ("192.168.1.100") instead. Emitting that as a source
        // field name would produce a pack that silently maps nothing, so only
        // names that actually occur as keys in the samples are kept.
        if !looks_like_a_field_name(&source, samples) {
            continue;
        }
        map.insert(
            ocsf_path,
            MapSpec::Field(ulpf_pack::spec::FieldSpec {
                from: ulpf_pack::spec::OneOrMany::One(source),
                cast: None,
                format: None,
                enum_table: None,
                default: None,
                observable: None,
            }),
        );
    }

    // Fixtures come from the real samples, so the scorer grades the candidate
    // against the traffic it was drafted from.
    let fixtures: Vec<Fixture> = samples
        .iter()
        .take(3)
        .map(|raw| Fixture {
            raw: raw.clone(),
            expect: BTreeMap::new(),
            note: Some("Representative sample; confirm mappings before approval.".into()),
        })
        .collect();

    Pack {
        identity: Identity {
            id: format!("candidate-{cluster_id}"),
            vendor: blank_to_unknown(spec.vendor),
            product: blank_to_unknown(spec.product),
            version: None,
            log_format: Some(blank_to_unknown(spec.log_format)),
            detect: vec![Detector {
                contains_all: detect,
                contains_any: Vec::new(),
                contains_none: Vec::new(),
                starts_with: None,
            }],
            // Well below every hand-written pack, so a candidate can never
            // shadow a reviewed one.
            priority: 1000,
        },
        extract: if decoders.is_empty() {
            vec![ExtractStep {
                decoder: "keyvalue".into(),
                sep: None,
                delim: None,
                headers: Vec::new(),
                patterns: Vec::new(),
                optional: true,
            }]
        } else {
            decoders
        },
        map,
        enums: BTreeMap::new(),
        fixtures,
        provenance: Some(Provenance {
            author: Some("generated".into()),
            created: Some(ulpf_core::now_nanos().to_string()),
            cluster_id: Some(cluster_id.to_string()),
            approved_by: None,
            model: Some(model.to_string()),
        }),
    }
}

/// Map source field names onto OCSF attributes by naming convention.
///
/// Device vendors are remarkably consistent here: a source address is
/// `srcip`, `src_addr`, `src`, `source_ip` or `saddr`, essentially never
/// anything else. Matching those patterns is deterministic and, unlike a small
/// model, cannot answer with the field's *value*.
///
/// `qwen2.5:1.5b-instruct` returned values rather than names even when handed
/// an explicit list of the available names, so this carries the mapping and
/// the model is used only for naming the vendor and format.
pub fn infer_field_map(available: &[String]) -> BTreeMap<String, String> {
    // Ordered: the first available name matching any pattern wins, so more
    // specific spellings are listed before looser ones.
    const RULES: &[(&str, &[&str])] = &[
        (
            "src_endpoint.port",
            &[
                "srcport",
                "src_port",
                "src_prt",
                "sport",
                "spt",
                "sourceport",
            ],
        ),
        (
            "dst_endpoint.port",
            &[
                "dstport",
                "dst_port",
                "dst_prt",
                "dport",
                "dpt",
                "destport",
                "destinationport",
            ],
        ),
        (
            "src_endpoint.ip",
            &[
                "srcip",
                "src_ip",
                "src_addr",
                "saddr",
                "sourceip",
                "source_ip",
                "src",
            ],
        ),
        (
            "dst_endpoint.ip",
            &[
                "dstip",
                "dst_ip",
                "dst_addr",
                "daddr",
                "destip",
                "destination_ip",
                "dst",
            ],
        ),
        (
            "connection_info.protocol_name",
            &["proto", "protocol", "ipproto", "transport"],
        ),
        (
            "device.hostname",
            &["devname", "hostname", "host", "device", "dvchost", "devid"],
        ),
        (
            "actor.user.name",
            &["user", "username", "usr", "suser", "srcuser", "account"],
        ),
        ("url", &["url", "request", "uri", "requesturl", "cs_uri"]),
        (
            "message",
            &["msg", "message", "evt", "event", "reason", "description"],
        ),
    ];

    let normalise = |s: &str| {
        s.to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
    };

    let mut out = BTreeMap::new();
    let mut used: Vec<String> = Vec::new();

    for (ocsf_path, patterns) in RULES {
        for pattern in *patterns {
            let target = normalise(pattern);
            if let Some(found) = available
                .iter()
                .find(|name| normalise(name) == target && !used.contains(name))
            {
                out.insert(ocsf_path.to_string(), found.clone());
                used.push(found.clone());
                break;
            }
        }
    }
    out
}

/// Field names that actually occur in the samples.
///
/// Handles the two shapes that carry names — `key=value` bodies and JSON
/// objects — and falls back to positional `col.N` for delimited records.
pub fn available_field_names(samples: &[String]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();

    for sample in samples.iter().take(5) {
        // key=value
        for token in sample.split_whitespace() {
            if let Some((key, _)) = token.split_once('=') {
                if !key.is_empty()
                    && key
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                    && !names.iter().any(|n| n == key)
                {
                    names.push(key.to_string());
                }
            }
        }
        // JSON keys
        if sample.trim_start().starts_with('{') {
            if let Ok(serde_json::Value::Object(map)) =
                serde_json::from_str::<serde_json::Value>(sample)
            {
                for key in map.keys() {
                    if !names.iter().any(|n| n == key) {
                        names.push(key.clone());
                    }
                }
            }
        }
    }

    // Positional fallback for delimited records with no names at all.
    if names.is_empty() {
        if let Some(first) = samples.first() {
            let columns = first.matches(',').count() + 1;
            if columns >= 3 {
                names.extend((0..columns.min(40)).map(|i| format!("col.{i}")));
            }
        }
    }

    names.truncate(60);
    names
}

/// Whether `candidate` plausibly names a field the decoders will produce.
///
/// Accepts `col.N` (positional CSV), and any token that appears in the samples
/// immediately followed by `=` or `":` — i.e. it is used as a key there, not
/// as a value.
fn looks_like_a_field_name(candidate: &str, samples: &[String]) -> bool {
    let name = candidate.trim();
    if name.is_empty() || name.eq_ignore_ascii_case("unknown") || name.contains(' ') {
        return false;
    }
    if name.starts_with("col.") {
        return true;
    }
    let as_kv = format!("{name}=");
    let as_json = format!("\"{name}\"");
    samples
        .iter()
        .any(|s| s.contains(&as_kv) || s.contains(&as_json))
}

/// Derive detector literals from the samples themselves.
///
/// Takes the whitespace-separated tokens that appear, unchanged, in *every*
/// sample in the cluster — which is exactly what Drain's template already
/// tells us is the fixed part of the shape. Volatile tokens are excluded by
/// [`is_stable_literal`], so timestamps and addresses can never end up in a
/// detector.
/// Whether a token before `=` looks like a field name rather than prose.
fn is_field_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 40
        && key.chars().any(|c| c.is_ascii_alphabetic())
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Derive the `contains_all` literals that will claim this source.
///
/// Two rules, both learned from drafts that scored well and then matched
/// nothing in production:
///
/// * **A `key=value` token contributes its key, never its value.** With five
///   samples from one device, a constant `dst_addr=8.8.4.4` looks as shared as
///   `dst_addr=` does — but a detector built on the value claims only traffic
///   to that one address. The field *name* is what identifies the format; the
///   value is an accident of the sample set.
/// * **A program or vendor tag outranks a field name.** `acmefw:` identifies a
///   device; `src=` is carried by half of all key-value logs ever written. An
///   earlier version ranked purely by length, which put a destination address
///   first and dropped the vendor tag off the end of the list.
pub fn derive_detectors(samples: &[String]) -> Vec<String> {
    let Some(first) = samples.first() else {
        return Vec::new();
    };

    let mut shared: Vec<String> = Vec::new();
    for token in first.split_whitespace() {
        match token.split_once('=') {
            Some((key, _)) if is_field_key(key) => shared.push(format!("{key}=")),
            // Not a pair, so the token itself has to carry the identity.
            _ if is_stable_literal(token) => shared.push(token.to_string()),
            _ => {}
        }
    }

    for sample in samples.iter().skip(1) {
        shared.retain(|token| sample.contains(token.as_str()));
    }

    shared.sort();
    shared.dedup();
    shared.sort_by(|a, b| {
        // Class 0 is a tag or literal marker, class 1 a bare field name.
        let class = |t: &String| usize::from(t.ends_with('='));
        class(a)
            .cmp(&class(b))
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| a.cmp(b))
    });
    shared.truncate(3);
    shared
}

fn blank_to_unknown(s: String) -> String {
    if s.trim().is_empty() {
        "Unknown".into()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_looping_reply_is_cut_at_the_repeat() {
        // The exact failure seen in the console: one sentence, many times.
        let looped = "Here is the answer.
"
        .to_string()
            + &"The logs are in a format that is easy to understand and read.
"
            .repeat(40);
        let out = trim_degenerate_repetition(&looped);
        let occurrences = out.matches("easy to understand").count();
        assert!(
            occurrences <= 2,
            "still repeating {occurrences} times: {out}"
        );
        assert!(out.starts_with("Here is the answer."));
    }

    #[test]
    fn a_normal_reply_is_left_alone() {
        let normal = "You have 11 packs loaded.
Coverage is 98%.
Four records are unparsed.";
        assert_eq!(trim_degenerate_repetition(normal), normal);
    }

    #[test]
    fn repetition_inside_one_paragraph_is_also_cut() {
        let looped = "Fine. ".to_string()
            + &"The logs are in a format that is easy to understand and read. ".repeat(30);
        let out = trim_degenerate_repetition(&looped);
        assert!(
            out.len() < looped.len() / 3,
            "not trimmed: {} chars",
            out.len()
        );
    }

    #[test]
    fn volatile_detector_literals_are_rejected() {
        // These are what made an earlier drafter emit unusable detectors.
        assert!(!is_stable_literal("12:11:24"));
        assert!(!is_stable_literal("192.168.1.10"));
        assert!(!is_stable_literal("2024-03-15"));
        assert!(!is_stable_literal("1045"));
        assert!(!is_stable_literal("UserID: 1045"));
    }

    #[test]
    fn stable_detector_literals_are_kept() {
        assert!(is_stable_literal("devname="));
        assert!(is_stable_literal("type=traffic"));
        assert!(is_stable_literal("[AppServer]"));
        assert!(is_stable_literal("MyAppClient"));
    }

    #[test]
    fn field_names_map_onto_ocsf_by_convention() {
        // The exact names from the unknown appliance in testing.
        let available: Vec<String> = [
            "evt", "src_addr", "src_prt", "dst_addr", "dst_prt", "proto", "verdict", "rule",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let m = infer_field_map(&available);
        assert_eq!(
            m.get("src_endpoint.ip").map(String::as_str),
            Some("src_addr")
        );
        assert_eq!(
            m.get("src_endpoint.port").map(String::as_str),
            Some("src_prt")
        );
        assert_eq!(
            m.get("dst_endpoint.ip").map(String::as_str),
            Some("dst_addr")
        );
        assert_eq!(
            m.get("dst_endpoint.port").map(String::as_str),
            Some("dst_prt")
        );
        assert_eq!(
            m.get("connection_info.protocol_name").map(String::as_str),
            Some("proto")
        );

        // FortiGate spellings resolve too.
        let fg: Vec<String> = ["srcip", "srcport", "dstip", "dstport", "devname", "action"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let m2 = infer_field_map(&fg);
        assert_eq!(m2.get("src_endpoint.ip").map(String::as_str), Some("srcip"));
        assert_eq!(
            m2.get("device.hostname").map(String::as_str),
            Some("devname")
        );
    }

    #[test]
    fn a_source_name_is_never_reused_for_two_attributes() {
        let available: Vec<String> = ["src", "dst"].iter().map(|s| s.to_string()).collect();
        let m = infer_field_map(&available);
        let sources: Vec<&String> = m.values().collect();
        let mut uniq = sources.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(sources.len(), uniq.len(), "a field was mapped twice: {m:?}");
    }

    #[test]
    fn decoder_chain_is_inferred_from_the_bytes() {
        let kv = vec!["Mar 15 10:30:01 gw01 fw: src_addr=10.0.0.1 dst_addr=8.8.8.8".to_string()];
        assert_eq!(infer_decoders(&kv), vec!["syslog", "keyvalue"]);

        let cef = vec!["CEF:0|V|P|1|1|name|5|src=10.0.0.1".to_string()];
        assert_eq!(infer_decoders(&cef), vec!["cef"]);

        let js = vec![r#"{"src_ip":"10.0.0.1"}"#.to_string()];
        assert_eq!(infer_decoders(&js), vec!["json"]);

        let csv = vec!["a,b,c,d,e,f,g,h".to_string()];
        assert_eq!(infer_decoders(&csv), vec!["csv"]);
    }

    #[test]
    fn calendar_words_and_bare_hostnames_are_weak_detectors() {
        // Stable within one capture, but "Mar" fails in April and "gw01"
        // fails on the next appliance.
        assert!(!is_stable_literal("Mar"));
        assert!(!is_stable_literal("gw01"));
        // A real format marker has structure.
        assert!(is_stable_literal("zephyrfw:"));
        assert!(is_stable_literal("devname="));
    }

    #[test]
    fn values_are_not_accepted_as_field_names() {
        // What a small model actually returns for a positional format.
        let apache = vec![
            r#"192.168.1.100 - - [15/Mar/2024:10:30:01 +0000] "GET /a HTTP/1.1" 200 1024"#
                .to_string(),
        ];
        assert!(!looks_like_a_field_name("192.168.1.100", &apache));
        assert!(!looks_like_a_field_name("/api/v1/users", &apache));
        assert!(!looks_like_a_field_name("Unknown", &apache));
        assert!(!looks_like_a_field_name("GET /a HTTP/1.1", &apache));
    }

    #[test]
    fn real_field_names_are_accepted() {
        let kv = vec!["devname=\"FGT\" srcip=10.0.0.1 action=accept".to_string()];
        assert!(looks_like_a_field_name("srcip", &kv));
        assert!(looks_like_a_field_name("action", &kv));

        let js = vec![r#"{"src_ip":"10.0.0.1","action":"allow"}"#.to_string()];
        assert!(looks_like_a_field_name("src_ip", &js));

        // Positional columns are always legitimate.
        assert!(looks_like_a_field_name("col.7", &kv));
    }

    #[test]
    fn detectors_come_from_tokens_shared_by_every_sample() {
        // Real Apache lines: the shared, non-volatile tokens are the format
        // markers, never the addresses or timestamps.
        let samples = vec![
            r#"192.168.1.100 - - [15/Mar/2024:10:30:01 +0000] "GET /a HTTP/1.1" 200 1024 "-" "MyAppClient/1.0""#.to_string(),
            r#"10.2.4.19 - - [15/Mar/2024:10:31:44 +0000] "POST /b HTTP/1.1" 401 512 "-" "MyAppClient/1.0""#.to_string(),
        ];
        let detect = derive_detectors(&samples);
        assert!(!detect.is_empty(), "expected at least one detector");
        for d in &detect {
            assert!(
                samples.iter().all(|s| s.contains(d.as_str())),
                "`{d}` is not present in every sample"
            );
            assert!(!d.contains("192.168"), "address leaked into detector: {d}");
            assert!(!d.contains("10:30"), "timestamp leaked into detector: {d}");
        }
    }

    #[test]
    fn a_constant_value_never_becomes_the_detector() {
        // Eight lines from one device all happen to talk to 8.8.4.4. Keying on
        // that claims only traffic to that address; keying on `dst_addr=` and
        // the program tag claims the device.
        let samples: Vec<String> = (1..=8)
            .map(|i| {
                format!(
                    "Sep  3 10:00:0{i} fw01 acmefw: action=allow src_addr=10.1.2.{i}                      dst_addr=8.8.4.4 src_port=4000{i} dst_port=443 proto=tcp"
                )
            })
            .collect();

        let detect = derive_detectors(&samples);
        assert!(
            !detect.iter().any(|d| d.contains("8.8.4.4")),
            "a constant value leaked into the detector: {detect:?}"
        );
        assert!(
            detect.iter().any(|d| d == "acmefw:"),
            "the program tag is the strongest signal and must rank first: {detect:?}"
        );
        assert_eq!(detect[0], "acmefw:", "tags outrank bare field names");
        for d in &detect {
            assert!(
                samples.iter().all(|s| s.contains(d.as_str())),
                "`{d}` is not present in every sample"
            );
        }
    }

    #[test]
    fn json_is_extracted_from_a_fenced_reply() {
        let reply = "Here you go:
```json
{\"vendor\":\"Acme\",\"product\":\"Gateway\"}
```";
        let spec = parse_json_object(reply).unwrap();
        assert_eq!(spec.vendor, "Acme");
        assert_eq!(spec.product, "Gateway");
    }

    #[test]
    fn a_reply_with_no_json_is_an_error_not_a_fabricated_pack() {
        assert!(parse_json_object("I could not determine the format.").is_err());
    }

    #[test]
    fn assembled_pack_is_low_priority_and_marked_generated() {
        let spec = DraftSpec {
            vendor: "Acme".into(),
            product: "Gateway".into(),
            log_format: "syslog-keyvalue".into(),
            fields: BTreeMap::from([
                ("src_endpoint.ip".into(), "srcip".into()),
                ("not_a_real_field".into(), "x".into()),
            ]),
        };
        let samples = vec![
            "acme_fw srcip=10.0.0.1 action=accept".to_string(),
            "acme_fw srcip=10.0.0.2 action=deny".to_string(),
        ];
        let pack = assemble_pack("abc", spec, &samples, "test-model");

        // Never shadows a reviewed pack.
        assert_eq!(pack.identity.priority, 1000);
        // Detectors are derived from tokens common to every sample, so the
        // shared marker survives and the per-line values do not.
        let detect = &pack.identity.detect[0].contains_all;
        assert!(detect.contains(&"acme_fw".to_string()), "got {detect:?}");
        assert!(
            !detect.iter().any(|d| d.contains("10.0.0.1")),
            "got {detect:?}"
        );
        // Decoders are inferred from the samples, not taken from the model:
        // an unframed key=value body needs exactly the keyvalue decoder.
        let chain: Vec<&str> = pack.extract.iter().map(|e| e.decoder.as_str()).collect();
        assert_eq!(chain, vec!["keyvalue"]);
        // Unknown OCSF paths are filtered out; the real one survives.
        assert!(pack.map.contains_key("src_endpoint.ip"));
        assert!(!pack.map.contains_key("not_a_real_field"));
        // Provenance records that a human has not signed off.
        let prov = pack.provenance.unwrap();
        assert_eq!(prov.author.as_deref(), Some("generated"));
        assert!(prov.approved_by.is_none());
    }
}
