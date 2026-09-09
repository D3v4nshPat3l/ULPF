//! The operator console: an embedded HTTP server and single-page UI.
//!
//! This is requirement (f) — unified visibility across heterogeneous sources —
//! and the surface a judge or an analyst actually looks at. It deliberately
//! serves everything from the binary itself: no CDN, no node_modules, no
//! external font. A strict reading of requirement (j) means the console has to
//! work on a machine with no route off the host, so the HTML, CSS and script
//! are compiled in via `include_str!`.
//!
//! The interesting endpoint is `POST /api/ingest`. It runs one line through the
//! real pipeline and returns not just the OCSF result but the intermediate
//! stages — which pack claimed it, what the decoder chain extracted, what the
//! attestation covers. Showing the middle of the pipeline is what makes the
//! normalization legible rather than magical.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use ulpf_core::{Envelope, RawRef, Transport};
use ulpf_ocsf::OcsfEvent;
use ulpf_vault::VaultReader;

use crate::pipeline::Pipeline;

const INDEX_HTML: &str = include_str!("ui/index.html");
const DEV_HTML: &str = include_str!("ui/dev.html");

/// Recent events kept for the console table.
///
/// Bounded on purpose: the console is a window onto a stream, not a store. The
/// sinks are where events are meant to land, and an unbounded buffer here would
/// turn a long-running demo into an out-of-memory report.
pub const RECENT_CAPACITY: usize = 500;
const MAX_INGEST_LINES: usize = 2_000;
const MAX_INGEST_BYTES: usize = 4 * 1024 * 1024;

pub struct AppState {
    pub pipeline: Pipeline,
    pub recent: Vec<RecentEvent>,
    pub chain_anchor: Option<ulpf_ocsf::ChainLink>,
    pub latest_checkpoint: Option<ulpf_ocsf::Checkpoint>,
    pub checkpoint_path: std::path::PathBuf,
    pub merkle_leaves_path: std::path::PathBuf,
    pub public_key_path: std::path::PathBuf,
    pub vault_dir: std::path::PathBuf,
    pub packs_dir: std::path::PathBuf,
    pub drain: ulpf_generator::drain::Drain,
    /// Source profiles already computed for a cluster, keyed by cluster id and
    /// valid for as long as that cluster's retained sample count is unchanged.
    /// `Drain` only ever pushes samples, so a cluster whose sample count has
    /// not moved has the same samples it was profiled from.
    pub cluster_profiles: HashMap<String, (usize, Value)>,
    pub simulator: crate::simulator::Simulator,
    /// Set when `serve` was started with `--encrypt-vault`. The `raw`
    /// handler needs this to build its own `VaultReader` against the same
    /// encrypted vault the pipeline's `VaultWriter` is already using.
    pub vault_key: Option<ulpf_vault::crypto::Key32>,
}

#[derive(Clone)]
pub struct RecentEvent {
    pub event: OcsfEvent,
    pub disposition: String,
    pub pack: Option<String>,
    pub locator: String,
}

type Shared = Arc<Mutex<AppState>>;

/// Build the console router.
///
/// `expected_origin` is the `scheme://host:port` the console is reachable at,
/// and gates the browser-safety middleware below. `None` disables that guard
/// and exists for callers that drive handlers directly.
///
/// `auth_token` is the console's bearer secret (see `crate::auth`). `None`
/// disables the check entirely — used by `--no-auth` and by tests that drive
/// handlers directly without a token to present. Every other deployment
/// should carry `Some`: this is the only thing that stops a client which can
/// already reach the port (the Origin/Host guard below cannot, by design) from
/// approving packs or reading raw evidence.
pub fn router(
    state: Shared,
    expected_origin: Option<String>,
    auth_token: Option<Arc<str>>,
) -> Router {
    let probe_state = state.clone();
    let guarded = Router::new()
        .route("/api/stats", get(stats))
        .route("/api/packs", get(packs))
        .route("/api/events", get(events))
        .route("/api/clusters", get(clusters))
        .route("/api/generate", post(generate))
        .route("/api/chat", post(chat))
        .route("/api/ingest", post(ingest))
        .route("/api/approve", post(approve))
        .route("/api/raw/{locator}", get(raw))
        .route("/api/verify", post(verify))
        .route("/api/tamper", post(tamper))
        .route("/api/clear", post(clear))
        .route("/api/sim/sources", get(sim_sources))
        .route("/api/sim/target", post(sim_target))
        .route("/api/sim/toggle", post(sim_toggle))
        .route("/api/sim/stop-all", post(sim_stop_all))
        .route("/api/proof", post(make_proof))
        .route("/api/verify-proof", post(check_proof))
        .layer(DefaultBodyLimit::max(MAX_INGEST_BYTES))
        .with_state(state)
        // Layered after `with_state`: the expected origin is captured by the
        // closure rather than threaded through the handlers' AppState.
        .layer(middleware::from_fn(move |request: Request, next: Next| {
            let expected = expected_origin.clone();
            async move { same_origin_only(expected, request, next).await }
        }))
        // Auth is the outermost layer of the two (applied last, so it runs
        // first): a request with no token is rejected before the Origin/Host
        // check ever inspects it, which keeps the 401 response identical
        // whether or not a browser happened to be involved.
        .layer(middleware::from_fn(move |request: Request, next: Next| {
            let token = auth_token.clone();
            async move {
                match token {
                    Some(token) => crate::auth::require_token(token, request, next).await,
                    None => next.run(request).await,
                }
            }
        }));

    // Liveness and readiness are merged *after* the guard layer, not registered
    // before it. `.layer()` applies to every route already on the router, so
    // listing them above put them behind the Host check despite a comment
    // saying otherwise — and a probe arriving through a container port mapping
    // carries the published port in `Host`, which never matches the bound
    // address. `docker run -p 18787:8787` plus `curl /readyz` returned
    // "unexpected Host header", so the readiness probe the Dockerfile
    // documents could not succeed from outside the container.
    //
    // Neither endpoint reads request state or discloses event data: /healthz
    // answers while the process serves, /readyz reports pack count, vault
    // writability and schema version. A readiness check that can be refused is
    // not a readiness check.
    let probes = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(probe_state);

    // `/` and `/dev` are merged in the same unguarded way, for a different
    // reason: they are the page *shell* — static HTML/CSS/JS with no
    // server-templated secret and no state dependency at all (`index` and
    // `dev_dashboard` take no `State` — see below) — and the page's own
    // script is what asks for the console token via `window.prompt()` and
    // attaches it to every `/api/*` call afterward. That script cannot run
    // if the page itself never arrives: with these two routes inside the
    // guarded router, a first-time visit with no token yet (which is every
    // visit, on a fresh browser) received the same bare JSON 401 `/api/*`
    // gets, and the token prompt already written into this page was dead
    // code — nothing had loaded it. The API underneath is exactly as
    // protected as before; only the shell that asks for the key to that API
    // is unlocked.
    let pages = Router::new()
        .route("/", get(index))
        .route("/dev", get(dev_dashboard));

    guarded.merge(probes).merge(pages)
}

/// Refuse cross-origin and rebound requests.
///
/// This guard predates `crate::auth` and is kept for two reasons even though
/// the token now closes the main attack it was written for. A classic CSRF —
/// a malicious page's `<form>` or plain `fetch` POSTing to
/// `127.0.0.1:8787/api/approve` — cannot attach an `Authorization` header the
/// page has no way to read, since the console token lives in *this origin's*
/// localStorage; the browser does not attach it on the attacker's behalf the
/// way it would a cookie. So token auth already defeats that specific attack.
///
/// What this guard still covers: **`--no-auth` deployments**, where it is the
/// only control between a reachable port and an unauthenticated approval, and
/// **defense in depth** against DNS rebinding — a hostname the attacker
/// controls resolving to this loopback address, which would otherwise let a
/// same-origin-looking request reach handlers this check refuses before the
/// auth layer even runs. A Source Pack decides how every subsequent record is
/// interpreted, and that is worth two independent checks rather than one.
///
/// Two checks close it without introducing a credential to manage:
///
/// * **Origin.** A browser attaches `Origin` to every cross-origin request and
///   forbids the page from forging it. If it is present and is not ours, the
///   request did not come from the console. Absent means a non-browser client
///   (curl, an orchestrator, our own tests), which is not the threat here.
/// * **Host.** DNS rebinding defeats an origin check by making the attacker's
///   own name resolve to 127.0.0.1, so the page and the console share an
///   origin. The `Host` header still carries that name, so requiring it to be
///   one we actually bound closes it.
///
/// This is a browser-safety boundary, not authentication. It stops a remote
/// page from driving the console; it does not stop someone who can already
/// reach the port. Binding to loopback remains the deployment control, and a
/// reverse proxy in front remains the answer for anything wider.
async fn same_origin_only(
    expected_origin: Option<String>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = expected_origin.as_deref() else {
        return next.run(request).await;
    };

    // Read both headers into owned values before any await. Holding a borrow
    // of the request across `next.run` makes the future non-Send, because the
    // body behind it is not Sync.
    let (origin, host) = {
        let headers = request.headers();
        let get = |name: header::HeaderName| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_ascii_lowercase)
        };
        (get(header::ORIGIN), get(header::HOST))
    };

    if let Some(origin) = origin {
        if origin != expected {
            return refuse(
                "this request came from another origin; the console does not accept cross-site requests",
            );
        }
    }

    // `expected` is scheme://host:port; the Host header is host:port.
    let expected_host = expected.split("://").nth(1).unwrap_or(expected);
    match host {
        // A bare loopback host on the right port is the same machine by
        // another name, and is what a browser sends for a hand-typed URL.
        Some(host) if host != expected_host && !loopback_equivalent(&host, expected_host) => {
            return refuse(
                "unexpected Host header; the console only answers on the address it was bound to",
            )
        }
        _ => {}
    }

    next.run(request).await
}

/// True when `host` names this machine on the same port as `expected`.
fn loopback_equivalent(host: &str, expected: &str) -> bool {
    let port = |s: &str| s.rsplit(':').next().unwrap_or_default().to_string();
    if port(host) != port(expected) {
        return false;
    }
    let name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    matches!(
        name.trim_matches(|c| c == '[' || c == ']'),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn refuse(message: &str) -> Response {
    ApiError(StatusCode::FORBIDDEN, message.to_string()).into_response()
}

/// Liveness: the process is up and serving. Deliberately does no work.
async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        "ok
",
    )
}

/// Readiness: the collector can actually do its job.
///
/// Distinct from liveness on purpose. A collector that is running but has no
/// packs loaded, or cannot write its vault, will accept syslog and silently
/// fail to preserve it — which is the one outcome this project exists to
/// prevent. An orchestrator should take it out of rotation instead.
async fn readyz(State(state): State<Shared>) -> Response {
    let s = lock(&state);
    let packs = s.pipeline.packs().len();
    let vault_writable = s.vault_dir.exists();
    let chain_signed = s.latest_checkpoint.is_some() || s.pipeline.chain_head().is_none();
    let ready = packs > 0 && vault_writable;

    let body = json!({
        "ready": ready,
        "packs_loaded": packs,
        "vault_writable": vault_writable,
        "chain_signed_or_empty": chain_signed,
        "schema_version": ulpf_ocsf::SCHEMA_VERSION,
    });
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body)).into_response()
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn dev_dashboard() -> Html<&'static str> {
    Html(DEV_HTML)
}

/// Anything that goes wrong becomes a JSON error the UI can render.
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl From<ulpf_ocsf::IntegrityError> for ApiError {
    fn from(error: ulpf_ocsf::IntegrityError) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }
}

fn lock(state: &Shared) -> std::sync::MutexGuard<'_, AppState> {
    // A poisoned lock means a handler panicked mid-request. The pipeline state
    // is still structurally valid — the vault is append-only and the chain head
    // is only advanced after a successful attestation — so recovering is
    // preferable to taking the console down.
    state.lock().unwrap_or_else(|e| e.into_inner())
}

async fn stats(State(state): State<Shared>) -> Json<Value> {
    let s = lock(&state);
    let st = &s.pipeline.stats;
    Json(json!({
        "received": st.received,
        "parsed": st.parsed,
        "unidentified": st.unidentified,
        "searchable_unidentified": st.searchable_unidentified,
        "extract_failed": st.extract_failed,
        "normalize_failed": st.normalize_failed,
        "bytes_in": st.bytes_in,
        "coverage": st.coverage(),
        "by_pack": st.by_pack,
        "schema_version": ulpf_ocsf::SCHEMA_VERSION,
        "chain_sequence": s.latest_checkpoint.as_ref().map(|cp| cp.sequence).unwrap_or(0),
        "chain_uid": s.latest_checkpoint.as_ref().map(|cp| cp.chain_uid.as_str()),
        "checkpoint_signed": s.latest_checkpoint.is_some(),
    }))
}

async fn packs(State(state): State<Shared>) -> Json<Value> {
    let s = lock(&state);
    let list: Vec<Value> = s
        .pipeline
        .packs()
        .iter()
        .map(|p| {
            let report = ulpf_pack::library::test_pack(p);
            json!({
                "id": p.id,
                "vendor": p.vendor,
                "product": p.product,
                "log_format": p.log_format,
                "priority": p.priority,
                "decoders": p.spec.extract.iter().map(|e| e.decoder.clone()).collect::<Vec<_>>(),
                "mapped_attributes": p.spec.map.len(),
                "fixtures": report.total,
                "fixtures_passed": report.passed,
                "field_accuracy": report.field_accuracy(),
            })
        })
        .collect();
    Json(json!({ "packs": list }))
}

async fn events(State(state): State<Shared>) -> Json<Value> {
    let s = lock(&state);
    let rows: Vec<Value> = s.recent.iter().rev().map(summarize).collect();
    Json(json!({ "events": rows }))
}

/// The console polls this every two seconds, so what it costs is paid
/// continuously for as long as a console is open.
///
/// Profiling every retained cluster inline under the state lock is what that
/// used to mean: measured at the 1000-cluster cap it is ~104 ms per request in
/// a release build and ~1.2 s in a debug one, and the lock it was holding is
/// the same one the UDP ingest path needs to record an event. A console left
/// open would stall the collector for that long, twice a second.
///
/// So the lock is released before any profiling happens, and a profile is
/// computed once per cluster rather than once per poll.
async fn clusters(State(state): State<Shared>) -> Json<Value> {
    let (ranked, overflow, cached) = {
        let s = lock(&state);
        (
            s.drain.ranked_clusters(),
            s.drain.overflow(),
            s.cluster_profiles.clone(),
        )
    };

    let mut fresh: HashMap<String, (usize, Value)> = HashMap::with_capacity(ranked.len());
    let list: Vec<Value> = ranked
        .into_iter()
        .map(|c| {
            let source_profile = match cached.get(&c.id) {
                Some((len, profile)) if *len == c.samples.len() => profile.clone(),
                _ => json!(ulpf_generator::profile::analyze(&c.samples)),
            };
            // Rebuilt from the clusters that still exist, so the cache cannot
            // outlive the cluster table it describes.
            fresh.insert(c.id.clone(), (c.samples.len(), source_profile.clone()));
            json!({
                "id": c.id,
                "count": c.count,
                "template": c.template.join(" "),
                "samples": c.samples,
                "source_profile": source_profile,
                // Fraction of the template that is still a literal token
                // rather than a wildcard. Two clusters at equal count are
                // not equally trustworthy: this is the number that says so.
                "specificity": c.specificity(),
            })
        })
        .collect();

    lock(&state).cluster_profiles = fresh;

    // Report what the cluster cap dropped rather than hiding it: a rising
    // overflow is itself the signal that unparsed traffic is more varied than
    // the console is showing.
    Json(json!({ "clusters": list, "overflow": overflow }))
}

/// Either drive an existing dead-letter cluster, or hand over raw lines
/// directly — the console's Copilot pastes a line, the Clusters view sends an
/// id, and both should work.
#[derive(serde::Deserialize)]
struct GenerateBody {
    #[serde(default)]
    cluster_id: Option<String>,
    #[serde(default)]
    raw_log: Option<String>,
    /// "ai" drafts with the local model; "heuristic" uses the deterministic
    /// generator only. Absent means "ai, falling back to heuristic if the model
    /// is unreachable", which is the behaviour the console had before the
    /// choice was made explicit.
    #[serde(default)]
    mode: Option<String>,
}

async fn generate(
    State(state): State<Shared>,
    Json(body): Json<GenerateBody>,
) -> Result<Json<Value>, ApiError> {
    // Pasted lines win when both are supplied.
    let (samples, label) = match (&body.raw_log, &body.cluster_id) {
        (Some(raw), _) if !raw.trim().is_empty() => {
            let lines: Vec<String> = raw
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .take(20)
                .collect();
            (lines, "pasted".to_string())
        }
        (_, Some(id)) => {
            let s = lock(&state);
            let found = s
                .drain
                .ranked_clusters()
                .into_iter()
                .find(|c| &c.id == id)
                .map(|c| c.samples.clone())
                .unwrap_or_default();
            (found, id.clone())
        }
        _ => {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                "supply either raw_log or cluster_id".into(),
            ))
        }
    };

    if samples.is_empty() {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "no log lines to learn from".into(),
        ));
    }

    // The operator chooses the generator explicitly. A deployment with no GPU,
    // or one where an LLM is not permitted at all, must still be able to draft
    // a pack — so the deterministic path is a first-class option, not just a
    // failure mode.
    let mode = body.mode.as_deref().unwrap_or("auto");
    if mode == "heuristic" {
        return heuristic_draft(&samples, "requested");
    }
    if !matches!(mode, "auto" | "ai") {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("unknown mode '{mode}': expected 'ai' or 'heuristic'"),
        ));
    }

    let client = ulpf_generator::llm::GeneratorClient::from_env();

    // Probe first so an offline model gives an actionable message rather than
    // a 500 in front of whoever is watching the console.
    if let Err(error) = client.probe().await {
        // "ai" was asked for by name, so silently substituting a different
        // generator would misreport what produced the pack.
        if mode == "ai" {
            return Err(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "the local model is unreachable ({error}).                      Start Ollama, or choose the deterministic heuristic generator."
                ),
            ));
        }
        tracing::warn!(
            "LLM offline ({}). Falling back to deterministic heuristic generator.",
            error
        );
        return heuristic_draft(&samples, "llm-offline");
    }

    let pack = client
        .draft_pack(&label, &samples)
        .await
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e.to_string()))?;
    let source_profile = ulpf_generator::profile::analyze(&samples);

    // Grade the candidate against the samples it was drafted from, before a
    // human is asked to approve it.
    let score = ulpf_generator::scorer::Scorer::score(&pack);
    // A fixture only checks that a value reached the path the pack named; it
    // says nothing about whether that path is a real OCSF attribute. A model
    // is exactly the kind of author that invents a plausible-looking one.
    let unknown_ocsf_paths = ulpf_generator::ocsf_paths::unknown_paths(&pack);
    let pack_yaml = serde_yaml::to_string(&pack)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "pack_yaml": pack_yaml,
        "model": client.model(),
        "generator": "ai",
        "reason": "model-drafted",
        "fixtures": score.total,
        "fixtures_passed": score.passed,
        "field_accuracy": score.field_accuracy(),
        "unknown_ocsf_paths": unknown_ocsf_paths,
        "source_profile": source_profile,
    })))
}

/// Draft a pack with the rules-based generator.
///
/// Every sample is passed, not just the first: detector derivation needs more
/// than one line to tell fixed structure from per-record values, and a pack
/// with no detector loads but claims nothing.
fn heuristic_draft(samples: &[String], reason: &str) -> Result<Json<Value>, ApiError> {
    let raw_log = samples.join(
        "
",
    );
    let draft = ulpf_generator::heuristic::draft_pack(&raw_log)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "pack_yaml": draft.pack_yaml,
        "model": draft.model,
        "generator": "heuristic",
        "reason": reason,
        "fixtures": draft.fixtures,
        "fixtures_passed": draft.fixtures_passed,
        "field_accuracy": draft.field_accuracy,
        "unknown_ocsf_paths": draft.unknown_ocsf_paths,
        "source_profile": draft.source_profile,
    })))
}

#[derive(serde::Deserialize)]
struct ProofRequest {
    /// The event's attestation fingerprint, as shown in the event detail panel.
    fingerprint: String,
    #[serde(default)]
    event_uid: Option<String>,
}

/// Issue an inclusion proof for one event.
///
/// A checkpoint is forced first. Only leaves the last signed checkpoint commits
/// to can be proved, and on a live collector the event an operator just clicked
/// is usually newer than that. Signing one now costs a single Ed25519
/// signature and removes an otherwise baffling "wait a few seconds" failure.
async fn make_proof(
    State(state): State<Shared>,
    Json(body): Json<ProofRequest>,
) -> Result<Response, ApiError> {
    let mut s = lock(&state);

    if let Ok(Some(checkpoint)) = s.pipeline.checkpoint_now() {
        let leaves_path = s.merkle_leaves_path.clone();
        let checkpoint_path = s.checkpoint_path.clone();
        let leaves = s.pipeline.merkle_leaves().to_vec();
        crate::integrity_state::persist_leaves(&leaves_path, &leaves)
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        crate::integrity_state::persist_checkpoint(&checkpoint_path, &checkpoint)
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        s.latest_checkpoint = Some(checkpoint);
    }

    let checkpoint = s
        .latest_checkpoint
        .clone()
        .ok_or_else(|| ApiError(StatusCode::CONFLICT, "no signed checkpoint yet".into()))?;
    let leaves = s.pipeline.merkle_leaves()[..checkpoint.tree_size as usize].to_vec();
    let fingerprint = body.fingerprint.trim().to_ascii_lowercase();

    let bundle = crate::proof::build_bundle(
        ulpf_ocsf::HashAlgorithm::Sha256,
        &checkpoint,
        leaves,
        &fingerprint,
        body.event_uid,
    )
    .map_err(|e| ApiError(StatusCode::NOT_FOUND, e.to_string()))?;

    // The bundle is the whole body, pretty-printed, and the key path travels in
    // a header. Wrapping it in an envelope would force the console to parse the
    // response to dig the bundle out, and parsing is precisely what must not
    // happen: `created_time` is nanoseconds, past 2^53, so a JavaScript
    // round-trip rounds it and the signature stops matching. Handing back the
    // exact bytes lets the console show, copy and re-post them untouched.
    let body = serde_json::to_string_pretty(&bundle)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let key_path = s.public_key_path.display().to_string();

    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&key_path) {
        headers.insert(
            axum::http::HeaderName::from_static("x-ulpf-public-key"),
            value,
        );
    }
    Ok(response)
}

/// The bundle arrives as the raw request body rather than wrapped in a field.
///
/// A checkpoint's `created_time` is nanoseconds since the epoch, around
/// 1.8e18, which is far past the 2^53 that JavaScript can hold exactly. A
/// browser that parses the proof and re-serializes it silently rounds that
/// number and the signature stops matching — a valid proof rejected for a
/// reason nothing in the message would explain. Taking the body as-is means
/// the console can post the bytes it was given without ever parsing them.
type CheckProofRequest = crate::proof::ProofBundle;

/// Check a pasted proof against this collector's signed checkpoint.
///
/// Verifying here is a convenience, not the security claim: the point of a
/// proof is that someone else can check it with `ulpf verify-proof` and a
/// public key, holding nothing of this collector's.
async fn check_proof(
    State(state): State<Shared>,
    Json(body): Json<CheckProofRequest>,
) -> Result<Json<Value>, ApiError> {
    let bundle = body;

    // Verify against the checkpoint the proof carries, not this collector's
    // current one. The tree grows every few seconds, so a proof issued a moment
    // ago names an earlier tree size — checking it against the latest
    // checkpoint would reject a perfectly good proof. The embedded copy is
    // still only accepted once its signature checks out against the trusted
    // key below.
    let checkpoint = bundle.checkpoint.clone();
    let key_path = { lock(&state).public_key_path.clone() };

    let key = crate::integrity_state::read_public_key(&key_path)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let label = key_path.display().to_string();

    let outcome = crate::proof::check_bundle(&bundle, &checkpoint, Some(&key), Some(&label), None)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("{e:#}")))?;

    Ok(Json(serde_json::to_value(outcome).unwrap_or(json!({}))))
}

/// The corpora the simulator can replay, with live per-stream counters.
async fn sim_sources(State(state): State<Shared>) -> Json<Value> {
    let s = lock(&state);
    Json(json!({
        "target": s.simulator.target(),
        "data_dir": s.simulator.data_dir().display().to_string(),
        "running": s.simulator.running_count(),
        "total_sent": s.simulator.total_sent(),
        "sources": s.simulator.status(),
    }))
}

#[derive(serde::Deserialize)]
struct SimToggleBody {
    id: String,
    on: bool,
    #[serde(default)]
    eps: Option<u64>,
}

/// Flip one source on or off.
async fn sim_toggle(
    State(state): State<Shared>,
    Json(body): Json<SimToggleBody>,
) -> Result<Json<Value>, ApiError> {
    let mut s = lock(&state);
    if body.on {
        // A missing corpus is the operator's problem to fix, not a server
        // fault, so it comes back as 400 with the fetch command in the text.
        s.simulator
            .start(&body.id, body.eps.unwrap_or(20))
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    } else {
        s.simulator.stop(&body.id);
    }
    Ok(Json(json!({
        "ok": true,
        "running": s.simulator.running_count(),
        "sources": s.simulator.status(),
    })))
}

#[derive(serde::Deserialize)]
struct SimTargetBody {
    target: String,
}

/// Change the simulator destination. Restarts any running streams.
async fn sim_target(
    State(state): State<Shared>,
    Json(body): Json<SimTargetBody>,
) -> Result<Json<Value>, ApiError> {
    let mut s = lock(&state);
    s.simulator.set_target(&body.target);
    Ok(Json(json!({
        "ok": true,
        "target": s.simulator.target(),
        "running": s.simulator.running_count(),
        "sources": s.simulator.status(),
    })))
}

async fn sim_stop_all(State(state): State<Shared>) -> Json<Value> {
    let mut s = lock(&state);
    s.simulator.stop_all();
    Json(json!({ "ok": true, "sources": s.simulator.status() }))
}

#[derive(serde::Deserialize)]
struct ChatBody {
    messages: Vec<ulpf_generator::llm::ChatMessage>,
}

const MAX_CHAT_TURNS: usize = 24;

/// Free-form conversation with the local model.
///
/// A system message describes what ULPF is and, importantly, what is happening
/// in *this* collector right now — packs loaded, coverage, unparsed clusters —
/// so the assistant can answer questions about the operator's own data rather
/// than only in generalities.
async fn chat(
    State(state): State<Shared>,
    Json(body): Json<ChatBody>,
) -> Result<Json<Value>, ApiError> {
    if body.messages.is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "no messages".into()));
    }

    let context = {
        let s = lock(&state);
        let st = &s.pipeline.stats;
        let packs: Vec<String> = s
            .pipeline
            .packs()
            .iter()
            .map(|p| format!("{} ({} {})", p.id, p.vendor, p.product))
            .collect();
        let clusters: Vec<String> = s
            .drain
            .ranked_clusters()
            .into_iter()
            .take(5)
            .map(|c| format!("{} x{} :: {}", c.id, c.count, c.template.join(" ")))
            .collect();

        // The most recent events, in full enough detail to answer "what did you
        // just parse?". Without these the assistant only has counts, and had to
        // say it could not see any logs - which was true, and unhelpful.
        let recent: Vec<String> = s
            .recent
            .iter()
            .rev()
            .take(6)
            .map(|r| {
                let e = &r.event;
                let get = |p: &str| {
                    e.get_path(p)
                        .and_then(|v| {
                            v.as_str()
                                .map(str::to_string)
                                .or_else(|| v.as_i64().map(|n| n.to_string()))
                        })
                        .unwrap_or_else(|| "-".into())
                };
                format!(
                    "[{}] pack={} class={} {}:{} -> {}:{} proto={} raw={}",
                    r.disposition,
                    r.pack.clone().unwrap_or_else(|| "none".into()),
                    e.class_uid().unwrap_or(0),
                    get("src_endpoint.ip"),
                    get("src_endpoint.port"),
                    get("dst_endpoint.ip"),
                    get("dst_endpoint.port"),
                    get("connection_info.protocol_name"),
                    e.get_path("raw_data")
                        .and_then(|v| v.as_str())
                        .map(|t| t.chars().take(160).collect::<String>())
                        .unwrap_or_else(|| "(not inlined)".into()),
                )
            })
            .collect();
        format!(
            "You are the assistant built into ULPF, a log pre-processing tool for the              Smart India Hackathon problem statement 26156 (NTRO).

             What ULPF does: it accepts logs from any perimeter device, stores the exact              original bytes in an append-only vault before parsing anything, identifies the              source using declarative YAML 'Source Packs', extracts fields with a decoder              chain, normalises to the OCSF 1.9 schema, and chains every event with a              SHA-256 fingerprint so tampering is detectable.

             Decoders available: syslog, keyvalue, csv, cef, leef, json, xml, regex.
             Common OCSF targets: src_endpoint.ip, src_endpoint.port, dst_endpoint.ip,              dst_endpoint.port, connection_info.protocol_name, device.hostname,              actor.user.name, url, message.

             LIVE STATE OF THIS COLLECTOR:
             - events received: {received}, normalised: {parsed} ({coverage:.2}% coverage)
             - unidentified: {unid}
             - source packs loaded ({npacks}): {packs}
             - top unparsed clusters: {clusters}
             - the {nrecent} most recent events (newest first):
{recent}

             RULES FOR YOUR ANSWERS:
             1. Never repeat a sentence. Say a thing once and stop.
             2. Default to two or three sentences. Expand only if asked.
             3. When asked about recent or latest logs, quote the actual events listed              above - they are real records this collector processed.
             4. Do not confuse an unparsed cluster template with a parsed event.
             5. If something is genuinely outside what you can see, say so in one line              and suggest what would answer it.
             6. When given a log line, explain what it is, which decoders read it, and              which OCSF attributes its values map to.",
            received = st.received,
            parsed = st.parsed,
            coverage = st.coverage() * 100.0,
            unid = st.unidentified,
            npacks = packs.len(),
            packs = packs.join(", "),
            clusters = if clusters.is_empty() {
                "none".to_string()
            } else {
                clusters.join(" | ")
            },
            nrecent = recent.len(),
            recent = if recent.is_empty() {
                "  (nothing ingested yet)".to_string()
            } else {
                recent
                    .iter()
                    .map(|r| format!("  {r}"))
                    .collect::<Vec<_>>()
                    .join("
")
            },
        )
    };

    let client = ulpf_generator::llm::GeneratorClient::from_env();
    if let Err(error) = client.probe().await {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "No local model reachable at {}. Start Ollama, or set ULPF_LLM_ENDPOINT. ({error})",
                client.endpoint()
            ),
        ));
    }

    // Keep only the recent turns so a long session cannot outgrow the context
    // window; the system message is always re-sent.
    let mut thread = vec![ulpf_generator::llm::ChatMessage {
        role: "system".into(),
        content: context,
    }];
    let start = body.messages.len().saturating_sub(MAX_CHAT_TURNS);
    thread.extend(body.messages[start..].iter().cloned());

    let reply = client
        .chat(&thread)
        .await
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(json!({ "reply": reply, "model": client.model() })))
}

#[derive(serde::Deserialize)]
struct ApproveBody {
    yaml: String,
}

/// Reduce a pack id to a single safe filename stem.
///
/// The id arrives in the request body, and it used to be joined onto the packs
/// directory verbatim. `Path::join` *replaces* the base when handed an absolute
/// path, so an id of `C:/anywhere/evil` — or one containing `../` — wrote a
/// file of the caller's choosing anywhere the process could reach. The console
/// has no authentication, so any page the operator had open could reach it.
///
/// Everything outside a conservative filename alphabet becomes `_`, and the
/// result is rejected if nothing usable survives.
fn safe_pack_stem(id: &str) -> Result<String, ApiError> {
    let stem: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();

    // `.`, `..` and a leading dot are filenames too, and none of them are a
    // pack. Trim to something that can only ever name a file in this directory.
    let stem = stem.trim_matches('.').to_string();
    if stem.is_empty() || stem.len() > 128 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("identity.id `{id}` does not reduce to a usable pack filename"),
        ));
    }
    Ok(stem)
}

async fn approve(
    State(state): State<Shared>,
    Json(body): Json<ApproveBody>,
) -> Result<Json<Value>, ApiError> {
    let mut pack: ulpf_pack::Pack = serde_yaml::from_str(&body.yaml)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("invalid YAML: {e}")))?;

    // Compile before writing. A pack that cannot compile would land in the live
    // directory, fail to load on the next hot reload, and leave the operator
    // looking at a pack list that silently disagrees with the folder.
    ulpf_pack::CompiledPack::compile(pack.clone()).map_err(|e| {
        ApiError(
            StatusCode::BAD_REQUEST,
            format!("pack does not compile: {e}"),
        )
    })?;

    // Compiling only proves the pack is well-formed. Approving activates it for
    // live traffic, so it also has to pass its own fixtures: a pack that cannot
    // even claim its own sample line compiles perfectly well and then claims
    // nothing in production.
    let report = ulpf_generator::scorer::Scorer::score(&pack);
    if report.total == 0 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "pack has no fixtures, so it cannot be validated before activation".into(),
        ));
    }
    if report.passed != report.total {
        let detail = report
            .failures
            .iter()
            .take(3)
            .map(|f| format!("fixture {}: {} — {}", f.fixture, f.path, f.detail))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!(
                "pack fails its own fixtures ({}/{} passed) and was not activated. {detail}",
                report.passed, report.total
            ),
        ));
    }

    let id = pack.identity.id.clone();
    let stem = safe_pack_stem(&id)?;

    if let Some(prov) = &mut pack.provenance {
        prov.approved_by = Some("console operator".to_string());
    }

    let packs_dir = lock(&state).packs_dir.clone();
    let file_path = packs_dir.join(format!("{stem}.yaml"));

    let yaml_out = serde_yaml::to_string(&pack)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    std::fs::write(&file_path, yaml_out).map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not write {}: {e}", file_path.display()),
        )
    })?;

    // The filesystem watcher picks the file up; report where it landed so the
    // operator can find it.
    Ok(Json(json!({
        "ok": true,
        "id": id,
        "file": file_path.display().to_string(),
        "fixtures": report.total,
        "fixtures_passed": report.passed,
    })))
}

/// Condense an event into the columns the console table shows.
fn summarize(r: &RecentEvent) -> Value {
    let e = r.event.as_map();
    let get = |path: &str| r.event.get_path(path).cloned().unwrap_or(Value::Null);
    json!({
        "uid": r.event.uid(),
        "vendor": get("metadata.product.vendor_name"),
        "product": get("metadata.product.name"),
        "log_format": get("metadata.log_format"),
        "class_uid": e.get("class_uid"),
        "activity_id": e.get("activity_id"),
        "type_uid": e.get("type_uid"),
        "severity_id": e.get("severity_id"),
        "time": e.get("time"),
        "src_ip": get("src_endpoint.ip"),
        "src_port": get("src_endpoint.port"),
        "dst_ip": get("dst_endpoint.ip"),
        "dst_port": get("dst_endpoint.port"),
        "disposition": r.disposition,
        "pack": r.pack,
        "locator": r.locator,
        "event": r.event.to_value(),
    })
}

#[derive(serde::Deserialize)]
struct IngestBody {
    lines: String,
}

/// Run one or more raw lines through the real pipeline.
async fn ingest(
    State(state): State<Shared>,
    Json(body): Json<IngestBody>,
) -> Result<Json<Value>, ApiError> {
    let mut s = lock(&state);
    let mut results = Vec::new();
    let line_count = body
        .lines
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    if line_count > MAX_INGEST_LINES {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request contains {line_count} records; maximum is {MAX_INGEST_LINES}"),
        ));
    }

    for line in body.lines.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let envelope = Envelope::new(Transport::Http, "console");

        // Capture the intermediate stages before processing, so the UI can show
        // *why* a line normalized the way it did rather than only the result.
        let identified = s.pipeline.packs().identify(line).map(|p| p.id.clone());
        let extracted = match s.pipeline.packs().identify(line) {
            Some(pack) => pack.extract(line).ok().map(|fields| {
                fields
                    .iter()
                    .map(|(k, v)| (k.to_string(), field_value_json(v)))
                    .collect::<serde_json::Map<String, Value>>()
            }),
            None => None,
        };

        let processed = s.pipeline.process(line.as_bytes(), &envelope)?;
        let recent = RecentEvent {
            event: processed.event.clone(),
            disposition: processed.disposition.label().to_string(),
            pack: processed.disposition.pack_id().map(str::to_string),
            locator: processed.raw_ref.to_locator(),
        };

        let source_profile = if identified.is_none() {
            Some(ulpf_generator::profile::analyze(&[line.to_string()]))
        } else {
            None
        };
        results.push(json!({
            "raw": line,
            "identified_pack": identified,
            "extracted": extracted,
            "source_profile": source_profile,
            "disposition": recent.disposition,
            "locator": recent.locator,
            "event": processed.event.to_value(),
            "summary": summarize(&recent),
        }));

        if !processed.disposition.is_parsed() {
            s.drain.process(line);
        }

        s.recent.push(recent);
        if s.recent.len() > RECENT_CAPACITY {
            let excess = s.recent.len() - RECENT_CAPACITY;
            let predecessor = &s.recent[excess - 1].event;
            let fingerprint = ulpf_ocsf::verify_event(predecessor)?;
            s.chain_anchor = Some(ulpf_ocsf::ChainLink {
                uid: predecessor.uid().unwrap_or_default().to_string(),
                type_uid: predecessor.type_uid(),
                fingerprint,
            });
            s.recent.drain(..excess);
        }
    }

    // Flush so the locators just handed out are immediately retrievable.
    let checkpoint = s.pipeline.checkpoint_now()?;
    if let Some(checkpoint) = &checkpoint {
        crate::integrity_state::persist_checkpoint(&s.checkpoint_path, checkpoint)?;
    }
    s.latest_checkpoint = checkpoint.clone();
    Ok(Json(json!({
        "results": results,
        "checkpoint": checkpoint,
    })))
}

fn field_value_json(v: &ulpf_core::Value<'_>) -> Value {
    match v {
        ulpf_core::Value::Str(s) => Value::String(s.to_string()),
        ulpf_core::Value::Int(i) => json!(i),
        ulpf_core::Value::Float(f) => json!(f),
        ulpf_core::Value::Bool(b) => json!(b),
        ulpf_core::Value::Null => Value::Null,
    }
}

/// Retrieve the original bytes behind a locator.
async fn raw(
    State(state): State<Shared>,
    Path(locator): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let raw_ref = RawRef::from_locator(&locator)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    let (dir, vault_key) = {
        let s = lock(&state);
        (s.vault_dir.clone(), s.vault_key)
    };

    let mut reader = match vault_key {
        Some(key) => VaultReader::open_with_key(&dir, key),
        None => VaultReader::open(&dir),
    };
    let bytes = reader
        .get(raw_ref)
        .map_err(|e| ApiError(StatusCode::NOT_FOUND, e.to_string()))?;

    // Recompute the fingerprint over what came back out of the vault. The
    // event carries the fingerprint recorded at ingest, so the UI can compare
    // the two and show that the retrieved bytes are provably the originals —
    // which holds whether or not the raw text was inlined into the event.
    let algorithm = {
        let s = lock(&state);
        s.recent
            .iter()
            .find(|event| event.locator == locator)
            .and_then(|event| event.event.get_path("raw_data_hash.algorithm_id"))
            .and_then(Value::as_u64)
            .map(|id| {
                if id == 99 {
                    ulpf_ocsf::types::HashAlgorithm::Blake3
                } else {
                    ulpf_ocsf::types::HashAlgorithm::Sha256
                }
            })
            .unwrap_or_default()
    };
    let recomputed = ulpf_ocsf::types::Fingerprint::over_raw(algorithm, &bytes);

    Ok(Json(json!({
        "locator": locator,
        "bytes": bytes.len(),
        "text": String::from_utf8_lossy(&bytes),
        "recomputed_hash": recomputed.value,
    })))
}

/// Verify the chain over everything currently in the console buffer.
async fn verify(State(state): State<Shared>) -> Json<Value> {
    let s = lock(&state);
    let events: Vec<OcsfEvent> = s.recent.iter().map(|r| r.event.clone()).collect();
    if events.is_empty() {
        return Json(json!({ "ok": false, "detail": "no events to verify" }));
    }
    match ulpf_ocsf::verify_chain_from(&events, s.chain_anchor.as_ref()) {
        Ok(head) => Json(json!({
            "ok": true,
            "count": events.len(),
            "head_uid": head.as_ref().map(|h| h.uid.clone()),
            "head_fingerprint": head.map(|h| h.fingerprint.value),
            // Two separate facts. The signature is either good or it is not,
            // and that is the security property. Whether the checkpoint also
            // names the current head is just a question of how recently one
            // was written — checkpoints are periodic, so between intervals a
            // perfectly valid checkpoint necessarily trails the live head.
            // Reporting a single "valid" flag conflated the two and made a
            // healthy chain look broken for 499 events out of every 500.
            "checkpoint_signature_valid": s
                .latest_checkpoint
                .as_ref()
                .is_some_and(|checkpoint| checkpoint.verify_self_signed().is_ok()),
            "checkpoint_at_head": s.latest_checkpoint.as_ref().is_some_and(|checkpoint| {
                s.pipeline.chain_head().is_some_and(|head| {
                    checkpoint.head_uid == head.uid && checkpoint.head == head.fingerprint
                })
            }),
        })),
        Err(e) => Json(json!({ "ok": false, "count": events.len(), "detail": e.to_string() })),
    }
}

/// Clear the bounded UI window without resetting counters, vault data, or the
/// cryptographic chain. The next retained event is anchored to the current
/// head, so verification remains meaningful after a clear.
async fn clear(State(state): State<Shared>) -> Result<Json<Value>, ApiError> {
    let mut s = lock(&state);
    s.chain_anchor = s.pipeline.chain_head().cloned();
    s.recent.clear();
    Ok(Json(json!({ "ok": true })))
}

#[derive(serde::Deserialize)]
struct TamperBody {
    /// Index into the console buffer, newest first, matching the table order.
    index: usize,
    path: String,
    value: String,
}

/// Alter one buffered event in place, so the UI can show verification failing.
///
/// This mutates only the console's in-memory copy. The vault is append-only and
/// is not touched, which is the point: the original bytes remain retrievable and
/// provably different from the doctored event.
async fn tamper(
    State(state): State<Shared>,
    Json(body): Json<TamperBody>,
) -> Result<Json<Value>, ApiError> {
    let mut s = lock(&state);
    let len = s.recent.len();
    if body.index >= len {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("no event at index {}", body.index),
        ));
    }
    // The table renders newest-first; translate to buffer order.
    let idx = len - 1 - body.index;
    let before = s.recent[idx]
        .event
        .get_path(&body.path)
        .cloned()
        .unwrap_or(Value::Null);

    s.recent[idx]
        .event
        .set_path(&body.path, Value::String(body.value.clone()))
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Json(json!({
        "uid": s.recent[idx].event.uid(),
        "path": body.path,
        "before": before,
        "after": body.value,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but real `AppState`, backed by a throwaway vault directory,
    /// so these tests exercise the actual router — middleware stack included
    /// — rather than the auth helper functions in isolation.
    fn test_state() -> (Shared, tempfile_shim::TempDir) {
        let dir = tempfile_shim::TempDir::new("ulpf-server-test");
        let vault = ulpf_vault::VaultWriter::open(dir.path().join("vault")).unwrap();
        let attestor = ulpf_ocsf::Attestor::new("test-authority", "test-chain");
        let pipeline = Pipeline::new(Arc::new(ulpf_pack::PackLibrary::new()), vault, attestor);
        let state = Arc::new(Mutex::new(AppState {
            pipeline,
            recent: Vec::new(),
            chain_anchor: None,
            latest_checkpoint: None,
            checkpoint_path: dir.path().join("chain.checkpoint.json"),
            merkle_leaves_path: dir.path().join("chain.merkle-leaves.bin"),
            public_key_path: dir.path().join("ed25519-signing.pub"),
            vault_dir: dir.path().join("vault"),
            packs_dir: dir.path().join("packs"),
            drain: ulpf_generator::drain::Drain::new(),
            cluster_profiles: HashMap::new(),
            simulator: crate::simulator::Simulator::new(
                dir.path().join("datasets"),
                "127.0.0.1:5514".into(),
            ),
            vault_key: None,
        }));
        (state, dir)
    }

    async fn call(app: Router, req: Request) -> StatusCode {
        use tower::ServiceExt;
        app.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn a_request_with_no_token_is_rejected() {
        let (state, _dir) = test_state();
        let app = router(state, None, Some(Arc::from("secret-token")));
        let req = Request::builder()
            .uri("/api/stats")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(call(app, req).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_request_with_the_wrong_token_is_rejected() {
        let (state, _dir) = test_state();
        let app = router(state, None, Some(Arc::from("secret-token")));
        let req = Request::builder()
            .uri("/api/stats")
            .header(header::AUTHORIZATION, "Bearer not-the-token")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(call(app, req).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_request_with_the_right_token_succeeds() {
        let (state, _dir) = test_state();
        let app = router(state, None, Some(Arc::from("secret-token")));
        let req = Request::builder()
            .uri("/api/stats")
            .header(header::AUTHORIZATION, "Bearer secret-token")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(call(app, req).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_x_ulpf_token_header_is_also_accepted() {
        let (state, _dir) = test_state();
        let app = router(state, None, Some(Arc::from("secret-token")));
        let req = Request::builder()
            .uri("/api/stats")
            .header("x-ulpf-token", "secret-token")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(call(app, req).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn health_and_ready_probes_need_no_token() {
        let (state, _dir) = test_state();
        let app = router(state, None, Some(Arc::from("secret-token")));
        let req = Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(call(app, req).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_page_shell_needs_no_token_but_the_api_underneath_still_does() {
        // Regression test: `/` and `/dev` used to sit behind the same guard
        // as `/api/*`, so a token-less first visit — the only kind there is,
        // before the page's own script has anywhere to store one — got the
        // same bare 401 the API returns, and the page's `window.prompt()`
        // token flow never got a chance to run at all.
        let (state, _dir) = test_state();
        let app = router(state, None, Some(Arc::from("secret-token")));

        let index_req = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(call(app.clone(), index_req).await, StatusCode::OK);

        let dev_req = Request::builder()
            .uri("/dev")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(call(app.clone(), dev_req).await, StatusCode::OK);

        let api_req = Request::builder()
            .uri("/api/stats")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(call(app, api_req).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn no_token_configured_means_no_check_at_all() {
        // The `--no-auth` escape hatch: `None` disables the layer entirely
        // rather than requiring an empty string to match.
        let (state, _dir) = test_state();
        let app = router(state, None, None);
        let req = Request::builder()
            .uri("/api/stats")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(call(app, req).await, StatusCode::OK);
    }

    /// A tiny self-cleaning temp directory, so these tests do not depend on a
    /// dev-dependency the rest of the crate has no other use for.
    mod tempfile_shim {
        use std::path::{Path, PathBuf};

        pub struct TempDir(PathBuf);
        impl TempDir {
            pub fn new(tag: &str) -> Self {
                let dir = std::env::temp_dir().join(format!(
                    "{tag}-{}-{:?}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&dir).unwrap();
                Self(dir)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    /// The Host check is what stops DNS rebinding, so its edge cases matter:
    /// too strict and a hand-typed `localhost:8787` is refused, too loose and
    /// an attacker's hostname on the right port is accepted.
    #[test]
    fn loopback_names_are_equivalent_only_on_the_same_port() {
        for host in ["localhost:8787", "127.0.0.1:8787", "[::1]:8787"] {
            assert!(
                loopback_equivalent(host, "127.0.0.1:8787"),
                "{host} names this machine"
            );
        }
        assert!(
            !loopback_equivalent("localhost:9999", "127.0.0.1:8787"),
            "a different port is a different service"
        );
        assert!(
            !loopback_equivalent("attacker.example.com:8787", "127.0.0.1:8787"),
            "a rebound hostname must not pass"
        );
        assert!(
            !loopback_equivalent("127.0.0.1.evil.com:8787", "127.0.0.1:8787"),
            "a suffix attack must not pass"
        );
    }
}
