//! `ulpf` — the Universal Log Pre-processing Framework command line.

mod features;
mod generator;
mod integrity_state;
mod parquet;
mod pipeline;
mod proof;
mod replay;
mod server;
mod simulator;
mod sinks;
mod watcher;

use std::io::{BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use ulpf_core::{Envelope, RawRef, Transport};
use ulpf_ocsf::types::HashAlgorithm;
use ulpf_ocsf::OcsfEvent;
use ulpf_pack::PackLibrary;
use ulpf_vault::{VaultReader, VaultWriter};

use pipeline::Pipeline;

const COMMIT_BATCH_SIZE: usize = 8_192;

struct PendingOutput {
    processed: pipeline::Processed,
    raw: Vec<u8>,
    received_at: i64,
}

struct RunOptions {
    packs_dir: PathBuf,
    vault_dir: PathBuf,
    input: String,
    output: String,
    blake3: bool,
    chain: String,
    integrity_dir: PathBuf,
    inline_raw: bool,
    dead_letter: Option<PathBuf>,
    parquet: Option<PathBuf>,
    features: Option<PathBuf>,
    opensearch: Option<String>,
    opensearch_index: String,
    splunk_hec: Option<String>,
    splunk_token_env: String,
    sink_batch_size: usize,
}

struct ListenOptions {
    packs_dir: PathBuf,
    vault_dir: PathBuf,
    integrity_dir: PathBuf,
    bind: String,
    output: String,
    chain: String,
    blake3: bool,
    inline_raw: bool,
}

#[derive(Parser)]
#[command(
    name = "ulpf",
    version,
    about = "Universal Log Pre-processing Framework — any log in, OCSF out, nothing lost"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ingest logs, normalize to OCSF, and write NDJSON.
    Run {
        /// Directory of Source Pack YAML files.
        #[arg(long, default_value = "packs")]
        packs: PathBuf,
        /// Raw vault directory.
        #[arg(long, default_value = "data/vault")]
        vault: PathBuf,
        /// Input file, or `-` for stdin.
        #[arg(long, short, default_value = "-")]
        input: String,
        /// Output NDJSON file, or `-` for stdout.
        #[arg(long, short, default_value = "-")]
        output: String,
        /// Use BLAKE3 instead of SHA-256 for fingerprints.
        #[arg(long)]
        blake3: bool,
        /// Chain identifier, for resuming an existing attestation chain.
        #[arg(long, default_value = "default")]
        chain: String,
        /// Persistent Ed25519 key and signed chain checkpoints.
        #[arg(long, default_value = "data/integrity")]
        integrity_dir: PathBuf,
        /// Carry the full original text in every event's `raw_data`.
        ///
        /// Off by default: the vault holds the bytes and each event carries a
        /// locator and fingerprint for them, so inlining roughly doubles the
        /// output for no extra forensic guarantee. Turn it on when events are
        /// leaving for a SIEM that will not have vault access.
        #[arg(long)]
        inline_raw: bool,
        /// Write unparsed events here, one JSON object per line.
        ///
        /// This is the dead-letter stream: the ranked input to template
        /// clustering, and the queue that decides which pack to write next.
        #[arg(long)]
        dead_letter: Option<PathBuf>,
        /// Write a self-contained Parquet archive with event_json and OCSF
        /// scalar columns.
        #[arg(long)]
        parquet: Option<PathBuf>,
        /// Write the columnar feature table, for analytics and model training.
        /// Its column contract is fixed; see docs/FEATURE_TABLE.md.
        #[arg(long)]
        features: Option<PathBuf>,
        /// OpenSearch base URL. Uses `/_bulk`; HTTP is intended for a trusted
        /// local proxy or lab endpoint.
        #[arg(long)]
        opensearch: Option<String>,
        /// OpenSearch index used by the bulk sink.
        #[arg(long, default_value = "ulpf-events")]
        opensearch_index: String,
        /// Splunk HEC URL, for example `http://127.0.0.1:8088/services/collector`.
        #[arg(long)]
        splunk_hec: Option<String>,
        /// Environment variable containing the Splunk HEC token.
        #[arg(long, default_value = "ULPF_SPLUNK_HEC_TOKEN")]
        splunk_token_env: String,
        /// Maximum events held by each remote sink before a request is sent.
        #[arg(long, default_value_t = 250)]
        sink_batch_size: usize,
    },

    /// Cluster dead-letter records and draft human-reviewable Source Packs.
    Draft {
        /// Dead-letter NDJSON produced by `ulpf run --dead-letter`.
        #[arg(long)]
        dead_letter: PathBuf,
        /// Directory where candidate YAML files and manifest.json are written.
        #[arg(long, default_value = "data/candidates")]
        output: PathBuf,
        /// Maximum number of template clusters to draft.
        #[arg(long, default_value_t = 20)]
        max_clusters: usize,
        /// Representative fixtures to include in each candidate.
        #[arg(long, default_value_t = 5)]
        examples_per_cluster: usize,
        /// Optional local executable that receives a JSON draft request on
        /// stdin and returns one Source Pack YAML document on stdout.
        #[arg(long)]
        sidecar: Option<PathBuf>,
    },

    /// Run every pack's own fixtures and report coverage.
    Test {
        #[arg(long, default_value = "packs")]
        packs: PathBuf,
    },

    /// Retrieve an original event from the vault by its locator.
    Raw {
        #[arg(long, default_value = "data/vault")]
        vault: PathBuf,
        /// Locator, as carried in `unmapped.ulpf_raw_locator`.
        locator: String,
    },

    /// Verify the attestation chain over a normalized NDJSON stream.
    Verify {
        /// NDJSON file produced by `ulpf run`, or `-` for stdin.
        #[arg(default_value = "-")]
        input: String,
        /// Signed checkpoint produced by the same run/chain.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        /// Trusted Ed25519 public key (hex). Stronger than trusting the key
        /// embedded in the checkpoint itself.
        #[arg(long)]
        public_key: Option<PathBuf>,
    },

    /// Prove one event is in the chain's Merkle tree.
    Prove {
        #[arg(long, default_value = "data/integrity")]
        integrity_dir: PathBuf,
        /// Chain the event belongs to.
        #[arg(long, default_value = "default")]
        chain: String,
        /// JSON file holding the single OCSF event to prove.
        #[arg(long)]
        event: Option<PathBuf>,
        /// Alternatively, the event's attestation fingerprint.
        #[arg(long)]
        fingerprint: Option<String>,
        /// The chain was written with BLAKE3 rather than SHA-256.
        #[arg(long)]
        blake3: bool,
    },

    /// Bridge an older tree size to the one the current checkpoint signs.
    ///
    /// An inclusion proof only reproduces the root it was issued under, so a
    /// log that keeps growing would strand every proof already handed out.
    /// This emits the hashes that show the older tree is an unmodified prefix
    /// of today's, which `verify-proof --consistency` then checks.
    Consistency {
        #[arg(long, default_value = "data/integrity")]
        integrity_dir: PathBuf,
        #[arg(long, default_value = "default")]
        chain: String,
        /// Tree size the older proof was issued against, from its `tree_size`.
        #[arg(long)]
        from: u64,
        /// The chain was written with BLAKE3 rather than SHA-256.
        #[arg(long)]
        blake3: bool,
    },

    /// Check an inclusion proof against a signed checkpoint.
    ///
    /// Reads only the files given: no vault, no chain, no other event.
    VerifyProof {
        #[arg(long)]
        proof: PathBuf,
        /// Signed checkpoint to check against. Optional: the proof carries the
        /// one it was made against, which is what makes it self-contained.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        /// Trusted Ed25519 public key. Without it the checkpoint is only
        /// checked against the key it carries, which proves far less.
        #[arg(long)]
        public_key: Option<PathBuf>,
        /// Also confirm this event is the one the proof is about.
        #[arg(long)]
        event: Option<PathBuf>,
        /// Bridge from `ulpf consistency`, when the log has grown since the
        /// proof was issued.
        #[arg(long)]
        consistency: Option<PathBuf>,
    },

    /// Probe a running collector's readiness endpoint. Exits non-zero if it
    /// is not ready.
    ///
    /// Exists because the runtime image is distroless: no shell, no curl, so
    /// the container HEALTHCHECK has nothing else to call.
    Healthcheck {
        #[arg(long, default_value = "http://127.0.0.1:8787/readyz")]
        url: String,
        /// Seconds to wait before treating the probe as failed.
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },

    /// Serve the operator console on http://127.0.0.1:PORT.
    Serve {
        #[arg(long, default_value = "packs")]
        packs: PathBuf,
        #[arg(long, default_value = "data/vault")]
        vault: PathBuf,
        #[arg(long, default_value = "data/integrity")]
        integrity_dir: PathBuf,
        #[arg(long, default_value = "console")]
        chain: String,
        /// Interface to bind. Keep the default for local-only access; use
        /// 0.0.0.0 explicitly inside a container or trusted lab network.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, short, default_value_t = 8787)]
        port: u16,
        /// Socket the UDP syslog receiver binds. Configurable so two
        /// collectors can share a host, which is what the horizontal-scale
        /// deployment needs.
        #[arg(long, default_value = "0.0.0.0:5514")]
        syslog_bind: String,
        /// OpenSearch base URL.
        #[arg(long)]
        opensearch: Option<String>,
        /// OpenSearch index used by the bulk sink.
        #[arg(long, default_value = "ulpf-events")]
        opensearch_index: String,
        /// Splunk HEC URL.
        #[arg(long)]
        splunk_hec: Option<String>,
        /// Environment variable containing the Splunk HEC token.
        #[arg(long, default_value = "ULPF_SPLUNK_HEC_TOKEN")]
        splunk_token_env: String,
        /// Write a self-contained Parquet archive of whole OCSF documents.
        #[arg(long)]
        parquet: Option<PathBuf>,
        /// Write the columnar feature table, for analytics and model training.
        /// Its column contract is fixed; see docs/FEATURE_TABLE.md.
        #[arg(long)]
        features: Option<PathBuf>,
        /// Maximum events held by each remote sink before a request is sent.
        #[arg(long, default_value_t = 250)]
        sink_batch_size: usize,
        /// Directory holding the public corpora the /dev simulator replays.
        #[arg(long, default_value = "../realdata")]
        datasets: PathBuf,
        /// Where the /dev simulator sends its UDP traffic.
        #[arg(long, default_value = "127.0.0.1:5514")]
        sim_target: String,
    },

    /// Receive real RFC 5424/RFC 3164 syslog datagrams over UDP.
    Listen {
        #[arg(long, default_value = "packs")]
        packs: PathBuf,
        #[arg(long, default_value = "data/vault")]
        vault: PathBuf,
        #[arg(long, default_value = "data/integrity")]
        integrity_dir: PathBuf,
        /// Socket address to bind. Port 5514 avoids administrator privileges.
        #[arg(long, default_value = "0.0.0.0:5514")]
        bind: String,
        #[arg(long, short, default_value = "data/syslog.ndjson")]
        output: String,
        #[arg(long, default_value = "syslog-udp")]
        chain: String,
        #[arg(long)]
        blake3: bool,
        #[arg(long)]
        inline_raw: bool,
    },

    /// List the built-in decoders a pack may use.
    Decoders,

    /// Replay raw logs over UDP to simulate a device.
    Replay {
        /// Source file containing raw logs.
        #[arg(long)]
        source: PathBuf,
        /// Target IP and port (e.g., 127.0.0.1:5514).
        #[arg(long, default_value = "127.0.0.1:5514")]
        target: String,
        /// Events per second.
        #[arg(long, default_value_t = 10)]
        eps: u64,
        /// Stop after this many events instead of looping forever.
        #[arg(long)]
        count: Option<u64>,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ulpf=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Run {
            packs,
            vault,
            input,
            output,
            blake3,
            chain,
            integrity_dir,
            inline_raw,
            dead_letter,
            parquet,
            features,
            opensearch,
            opensearch_index,
            splunk_hec,
            splunk_token_env,
            sink_batch_size,
        } => cmd_run(RunOptions {
            packs_dir: packs,
            vault_dir: vault,
            input,
            output,
            blake3,
            chain,
            integrity_dir,
            inline_raw,
            dead_letter,
            parquet,
            features,
            opensearch,
            opensearch_index,
            splunk_hec,
            splunk_token_env,
            sink_batch_size,
        }),
        Command::Draft {
            dead_letter,
            output,
            max_clusters,
            examples_per_cluster,
            sidecar,
        } => generator::draft(
            &dead_letter,
            &output,
            max_clusters,
            examples_per_cluster,
            sidecar.as_deref(),
        ),
        Command::Test { packs } => cmd_test(packs),
        Command::Raw { vault, locator } => cmd_raw(vault, &locator),
        Command::Verify {
            input,
            checkpoint,
            public_key,
        } => cmd_verify(&input, checkpoint.as_deref(), public_key.as_deref()),
        Command::Prove {
            integrity_dir,
            chain,
            event,
            fingerprint,
            blake3,
        } => proof::cmd_prove(
            &integrity_dir,
            &chain,
            event.as_deref(),
            fingerprint.as_deref(),
            blake3,
        ),
        Command::Consistency {
            integrity_dir,
            chain,
            from,
            blake3,
        } => proof::cmd_consistency(&integrity_dir, &chain, from, blake3),
        Command::VerifyProof {
            proof: proof_path,
            checkpoint,
            public_key,
            event,
            consistency,
        } => proof::cmd_verify_proof(
            &proof_path,
            checkpoint.as_deref(),
            public_key.as_deref(),
            event.as_deref(),
            consistency.as_deref(),
        ),
        Command::Healthcheck { url, timeout } => cmd_healthcheck(&url, timeout),
        Command::Serve {
            packs,
            vault,
            integrity_dir,
            chain,
            host,
            port,
            syslog_bind,
            opensearch,
            opensearch_index,
            splunk_hec,
            splunk_token_env,
            parquet,
            features,
            sink_batch_size,
            datasets,
            sim_target,
        } => cmd_serve(ServeConfig {
            packs_dir: packs,
            vault_dir: vault,
            integrity_dir,
            chain,
            host,
            port,
            syslog_bind,
            opensearch,
            opensearch_index,
            splunk_hec,
            splunk_token_env,
            parquet,
            features,
            sink_batch_size,
            datasets_dir: datasets,
            sim_target,
        }),
        Command::Replay {
            source,
            target,
            eps,
            count,
        } => replay::cmd_replay(&source, &target, eps, count),
        Command::Listen {
            packs,
            vault,
            integrity_dir,
            bind,
            output,
            chain,
            blake3,
            inline_raw,
        } => cmd_listen(ListenOptions {
            packs_dir: packs,
            vault_dir: vault,
            integrity_dir,
            bind,
            output,
            chain,
            blake3,
            inline_raw,
        }),
        Command::Decoders => {
            for name in ulpf_decode::BUILTIN_NAMES {
                println!("{name}");
            }
            Ok(())
        }
    }
}

fn cmd_run(options: RunOptions) -> anyhow::Result<()> {
    let RunOptions {
        packs_dir,
        vault_dir,
        input,
        output,
        blake3,
        chain,
        integrity_dir,
        inline_raw,
        dead_letter,
        parquet,
        features,
        opensearch,
        opensearch_index,
        splunk_hec,
        splunk_token_env,
        sink_batch_size,
    } = options;
    ensure_output_paths_are_safe(&input, &output, dead_letter.as_deref(), parquet.as_deref())?;
    let (library, errors) = PackLibrary::load_dir(&packs_dir)
        .with_context(|| format!("loading packs from {}", packs_dir.display()))?;
    for (path, err) in &errors {
        tracing::error!(path = %path.display(), %err, "pack failed to load");
    }
    if library.is_empty() {
        bail!(
            "no usable packs in {} — every event would be unparsed",
            packs_dir.display()
        );
    }
    tracing::info!(packs = library.len(), "pack library loaded");

    let vault = VaultWriter::open(&vault_dir)
        .with_context(|| format!("opening vault at {}", vault_dir.display()))?;

    let hash = if blake3 {
        HashAlgorithm::Blake3
    } else {
        HashAlgorithm::Sha256
    };
    let integrity = integrity_state::open(&integrity_dir, "ulpf-local", &chain, hash)?;
    let checkpoint_path = integrity.checkpoint_path.clone();
    let merkle_leaves_path = integrity.merkle_leaves_path.clone();
    let public_key_path = integrity.public_key_path.clone();
    let mut pipeline = Pipeline::new(std::sync::Arc::new(library), vault, integrity.attestor)
        .with_hash(hash)
        .inline_raw(inline_raw);

    let reader = open_input(&input)?;
    let mut writer = open_output(&output)?;
    let mut dead_letter_writer = match &dead_letter {
        Some(path) => Some(open_output(&path.display().to_string())?),
        None => None,
    };
    let mut sinks = sinks::AsyncSinkSet::new(sinks::SinkConfig {
        parquet: parquet.as_deref(),
        features: features.as_deref(),
        opensearch: opensearch.as_deref(),
        opensearch_index: &opensearch_index,
        splunk_hec: splunk_hec.as_deref(),
        splunk_token_env: &splunk_token_env,
        batch_size: sink_batch_size,
    })?;
    if !sinks.is_empty() {
        tracing::info!("optional output sinks enabled");
    }
    let transport = if input == "-" {
        Transport::Stdin
    } else {
        Transport::File
    };
    let mut envelope_template = Envelope::new(transport, "cli");
    if input != "-" {
        envelope_template.origin = Some(input.to_string());
    }

    let started = std::time::Instant::now();
    let mut reader = reader;
    let mut raw = Vec::new();
    let mut pending = Vec::with_capacity(COMMIT_BATCH_SIZE);
    loop {
        raw.clear();
        if reader.read_until(b'\n', &mut raw)? == 0 {
            break;
        }
        let envelope = Envelope {
            received_at: ulpf_core::now_nanos(),
            ..envelope_template.clone()
        };
        let processed = pipeline.process(&raw, &envelope)?;
        pending.push(PendingOutput {
            processed,
            raw: raw.clone(),
            received_at: envelope.received_at,
        });
        if pending.len() >= COMMIT_BATCH_SIZE {
            commit_pending(
                &mut pipeline,
                &mut pending,
                writer.as_mut(),
                &mut dead_letter_writer,
                &checkpoint_path,
                &merkle_leaves_path,
                &mut sinks,
            )?;
        }
    }
    commit_pending(
        &mut pipeline,
        &mut pending,
        writer.as_mut(),
        &mut dead_letter_writer,
        &checkpoint_path,
        &merkle_leaves_path,
        &mut sinks,
    )?;
    writer.flush()?;
    if let Some(dl) = &mut dead_letter_writer {
        dl.flush()?;
    }

    let elapsed = started.elapsed();
    // `finish` consumes the pipeline, so take the leaves while it still exists.
    let merkle_leaves = pipeline.merkle_leaves().to_vec();
    let (stats, checkpoint) = pipeline.finish()?;
    sinks.finish()?;
    if let Some(checkpoint) = &checkpoint {
        integrity_state::persist_leaves(&merkle_leaves_path, &merkle_leaves)?;
        integrity_state::persist_checkpoint(&checkpoint_path, checkpoint)?;
    }

    let eps = if elapsed.as_secs_f64() > 0.0 {
        stats.received as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    eprintln!("\n─── ULPF run summary ───");
    eprintln!("  received          {}", stats.received);
    eprintln!(
        "  parsed            {} ({:.4}% coverage)",
        stats.parsed,
        stats.coverage() * 100.0
    );
    eprintln!("  unidentified      {}", stats.unidentified);
    eprintln!("  extract failed    {}", stats.extract_failed);
    eprintln!("  normalize failed  {}", stats.normalize_failed);
    eprintln!("  bytes in          {}", stats.bytes_in);
    eprintln!(
        "  elapsed           {:.3}s  ({eps:.0} events/sec)",
        elapsed.as_secs_f64()
    );
    if !stats.by_pack.is_empty() {
        eprintln!("  by pack:");
        for (pack, n) in &stats.by_pack {
            eprintln!("    {pack:<40} {n}");
        }
    }
    if let Some(cp) = checkpoint {
        eprintln!(
            "  checkpoint        seq {} head {}…",
            cp.sequence,
            &cp.head.value[..16.min(cp.head.value.len())]
        );
        eprintln!("  checkpoint file   {}", checkpoint_path.display());
        eprintln!("  trusted key       {}", public_key_path.display());
    }
    Ok(())
}

fn commit_pending(
    pipeline: &mut Pipeline,
    pending: &mut Vec<PendingOutput>,
    writer: &mut dyn Write,
    dead_letter: &mut Option<Box<dyn Write>>,
    checkpoint_path: &Path,
    merkle_leaves_path: &Path,
    sinks: &mut sinks::AsyncSinkSet,
) -> anyhow::Result<()> {
    if pending.is_empty() {
        return Ok(());
    }

    // Commit the raw block before publishing any locator from it. Batching
    // preserves zstd's compression context without allowing an emitted OCSF
    // row to point at evidence that only exists in process memory.
    let checkpoint = pipeline.checkpoint_now()?;
    if let Some(checkpoint) = &checkpoint {
        // Leaves first: a checkpoint naming a tree size the leaf file cannot
        // reach would refuse to load on the next start.
        integrity_state::persist_leaves(merkle_leaves_path, pipeline.merkle_leaves())?;
        integrity_state::persist_checkpoint(checkpoint_path, checkpoint)?;
    }

    for item in pending.drain(..) {
        writeln!(writer, "{}", item.processed.event.to_json())?;
        sinks.write(&item.processed.event)?;
        if !item.processed.disposition.is_parsed() {
            if let Some(dl) = dead_letter.as_deref_mut() {
                let valid_utf8 = std::str::from_utf8(&item.raw).is_ok();
                let record = serde_json::json!({
                    "raw_text": String::from_utf8_lossy(&item.raw),
                    "raw_encoding": if valid_utf8 { "utf-8" } else { "lossy-utf-8" },
                    "raw_hex": if valid_utf8 { None } else { Some(hex::encode(&item.raw)) },
                    "disposition": item.processed.disposition.label(),
                    "pack": item.processed.disposition.pack_id(),
                    "locator": item.processed.raw_ref.to_locator(),
                    "received_at": item.received_at,
                });
                writeln!(dl, "{record}")?;
            }
        }
    }
    Ok(())
}

/// Start the console. Blocks until interrupted.
/// Everything `ulpf serve` needs.
///
/// Grouped rather than passed positionally: most of these are strings, and a
/// transposed pair - `opensearch_index` for `splunk_token_env`, say - would
/// compile cleanly and fail only at runtime against a live SIEM.
pub struct ServeConfig {
    pub packs_dir: PathBuf,
    pub vault_dir: PathBuf,
    pub integrity_dir: PathBuf,
    pub chain: String,
    pub host: String,
    pub port: u16,
    pub syslog_bind: String,
    pub opensearch: Option<String>,
    pub opensearch_index: String,
    pub splunk_hec: Option<String>,
    pub splunk_token_env: String,
    pub parquet: Option<PathBuf>,
    pub features: Option<PathBuf>,
    pub sink_batch_size: usize,
    pub datasets_dir: PathBuf,
    pub sim_target: String,
}

/// GET a readiness URL and translate it into an exit code.
///
/// 200 means ready, anything else means not. Deliberately dependency-free
/// beyond the HTTP client the generator already pulls in, and deliberately
/// silent on success so container logs stay readable.
fn cmd_healthcheck(url: &str, timeout_secs: u64) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()?;
        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => Ok(()),
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                eprintln!("not ready: {status} {}", body.trim());
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("unreachable at {url}: {e}");
                std::process::exit(1);
            }
        }
    })
}

fn cmd_serve(config: ServeConfig) -> anyhow::Result<()> {
    let ServeConfig {
        packs_dir,
        vault_dir,
        syslog_bind,
        integrity_dir,
        chain,
        host,
        port,
        opensearch,
        opensearch_index,
        splunk_hec,
        splunk_token_env,
        parquet,
        features,
        sink_batch_size,
        datasets_dir,
        sim_target,
    } = config;
    let chain = chain.as_str();
    let host = host.as_str();
    let opensearch = opensearch.as_deref();
    let opensearch_index = opensearch_index.as_str();
    let splunk_hec = splunk_hec.as_deref();
    let splunk_token_env = splunk_token_env.as_str();
    let parquet = parquet.as_deref();
    let features = features.as_deref();
    let (library, errors) = PackLibrary::load_dir(&packs_dir)
        .with_context(|| format!("loading packs from {}", packs_dir.display()))?;
    for (path, err) in &errors {
        tracing::error!(path = %path.display(), %err, "pack failed to load");
    }
    if library.is_empty() {
        bail!("no usable packs in {}", packs_dir.display());
    }
    let pack_count = library.len();

    let vault = VaultWriter::open(&vault_dir)
        .with_context(|| format!("opening vault at {}", vault_dir.display()))?;
    let integrity =
        integrity_state::open(&integrity_dir, "ulpf-console", chain, HashAlgorithm::Sha256)?;
    let resume_anchor = integrity.resume_anchor.clone();
    let checkpoint_path = integrity.checkpoint_path.clone();
    let merkle_leaves_path = integrity.merkle_leaves_path.clone();
    let public_key_path = integrity.public_key_path.clone();
    let mut pipeline = Pipeline::new(std::sync::Arc::new(library), vault, integrity.attestor);

    // Start pack hot-reload watcher
    if let Err(e) = watcher::spawn_pack_watcher(packs_dir.clone(), pipeline.packs_lock()) {
        tracing::warn!("failed to start pack hot-reload watcher: {}", e);
    }

    let latest_checkpoint = pipeline.checkpoint_now()?;

    let state = std::sync::Arc::new(std::sync::Mutex::new(server::AppState {
        pipeline,
        recent: Vec::new(),
        chain_anchor: resume_anchor,
        latest_checkpoint,
        checkpoint_path,
        merkle_leaves_path: merkle_leaves_path.clone(),
        public_key_path: public_key_path.clone(),
        vault_dir,
        packs_dir: packs_dir.clone(),
        drain: ulpf_generator::drain::Drain::new(),
        simulator: simulator::Simulator::new(datasets_dir, sim_target),
    }));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // Shared, not owned by the listener thread: Parquet writes its footer when
    // the writer is dropped, and `serve` had no path that ever dropped it. A
    // console run with --features or --parquet produced a file that was never
    // readable — not on Ctrl-C, not on `docker stop`, not ever, because the
    // process only ended by being killed. `finish` consumes the set, so an
    // Option is what lets the shutdown path take it back.
    let sinks = std::sync::Arc::new(std::sync::Mutex::new(Some(sinks::AsyncSinkSet::new(
        sinks::SinkConfig {
            parquet,
            features,
            opensearch,
            opensearch_index,
            splunk_hec,
            splunk_token_env,
            batch_size: sink_batch_size,
        },
    )?)));
    let listener_sinks = sinks.clone();

    // Spawn UDP syslog listener on a dedicated thread to avoid blocking async.
    //
    // `bind_receiver` rather than a plain `UdpSocket::bind`: the console is the
    // path the simulator and any real device actually send to, so it needs the
    // same enlarged receive buffer the measured `listen` numbers were taken
    // with. Binding plainly here left the demo running on the ~64 KB OS
    // default, which docs/THROUGHPUT.md records as 37% loss at 15,000 EPS.
    let listener_state = state.clone();
    let bind = syslog_bind.clone();
    std::thread::spawn(move || {
        let socket = match bind_receiver(&bind) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to bind UDP syslog listener to {}: {:#}", bind, e);
                return;
            }
        };
        tracing::info!("ULPF UDP syslog receiver listening on {}", bind);

        let mut buffer = vec![0u8; 65_535];
        // Same reasoning as `cmd_listen`: signing and fsyncing a checkpoint per
        // datagram costs an Ed25519 signature plus a synchronous write for every
        // record. The vault is still flushed each event so a locator shown in
        // the console is immediately retrievable.
        let mut since_checkpoint: u64 = 0;
        let mut last_checkpoint = std::time::Instant::now();
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, peer)) => {
                    let envelope = Envelope::new(Transport::SyslogUdp, "udp-listener")
                        .with_peer(peer.ip())
                        .with_origin(bind.clone());

                    let mut st = listener_state.lock().unwrap();
                    let processed = match st.pipeline.process(&buffer[..len], &envelope) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::error!("Pipeline process error: {}", e);
                            continue;
                        }
                    };

                    let _ = st.pipeline.flush();
                    since_checkpoint += 1;
                    if since_checkpoint >= CHECKPOINT_EVERY
                        || last_checkpoint.elapsed() >= CHECKPOINT_INTERVAL
                    {
                        since_checkpoint = 0;
                        last_checkpoint = std::time::Instant::now();
                        if let Ok(Some(checkpoint)) = st.pipeline.checkpoint_now() {
                            let path = st.checkpoint_path.clone();
                            let leaves_path = st.merkle_leaves_path.clone();
                            let leaves = st.pipeline.merkle_leaves().to_vec();
                            let _ = integrity_state::persist_leaves(&leaves_path, &leaves);
                            let _ = integrity_state::persist_checkpoint(&path, &checkpoint);
                            st.latest_checkpoint = Some(checkpoint);
                        }
                    }

                    if let Some(sink) = listener_sinks.lock().unwrap().as_mut() {
                        let _ = sink.write(&processed.event);
                    }

                    // Add to recent events for the console UI
                    let pack_id = processed.disposition.pack_id().map(|s| s.to_string());
                    let mut disp_label = processed.disposition.label().to_string();
                    if let ulpf_core::Disposition::Unidentified = &processed.disposition {
                        st.drain
                            .process(std::str::from_utf8(&buffer[..len]).unwrap_or_default());
                        tracing::info!("Drain clustering updated for unidentified event");
                    } else if let ulpf_core::Disposition::ExtractFailed { reason, .. }
                    | ulpf_core::Disposition::NormalizeFailed { reason, .. } =
                        &processed.disposition
                    {
                        disp_label = format!("{} ({})", disp_label, reason);
                    }

                    st.recent.push(crate::server::RecentEvent {
                        event: processed.event,
                        disposition: disp_label,
                        pack: pack_id,
                        locator: processed.raw_ref.to_locator(),
                    });
                    // Dropping the oldest event without moving the anchor left
                    // the verifier looking at a window whose first record
                    // references a predecessor it had never seen, so a healthy
                    // chain reported "chain broken" as soon as the console had
                    // seen RECENT_CAPACITY events. Advance the anchor to the
                    // event being evicted, exactly as the ingest path does.
                    if st.recent.len() > crate::server::RECENT_CAPACITY {
                        let excess = st.recent.len() - crate::server::RECENT_CAPACITY;
                        let predecessor = &st.recent[excess - 1].event;
                        match ulpf_ocsf::verify_event(predecessor) {
                            Ok(fingerprint) => {
                                st.chain_anchor = Some(ulpf_ocsf::ChainLink {
                                    uid: predecessor.uid().unwrap_or_default().to_string(),
                                    type_uid: predecessor.type_uid(),
                                    fingerprint,
                                });
                            }
                            Err(error) => {
                                tracing::error!("evicted event failed to verify: {}", error)
                            }
                        }
                        st.recent.drain(..excess);
                    }
                }
                Err(e) => tracing::error!("UDP receive error: {}", e),
            }
        }
    });

    runtime.block_on(async {
        // The console's own origin, so the guard can tell the operator's tab
        // apart from any other page that knows the port.
        let app = server::router(state.clone(), Some(format!("http://{host}:{port}")));
        let addr: std::net::SocketAddr = match format!("{host}:{port}").parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("  {host}:{port} is not a valid socket address: {e}");
                std::process::exit(2);
            }
        };
        // A taken port is an ordinary operator mistake — two collectors on one
        // host, a console already running — and deserves a sentence, not a
        // panic and a backtrace.
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("  could not bind the console to {addr}: {e}");
                eprintln!(
                    "  choose another port with --port, or stop the process already using it."
                );
                std::process::exit(2);
            }
        };

        eprintln!();
        eprintln!(
            "  ULPF console  ·  {pack_count} packs  ·  OCSF {}",
            ulpf_ocsf::SCHEMA_VERSION
        );
        eprintln!("  Listening on http://{host}:{port}");
        // The verifier needs this path: `ulpf verify --public-key <path>`.
        eprintln!("  trusted key   {}", public_key_path.display());
        eprintln!();

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .unwrap();

        Ok::<(), anyhow::Error>(())
    })?;

    // Past this point the HTTP server has stopped. The UDP listener thread is
    // still parked on recv_from and will die with the process; taking the sinks
    // out from under it is safe because a write only happens while holding this
    // same lock.
    eprintln!();
    eprintln!("  Shutting down. Sealing outputs…");

    // Commit whatever arrived since the last periodic checkpoint, so a clean
    // stop leaves the tail of the chain signed rather than stranded.
    {
        let mut st = state.lock().unwrap();
        match st.pipeline.checkpoint_now() {
            Ok(Some(checkpoint)) => {
                let path = st.checkpoint_path.clone();
                let leaves_path = st.merkle_leaves_path.clone();
                let leaves = st.pipeline.merkle_leaves().to_vec();
                if let Err(e) = integrity_state::persist_leaves(&leaves_path, &leaves) {
                    eprintln!("  could not write Merkle leaves: {e:#}");
                }
                if let Err(e) = integrity_state::persist_checkpoint(&path, &checkpoint) {
                    eprintln!("  could not write checkpoint: {e:#}");
                } else {
                    eprintln!("  checkpoint    seq {}", checkpoint.sequence);
                }
                st.latest_checkpoint = Some(checkpoint);
            }
            Ok(None) => {}
            Err(e) => eprintln!("  could not sign a final checkpoint: {e:#}"),
        }
    }

    // Dropping the sink set closes the Parquet writers, which is what writes
    // their footers. Without this the files stay unreadable.
    let taken = sinks.lock().unwrap().take();
    if let Some(sink) = taken {
        match sink.finish() {
            Ok(()) => eprintln!("  sinks         closed"),
            Err(e) => eprintln!("  sink shutdown failed: {e:#}"),
        }
    }
    eprintln!();

    Ok(())
}

/// Resolve when the operator asks the process to stop.
///
/// Ctrl-C covers an interactive run; SIGTERM is what `docker stop` and systemd
/// send, and the compose file allows 30s for it, which is only useful if
/// something is listening.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    }

    #[cfg(not(unix))]
    ctrl_c.await;
}

fn cmd_test(packs_dir: PathBuf) -> anyhow::Result<()> {
    let (library, errors) = PackLibrary::load_dir(&packs_dir)
        .with_context(|| format!("loading packs from {}", packs_dir.display()))?;

    for (path, err) in &errors {
        println!("LOAD FAIL  {}: {err}", path.display());
    }

    let report = library.test_all();
    for pack in library.iter() {
        let one = ulpf_pack::library::test_pack(pack);
        let mark = if one.is_ok() { "ok  " } else { "FAIL" };
        println!(
            "{mark}  {:<40} {}/{} fixtures  {:.0}% fields",
            pack.id,
            one.passed,
            one.total,
            one.field_accuracy() * 100.0
        );
    }

    if !report.failures.is_empty() {
        println!("\nfailures:");
        for f in &report.failures {
            println!(
                "  {} fixture {} at {}: {}",
                f.pack, f.fixture, f.path, f.detail
            );
        }
    }

    println!(
        "\n{} packs · {}/{} fixtures passed · {:.1}% field accuracy",
        library.len(),
        report.passed,
        report.total,
        report.field_accuracy() * 100.0
    );

    if !report.is_ok() || !errors.is_empty() {
        bail!("pack tests failed");
    }
    Ok(())
}

fn cmd_raw(vault_dir: PathBuf, locator: &str) -> anyhow::Result<()> {
    let raw_ref =
        RawRef::from_locator(locator).with_context(|| format!("parsing locator `{locator}`"))?;
    let mut reader = VaultReader::open(&vault_dir);
    let bytes = reader
        .get(raw_ref)
        .with_context(|| format!("retrieving {locator}"))?;
    std::io::stdout().write_all(&bytes)?;
    Ok(())
}

fn cmd_verify(
    input: &str,
    checkpoint_path: Option<&Path>,
    public_key_path: Option<&Path>,
) -> anyhow::Result<()> {
    let reader = open_input(input)?;
    let mut events = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&line)?;
        events.push(OcsfEvent::from_map(map));
    }

    if events.is_empty() {
        bail!("no events to verify");
    }

    if public_key_path.is_some() && checkpoint_path.is_none() {
        bail!("--public-key requires --checkpoint");
    }

    let verified: anyhow::Result<ulpf_ocsf::ChainLink> = if let Some(path) = checkpoint_path {
        let checkpoint = integrity_state::read_checkpoint(path)?;
        if let Some(key_path) = public_key_path {
            let key = integrity_state::read_public_key(key_path)?;
            checkpoint
                .verify_with(&key)
                .context("checkpoint did not verify with the trusted public key")?;
        }
        Ok(ulpf_ocsf::verify_checkpoint_segment(&events, &checkpoint)?)
    } else {
        let anchor = events
            .first()
            .map(ulpf_ocsf::predecessor)
            .transpose()?
            .flatten();
        Ok(ulpf_ocsf::verify_chain_from(&events, anchor.as_ref())?
            .ok_or_else(|| anyhow::anyhow!("no chain head"))?)
    };

    match verified {
        Ok(head) => {
            println!("OK  {} events verified", events.len());
            println!(
                "    chain head {} fingerprint {}",
                head.uid, head.fingerprint.value
            );
            if checkpoint_path.is_some() {
                println!("    signed checkpoint verified");
                if public_key_path.is_some() {
                    println!("    trusted public key verified");
                }
            } else {
                println!("    segment consistency only (supply --checkpoint for authenticity)");
            }
            Ok(())
        }
        Err(e) => {
            println!("FAIL  {e}");
            bail!("chain verification failed");
        }
    }
}

/// Signing and fsyncing a checkpoint after every datagram costs an Ed25519
/// signature plus a synchronous file write per event, which measured 102
/// events/sec over UDP against ~15,000/sec for the same records from a file.
/// The chain is tamper-evident from the per-event fingerprints alone; a
/// checkpoint only anchors it. Anchoring periodically gives the same guarantee
/// at a fraction of the cost, which is the design the integrity module
/// documents. Shared by both receive paths so they cannot drift apart.
const CHECKPOINT_EVERY: u64 = 500;
const CHECKPOINT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// 8 MB is roughly 55,000 syslog datagrams of headroom: enough to absorb a
/// multi-second burst while the pipeline drains, without reserving memory a
/// laptop would notice.
const RECV_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// Bind a UDP receiver with a receive buffer large enough to ride out a burst.
///
/// The OS default is about 64 KB, which for ~150-byte syslog records is
/// roughly 400 datagrams: a few milliseconds of scheduling delay at any real
/// rate and the kernel starts discarding. Measured here, a sustained 15,000
/// EPS lost 37% of records that way, and UDP gives the sender no indication —
/// the collector simply reports a lower count and nothing says why. Silent
/// loss is the one failure a log collector must not have, so ask for 8 MB and
/// report what the kernel actually granted rather than assuming it obliged.
fn bind_receiver(bind: &str) -> anyhow::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let addr: std::net::SocketAddr = bind
        .parse()
        .with_context(|| format!("parsing listen address {bind}"))?;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .with_context(|| format!("creating UDP socket for {bind}"))?;

    // Best effort: a hardened host may cap this well below the request, which
    // is not a reason to refuse to start.
    if let Err(error) = socket.set_recv_buffer_size(RECV_BUFFER_BYTES) {
        tracing::warn!("could not enlarge the UDP receive buffer: {}", error);
    }

    socket
        .bind(&addr.into())
        .with_context(|| format!("binding UDP syslog receiver to {bind}"))?;

    match socket.recv_buffer_size() {
        Ok(size) if size + 1 < RECV_BUFFER_BYTES => {
            // Linux reports double the requested value; only a genuine
            // shortfall is worth a warning.
            tracing::warn!(
                "UDP receive buffer is {} KB, below the {} KB requested;                  sustained bursts above a few thousand EPS may be dropped",
                size / 1024,
                RECV_BUFFER_BYTES / 1024
            );
        }
        Ok(size) => eprintln!("UDP receive buffer: {} KB", size / 1024),
        Err(_) => {}
    }

    Ok(socket.into())
}

fn cmd_listen(options: ListenOptions) -> anyhow::Result<()> {
    let ListenOptions {
        packs_dir,
        vault_dir,
        integrity_dir,
        bind,
        output,
        chain,
        blake3,
        inline_raw,
    } = options;
    let (library, errors) = PackLibrary::load_dir(&packs_dir)
        .with_context(|| format!("loading packs from {}", packs_dir.display()))?;
    for (path, error) in &errors {
        tracing::error!(path = %path.display(), %error, "pack failed to load");
    }
    if library.is_empty() {
        bail!("no usable packs in {}", packs_dir.display());
    }

    let hash = if blake3 {
        HashAlgorithm::Blake3
    } else {
        HashAlgorithm::Sha256
    };
    let integrity = integrity_state::open(&integrity_dir, "ulpf-syslog", &chain, hash)?;
    let checkpoint_path = integrity.checkpoint_path.clone();
    let merkle_leaves_path = integrity.merkle_leaves_path.clone();
    let public_key_path = integrity.public_key_path.clone();
    let vault = VaultWriter::open(&vault_dir)
        .with_context(|| format!("opening vault at {}", vault_dir.display()))?;
    let mut pipeline = Pipeline::new(std::sync::Arc::new(library), vault, integrity.attestor)
        .with_hash(hash)
        .inline_raw(inline_raw);

    // Start pack hot-reload watcher
    if let Err(e) = watcher::spawn_pack_watcher(packs_dir.clone(), pipeline.packs_lock()) {
        tracing::warn!("failed to start pack hot-reload watcher: {}", e);
    }

    let mut writer = open_output(&output)?;
    let socket = bind_receiver(&bind)?;
    eprintln!("ULPF UDP syslog receiver listening on {bind}");
    eprintln!("OCSF output: {output}");
    eprintln!("checkpoint: {}", checkpoint_path.display());
    eprintln!("trusted key: {}", public_key_path.display());
    eprintln!("Each accepted datagram is durable before it is emitted; press Ctrl+C to stop.");

    let mut buffer = vec![0u8; 65_535];
    let mut last_checkpoint = std::time::Instant::now();
    let mut pending: u64 = 0;

    let anchor = |pipeline: &mut Pipeline, writer: &mut Box<dyn Write>| -> anyhow::Result<()> {
        writer.flush()?;
        if let Some(checkpoint) = pipeline.checkpoint_now()? {
            integrity_state::persist_leaves(&merkle_leaves_path, pipeline.merkle_leaves())?;
            integrity_state::persist_checkpoint(&checkpoint_path, &checkpoint)?;
        }
        Ok(())
    };

    loop {
        // A transient socket error must not take the collector down.
        let (len, peer) = match socket.recv_from(&mut buffer) {
            Ok(v) => v,
            Err(error) => {
                tracing::warn!(%error, "recv_from failed; continuing");
                continue;
            }
        };

        let envelope = Envelope::new(Transport::SyslogUdp, "udp-listener")
            .with_peer(peer.ip())
            .with_origin(bind.to_string());

        // One malformed datagram from any host must not kill the receiver.
        match pipeline.process(&buffer[..len], &envelope) {
            Ok(processed) => {
                if let Err(error) = writeln!(writer, "{}", processed.event.to_json()) {
                    tracing::error!(%error, "failed to write event");
                }
            }
            Err(error) => {
                tracing::error!(%peer, %error, "failed to process datagram; continuing");
                continue;
            }
        }

        pending += 1;
        if pending >= CHECKPOINT_EVERY || last_checkpoint.elapsed() >= CHECKPOINT_INTERVAL {
            if let Err(error) = anchor(&mut pipeline, &mut writer) {
                tracing::error!(%error, "failed to persist checkpoint");
            }
            pending = 0;
            last_checkpoint = std::time::Instant::now();
        }

        if pipeline.stats.received % 1_000 == 0 {
            eprintln!(
                "received {} · parsed {} · coverage {:.4}%",
                pipeline.stats.received,
                pipeline.stats.parsed,
                pipeline.stats.coverage() * 100.0
            );
        }
    }
}

fn ensure_output_paths_are_safe(
    input: &str,
    output: &str,
    dead_letter: Option<&Path>,
    parquet: Option<&Path>,
) -> anyhow::Result<()> {
    let input_path = (input != "-")
        .then(|| normalized_path(Path::new(input)))
        .transpose()?;
    let output_path = (output != "-")
        .then(|| normalized_path(Path::new(output)))
        .transpose()?;
    let dead_path = dead_letter.map(normalized_path).transpose()?;
    let parquet_path = parquet.map(normalized_path).transpose()?;

    if input_path.is_some() && input_path == output_path {
        bail!("input and output resolve to the same file; refusing to truncate the input");
    }
    if input_path.is_some() && input_path == dead_path {
        bail!("input and dead-letter output resolve to the same file");
    }
    if output_path.is_some() && output_path == dead_path {
        bail!("main output and dead-letter output resolve to the same file");
    }
    if input_path.is_some() && input_path == parquet_path {
        bail!("input and Parquet output resolve to the same file");
    }
    if output_path.is_some() && output_path == parquet_path {
        bail!("main output and Parquet output resolve to the same file");
    }
    if dead_path.is_some() && dead_path == parquet_path {
        bail!("dead-letter and Parquet output resolve to the same file");
    }
    Ok(())
}

fn normalized_path(path: &Path) -> anyhow::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute.exists() {
        return Ok(std::fs::canonicalize(absolute)?);
    }
    let parent = absolute.parent().unwrap_or_else(|| Path::new("."));
    let normalized_parent = if parent.exists() {
        std::fs::canonicalize(parent)?
    } else {
        parent.to_path_buf()
    };
    Ok(normalized_parent.join(
        absolute
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("invalid path {}", absolute.display()))?,
    ))
}

fn open_input(path: &str) -> anyhow::Result<Box<dyn BufRead>> {
    if path == "-" {
        Ok(Box::new(std::io::BufReader::new(std::io::stdin())))
    } else {
        let f = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
        Ok(Box::new(std::io::BufReader::new(f)))
    }
}

fn open_output(path: &str) -> anyhow::Result<Box<dyn Write>> {
    if path == "-" {
        Ok(Box::new(BufWriter::new(std::io::stdout())))
    } else {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let f = std::fs::File::create(path).with_context(|| format!("creating {path}"))?;
        Ok(Box::new(BufWriter::new(f)))
    }
}
