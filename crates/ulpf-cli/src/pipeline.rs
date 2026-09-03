//! The end-to-end pipeline: raw bytes in, attested OCSF out.
//!
//! Stage order is the design, not an implementation detail. The vault append
//! happens *before* identification, so an event that no pack claims, or that
//! crashes a decoder, is already preserved. Everything after that point can
//! fail without costing data.

use std::collections::BTreeMap;
use std::sync::Arc;

use ulpf_core::{Disposition, Envelope, RawRef};
use ulpf_ocsf::event::{EventBuilder, OcsfEvent};
use ulpf_ocsf::types::{Fingerprint, HashAlgorithm, Metadata, Product, Severity};
use ulpf_ocsf::{Attestor, SCHEMA_VERSION};
use ulpf_pack::{NormalizeCtx, PackLibrary};
use ulpf_vault::VaultWriter;

/// Counters for one run, reported at the end and used as the demo's headline.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub received: u64,
    pub parsed: u64,
    pub unidentified: u64,
    pub extract_failed: u64,
    pub normalize_failed: u64,
    pub bytes_in: u64,
    /// Events claimed, by pack id.
    pub by_pack: BTreeMap<String, u64>,
}

impl Stats {
    /// Share of received events that a pack fully normalized.
    pub fn coverage(&self) -> f64 {
        if self.received == 0 {
            return 0.0;
        }
        self.parsed as f64 / self.received as f64
    }

    fn record(&mut self, disposition: &Disposition) {
        match disposition {
            Disposition::Parsed { pack_id } => {
                self.parsed += 1;
                *self.by_pack.entry(pack_id.clone()).or_default() += 1;
            }
            Disposition::Unidentified => self.unidentified += 1,
            Disposition::ExtractFailed { .. } => self.extract_failed += 1,
            Disposition::NormalizeFailed { .. } => self.normalize_failed += 1,
        }
    }
}

/// One processed event, ready to emit.
pub struct Processed {
    pub event: OcsfEvent,
    pub disposition: Disposition,
    pub raw_ref: RawRef,
}

/// Wires the vault, pack library and attestor into a single call per event.
pub struct Pipeline {
    packs: Arc<std::sync::RwLock<Arc<PackLibrary>>>,
    vault: VaultWriter,
    attestor: Attestor,
    hash: HashAlgorithm,
    inline_raw: bool,
    pub stats: Stats,
}

impl Pipeline {
    pub fn new(packs: Arc<PackLibrary>, vault: VaultWriter, attestor: Attestor) -> Self {
        Self {
            packs: Arc::new(std::sync::RwLock::new(packs)),
            vault,
            attestor,
            hash: HashAlgorithm::default(),
            inline_raw: false,
            stats: Stats::default(),
        }
    }

    /// Carry the full original text in every event's `raw_data`.
    ///
    /// Off by default: the vault holds the bytes and the event carries a
    /// locator and fingerprint for them, so inlining roughly doubles the
    /// output stream for no additional forensic guarantee.
    pub fn inline_raw(mut self, yes: bool) -> Self {
        self.inline_raw = yes;
        self
    }

    pub fn with_hash(mut self, hash: HashAlgorithm) -> Self {
        self.hash = hash;
        self
    }

    /// Process one raw event through every stage.
    pub fn process(&mut self, raw: &[u8], envelope: &Envelope) -> anyhow::Result<Processed> {
        self.stats.received += 1;
        self.stats.bytes_in += raw.len() as u64;

        // Stage 1: preserve. Nothing below this line can lose the original.
        let raw_ref = self.vault.append(raw)?;

        // UUIDv7 sorts by creation time, which keeps an NDJSON sink and the
        // attestation chain in the same order without a separate sequence.
        let event_uid = uuid::Uuid::now_v7().to_string();
        let text = String::from_utf8_lossy(raw);

        let active_packs = { self.packs.read().unwrap().clone() };

        let (mut event, disposition) = match active_packs.identify(&text) {
            None => (
                self.minimal_event(raw, envelope, &event_uid)?,
                Disposition::Unidentified,
            ),
            Some(pack) => match pack.extract(&text) {
                Err(e) => (
                    self.minimal_event(raw, envelope, &event_uid)?,
                    Disposition::ExtractFailed {
                        pack_id: pack.id.clone(),
                        reason: e.to_string(),
                    },
                ),
                Ok(fields) => {
                    let ctx = NormalizeCtx::new(envelope, event_uid.clone())
                        .with_vault(raw_ref)
                        .with_hash(self.hash)
                        .inline_raw(self.inline_raw);
                    match pack.normalize(&fields, raw, &ctx) {
                        Ok(ev) => (
                            ev,
                            Disposition::Parsed {
                                pack_id: pack.id.clone(),
                            },
                        ),
                        Err(e) => (
                            self.minimal_event(raw, envelope, &event_uid)?,
                            Disposition::NormalizeFailed {
                                pack_id: pack.id.clone(),
                                reason: e.to_string(),
                            },
                        ),
                    }
                }
            },
        };

        // Stage 2: ULPF provenance, on every event including unparsed ones.
        // `metadata.original_event_uid` belongs to identifiers emitted by the
        // source device, so the vault locator lives in the extension-friendly
        // `unmapped` object instead of overwriting that source semantic.
        event.set_unmapped("ulpf_raw_locator", serde_json::json!(raw_ref.to_locator()));
        event.set_unmapped("ulpf_receipt", serde_json::to_value(envelope)?);
        if let Some(reason) = failure_reason(&disposition) {
            event.set_unmapped("ulpf_disposition", serde_json::json!(disposition.label()));
            event.set_unmapped("ulpf_reason", serde_json::json!(reason));
        }

        // Stage 3: attest, linking this event to its predecessor.
        self.attestor.attest(&mut event)?;

        self.stats.record(&disposition);
        Ok(Processed {
            event,
            disposition,
            raw_ref,
        })
    }

    /// The event emitted when no pack could normalize the input.
    ///
    /// This is the difference between a lossless pipeline and a lossy one. An
    /// unparsed event still becomes a schema-valid OCSF record carrying its own
    /// raw text and vault locator, so it is searchable, countable and
    /// retrievable — and it feeds the dead-letter clustering that decides which
    /// pack to write next.
    fn minimal_event(
        &self,
        raw: &[u8],
        envelope: &Envelope,
        event_uid: &str,
    ) -> anyhow::Result<OcsfEvent> {
        let mut metadata = Metadata::new(SCHEMA_VERSION, Product::new("ULPF", "ULPF"));
        metadata.uid = Some(event_uid.to_string());
        metadata.logged_time = Some(envelope.received_at);
        metadata.log_format = Some("unknown".to_string());

        Ok(EventBuilder::new()
            .class(ulpf_ocsf::class::NETWORK_ACTIVITY)
            .activity(ulpf_ocsf::network_activity::UNKNOWN)
            .time(envelope.received_at)
            .severity(Severity::Informational)
            .metadata(metadata)
            .raw(raw, Fingerprint::over_raw(self.hash, raw))
            .build()?)
    }

    /// Flush the vault so everything appended so far is retrievable, and
    /// return the current signed checkpoint without consuming the pipeline.
    ///
    /// The server calls this between requests; `finish` is the shutdown path.
    /// Make everything written so far retrievable by locator, without paying
    /// for a signature. Separated from `checkpoint_now` so a hot receive loop
    /// can keep the vault readable per event while signing only periodically.
    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.vault.flush()?;
        Ok(())
    }

    pub fn checkpoint_now(&mut self) -> anyhow::Result<Option<ulpf_ocsf::Checkpoint>> {
        self.vault.flush()?;
        Ok(self.attestor.checkpoint(ulpf_core::now_nanos())?)
    }

    pub fn packs(&self) -> Arc<PackLibrary> {
        self.packs.read().unwrap().clone()
    }

    pub fn packs_lock(&self) -> Arc<std::sync::RwLock<Arc<PackLibrary>>> {
        self.packs.clone()
    }

    pub fn chain_head(&self) -> Option<&ulpf_ocsf::ChainLink> {
        self.attestor.head()
    }

    /// Flush the vault and emit a signed checkpoint, if a key is configured.
    pub fn finish(mut self) -> anyhow::Result<(Stats, Option<ulpf_ocsf::Checkpoint>)> {
        self.vault.flush()?;
        let checkpoint = self.attestor.checkpoint(ulpf_core::now_nanos())?;
        let stats = self.stats.clone();
        self.vault.close()?;
        Ok((stats, checkpoint))
    }
}

fn failure_reason(d: &Disposition) -> Option<&str> {
    match d {
        Disposition::Parsed { .. } => None,
        Disposition::Unidentified => Some("no pack detector matched"),
        Disposition::ExtractFailed { reason, .. } | Disposition::NormalizeFailed { reason, .. } => {
            Some(reason)
        }
    }
}
