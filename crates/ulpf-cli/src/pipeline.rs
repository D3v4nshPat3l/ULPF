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
use ulpf_ocsf::types::{Fingerprint, HashAlgorithm, Metadata, Observable, Product, Severity};
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
    /// Records no pack claimed that still carry at least one indicator or
    /// named field, so an analyst can find them by searching.
    ///
    /// Reported separately from `parsed` on purpose. Folding these into
    /// coverage would inflate the number the project is judged on: a record
    /// here has a real timestamp and searchable content, but nobody has told
    /// ULPF what it means, and that is a weaker claim than normalization.
    pub searchable_unidentified: u64,
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

        // A pack claiming a record is not the same as a pack understanding it.
        // A broad fallback — generic syslog, generic CEF — matches almost any
        // line of its shape and maps almost nothing from it, and because it
        // *succeeded* the record was never routed to salvage. Removing the
        // iptables pack showed this plainly: the generic syslog pack claimed
        // 100% of the corpus, emitted a single hostname observable, and a
        // firewall log full of addresses stayed unsearchable while reporting
        // full coverage.
        //
        // So salvage runs on every record, and adds only indicators the pack
        // did not already name. A threshold — "fewer than N observables" —
        // would be a number to defend with nothing behind it; deduplication
        // needs no threshold and cannot discard a pack's own mapping.
        salvage_into(&mut event, raw);

        // Stage 3: attest, linking this event to its predecessor.
        self.attestor.attest(&mut event)?;

        self.stats.record(&disposition);
        // Counted after the event is fully built, from the event itself, so
        // the figure is what a searcher would actually find rather than what
        // the extractors were asked to look for.
        if matches!(disposition, ulpf_core::Disposition::Unidentified) && is_searchable(&event) {
            self.stats.searchable_unidentified += 1;
        }
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

        // When the line states a time, use it. Stamping every unidentified
        // record with the moment ULPF received it asserts something false:
        // replaying a 2005 capture produced events dated today, and nothing
        // downstream could tell that the timestamp was the collector's clock
        // rather than the device's. Which of the two was used is recorded, so
        // a reader never has to guess.
        let text = String::from_utf8_lossy(raw);
        let generic = ulpf_decode::generic::extract(&text);
        let detected = ulpf_pack::time::detect_leading_time(&text);
        let (event_time, time_source) = match detected {
            Some(d) if d.year_stated => (d.nanos, "log"),
            // RFC 3164 has no year field, so the year is the collector's
            // assumption even though the month, day and clock are the
            // device's. Labelled distinctly rather than passed off as either.
            Some(d) => (d.nanos, "log-year-assumed"),
            None => (envelope.received_at, "receipt"),
        };

        let mut event = EventBuilder::new()
            // Base Event, not Network Activity. A record nobody identified
            // could be from a database, a printer or a badge reader; calling
            // it network traffic is a claim ULPF has no basis for. Class 0 is
            // the schema's own answer for "an event, kind unknown".
            .class(ulpf_ocsf::class::BASE_EVENT)
            .activity(ulpf_ocsf::network_activity::UNKNOWN)
            .time(event_time)
            // RFC 5424 severity when the line carried a <PRI> header, and
            // Informational when it did not -- not a guess either way, since
            // the absence of a priority is itself the absence of a claim.
            .severity(
                generic
                    .syslog_severity
                    .map(syslog_severity_to_ocsf)
                    .unwrap_or(Severity::Informational),
            )
            .metadata(metadata)
            .raw(raw, Fingerprint::over_raw(self.hash, raw))
            .build()?;
        event.set_unmapped("ulpf_time_source", serde_json::json!(time_source));

        // Keep the device's own field names. `salvage_into` below records the
        // entities it recognises but discards the vocabulary around them, so
        // `outcome=deny` vanished entirely -- "deny" is not an address, a port
        // or a URL. OCSF `unmapped` is the object the schema provides for
        // exactly this: attributes the producer could not map.
        if !generic.fields.is_empty() {
            let mut named = serde_json::Map::new();
            for (key, value) in &generic.fields {
                named.insert(key.clone(), serde_json::Value::String(value.clone()));
            }
            event.set_unmapped("ulpf_fields", serde_json::Value::Object(named));
        }
        // RFC 5424 severity, mapped onto the OCSF scale. Both are ordered
        // scales of the same idea, so this is a translation rather than a
        // judgement -- but it is a translation, so it is recorded as one and
        // only applied when the line actually carried a <PRI> header.
        if let Some(code) = generic.syslog_severity {
            event.set_unmapped("ulpf_syslog_severity", serde_json::json!(code));
        }

        salvage_into(&mut event, raw);
        Ok(event)
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

    /// Merkle leaf hashes, for persisting the tree across restarts.
    pub fn merkle_leaves(&self) -> &[[u8; 32]] {
        self.attestor.merkle_leaves()
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

/// Indicators the event already names, as (type_id, value).
fn existing_observables(event: &OcsfEvent) -> std::collections::HashSet<(u64, String)> {
    event
        .as_map()
        .get("observables")
        .and_then(|v| v.as_array())
        .map(|array| {
            array
                .iter()
                .filter_map(|o| {
                    Some((
                        o.get("type_id")?.as_u64()?,
                        o.get("value")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Recover indicators from arbitrary text and attach them as observables.
///
/// Deliberately only `observables`: this says an address is present, it does
/// not claim the address is the source. A wrong `src_endpoint.ip` is worse
/// than an absent one, because a detection rule acts on it.
/// Whether an unidentified record carries anything an analyst could search
/// for: a recognised indicator, or a field the device named itself.
///
/// Raw text alone does not count. Every record has that, so counting it would
/// make the figure meaningless -- it would simply equal the number of records
/// received.
fn is_searchable(event: &OcsfEvent) -> bool {
    let map = event.as_map();
    let has_observables = map
        .get("observables")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());
    let has_fields = map
        .get("unmapped")
        .and_then(|v| v.get("ulpf_fields"))
        .and_then(|v| v.as_object())
        .is_some_and(|o| !o.is_empty());
    has_observables || has_fields
}

/// RFC 5424 §6.2.1 severity onto the OCSF `severity_id` scale.
///
/// Both are ordered severities, but they are not the same length, so the ends
/// compress: syslog Alert and Critical both land on OCSF Critical, and Debug
/// joins Informational because OCSF has nothing below it. Written out rather
/// than computed so the choice at each step is visible and arguable.
fn syslog_severity_to_ocsf(code: u8) -> Severity {
    match code {
        0 => Severity::Fatal,         // Emergency: system is unusable
        1 | 2 => Severity::Critical,  // Alert, Critical
        3 => Severity::High,          // Error
        4 => Severity::Medium,        // Warning
        5 => Severity::Low,           // Notice
        _ => Severity::Informational, // Informational, Debug
    }
}

fn salvage_into(event: &mut OcsfEvent, raw: &[u8]) {
    let text = String::from_utf8_lossy(raw);
    let salvaged = ulpf_decode::salvage::salvage(&text);
    if salvaged.is_empty() {
        return;
    }
    let already = existing_observables(event);
    let mut added = 0usize;
    for item in salvaged {
        if already.contains(&(u64::from(item.type_id), item.value.clone())) {
            continue;
        }
        event.push_observable(Observable {
            name: "raw_data".to_string(),
            type_id: item.type_id,
            value: Some(item.value),
        });
        added += 1;
    }
    if added > 0 {
        event.set_unmapped("ulpf_salvaged_count", serde_json::json!(added));
    }
}
