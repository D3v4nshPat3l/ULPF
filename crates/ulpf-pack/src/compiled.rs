//! A pack, resolved and ready to run.
//!
//! Compiling once at load time and running many times per event is the whole
//! reason the hot path stays deterministic: decoder lookups, enum resolution
//! and observable-type parsing all happen here, so per-event work is field
//! lookup, coercion and assignment.

use std::collections::BTreeMap;

use ulpf_core::{Envelope, FieldMap, RawRef, Value};
use ulpf_decode::{Decoded, Decoder};
use ulpf_ocsf::event::{EventBuilder, OcsfEvent};
use ulpf_ocsf::types::{Fingerprint, HashAlgorithm, Metadata, Observable, ObservableType, Product};
use ulpf_ocsf::SCHEMA_VERSION;

use crate::error::{PackError, Result};
use crate::spec::{Cast, Detector, FieldSpec, MapSpec, Pack, TimeFormat};
use crate::time::parse_time;

/// Everything the mapper needs that is not the pack or the fields.
///
/// Grouped into a struct because these travel together on every call and the
/// parameter list was becoming a source of positional mistakes.
pub struct NormalizeCtx<'a> {
    pub envelope: &'a Envelope,
    /// Where the original bytes live. `None` means no vault is in use, which
    /// forces the raw text to be inlined so the event stays self-contained.
    pub raw_ref: Option<RawRef>,
    pub hash: HashAlgorithm,
    /// Value for `metadata.uid`.
    pub event_uid: String,
    /// Carry the full original text in `raw_data`.
    pub inline_raw: bool,
}

impl<'a> NormalizeCtx<'a> {
    pub fn new(envelope: &'a Envelope, event_uid: impl Into<String>) -> Self {
        Self {
            envelope,
            raw_ref: None,
            hash: HashAlgorithm::default(),
            event_uid: event_uid.into(),
            inline_raw: true,
        }
    }

    pub fn with_vault(mut self, raw_ref: RawRef) -> Self {
        self.raw_ref = Some(raw_ref);
        self.inline_raw = false;
        self
    }

    pub fn with_hash(mut self, hash: HashAlgorithm) -> Self {
        self.hash = hash;
        self
    }

    pub fn inline_raw(mut self, yes: bool) -> Self {
        self.inline_raw = yes;
        self
    }
}

/// A pack with its decoders instantiated and its mapping validated.
pub struct CompiledPack {
    pub id: String,
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
    pub log_format: Option<String>,
    pub priority: i32,
    detectors: Vec<Detector>,
    decoders: Vec<(Box<dyn Decoder>, bool)>,
    /// Mapping entries, ordered so that parents are written before children.
    mapping: Vec<(String, CompiledSpec)>,
    enums: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    pub spec: Pack,
}

enum CompiledSpec {
    Literal(serde_json::Value),
    Field(Box<CompiledField>),
}

struct CompiledField {
    candidates: Vec<String>,
    cast: Option<Cast>,
    format: Option<TimeFormat>,
    enum_table: Option<String>,
    default: Option<serde_json::Value>,
    observable: Option<ObservableType>,
}

impl CompiledPack {
    /// Resolve decoders and validate the mapping.
    pub fn compile(spec: Pack) -> Result<Self> {
        if spec.identity.id.trim().is_empty() {
            return Err(PackError::Invalid("identity.id must not be empty".into()));
        }
        if spec.identity.vendor.trim().is_empty() || spec.identity.product.trim().is_empty() {
            return Err(PackError::Invalid(
                "identity.vendor and identity.product must not be empty".into(),
            ));
        }
        if spec.identity.detect.is_empty() {
            return Err(PackError::Invalid(
                "identity.detect must contain at least one non-empty detector".into(),
            ));
        }
        if spec.identity.detect.iter().any(|detector| {
            detector.starts_with.is_none()
                && detector.contains_all.is_empty()
                && detector.contains_any.is_empty()
                && !detector.syslog_tag
                && !detector.loghub_syslog_prefix
        }) {
            return Err(PackError::Invalid(
                "identity.detect contains an empty detector".into(),
            ));
        }
        if spec.extract.is_empty() {
            return Err(PackError::Invalid(
                "extract must contain at least one decoder".into(),
            ));
        }

        let mut decoders = Vec::with_capacity(spec.extract.len());
        for step in &spec.extract {
            if step.decoder.trim().is_empty() {
                return Err(PackError::Invalid(
                    "extract.decoder must not be empty".into(),
                ));
            }
            let decoder = build_decoder(step)?;
            decoders.push((decoder, step.optional));
        }

        for required in ["class_uid", "activity_id"] {
            if !spec.map.contains_key(required) {
                return Err(PackError::Invalid(format!(
                    "map.{required} is required for every Source Pack"
                )));
            }
        }

        let mut mapping = Vec::with_capacity(spec.map.len());
        for (path, entry) in &spec.map {
            validate_target_path(path, entry)?;
            let compiled = match entry {
                MapSpec::Literal(v) => CompiledSpec::Literal(v.clone()),
                MapSpec::Field(f) => CompiledSpec::Field(Box::new(compile_field(f, &spec)?)),
            };
            mapping.push((path.clone(), compiled));
        }
        // Shallower paths first, so `src_endpoint` cannot be created as a leaf
        // after `src_endpoint.ip` already made it an object.
        mapping.sort_by_key(|(path, _)| path.matches('.').count());

        Ok(Self {
            id: spec.identity.id.clone(),
            vendor: spec.identity.vendor.clone(),
            product: spec.identity.product.clone(),
            version: spec.identity.version.clone(),
            log_format: spec.identity.log_format.clone(),
            priority: spec.identity.priority,
            detectors: spec.identity.detect.clone(),
            decoders,
            mapping,
            enums: spec.enums.clone(),
            spec,
        })
    }

    /// Whether this pack claims `raw`.
    pub fn claims(&self, raw: &str) -> bool {
        self.detectors.iter().any(|d| d.matches(raw))
    }

    /// Run the decoder chain, producing a flat field map.
    pub fn extract<'a>(&self, raw: &'a str) -> Result<FieldMap<'a>> {
        let mut fields = FieldMap::with_capacity(32);
        let mut current = raw;

        for (i, (decoder, optional)) in self.decoders.iter().enumerate() {
            match decoder.decode(current) {
                Ok(Decoded { fields: got, body }) => {
                    fields.merge_keeping_existing(got);
                    match body {
                        Some(inner) => current = inner,
                        // A terminal decoder ends the chain; anything after it
                        // would have nothing to read.
                        None => break,
                    }
                }
                Err(e) => {
                    if *optional {
                        continue;
                    }
                    return Err(PackError::Extract {
                        pack: self.id.clone(),
                        step: i,
                        decoder: decoder.name().to_string(),
                        source: e,
                    });
                }
            }
        }
        Ok(fields)
    }

    /// Map extracted fields onto an OCSF event.
    pub fn normalize(
        &self,
        fields: &FieldMap<'_>,
        raw: &[u8],
        ctx: &NormalizeCtx<'_>,
    ) -> Result<OcsfEvent> {
        let NormalizeCtx {
            envelope,
            raw_ref,
            hash,
            event_uid,
            inline_raw,
        } = ctx;
        let (hash, raw_ref) = (*hash, *raw_ref);
        let class_uid = self.required_int(fields, "class_uid")?;
        let activity_id = self.required_int(fields, "activity_id")?;
        if class_uid <= 0 {
            return Err(PackError::Mapping {
                pack: self.id.clone(),
                path: "class_uid".into(),
                detail: "must be a positive OCSF class identifier".into(),
            });
        }
        if !(0..=99).contains(&activity_id) {
            return Err(PackError::Mapping {
                pack: self.id.clone(),
                path: "activity_id".into(),
                detail: "must be in the OCSF activity range 0..=99".into(),
            });
        }
        let time = match self.lookup(fields, "time")? {
            Some(v) => v.as_i64().ok_or_else(|| PackError::Mapping {
                pack: self.id.clone(),
                path: "time".into(),
                detail: "did not resolve to an integer timestamp".into(),
            })?,
            // No usable device timestamp: fall back to receipt time rather than
            // dropping the event. `metadata.logged_time` records both, so the
            // substitution stays visible to an analyst.
            None => envelope.received_at,
        };
        let severity_id = self
            .lookup(fields, "severity_id")?
            .and_then(|v| v.as_i64())
            .unwrap_or(1);
        if !matches!(severity_id, 0..=6 | 99) {
            return Err(PackError::Mapping {
                pack: self.id.clone(),
                path: "severity_id".into(),
                detail: "must be one of 0..=6 or 99".into(),
            });
        }
        let severity_id = severity_id as u8;

        let mut metadata = Metadata::new(
            SCHEMA_VERSION,
            Product::new(self.vendor.clone(), self.product.clone()),
        );
        metadata.product.version = self.version.clone();
        metadata.uid = Some(event_uid.clone());
        metadata.log_format = self.log_format.clone();
        metadata.log_provider = Some(self.id.clone());
        metadata.logged_time = Some(envelope.received_at);
        metadata.processed_time = Some(ulpf_core::now_nanos());
        let mut builder = EventBuilder::new()
            .class(class_uid)
            .activity(activity_id)
            .time(time)
            .severity_id(severity_id)
            .metadata(metadata);

        // The vault already holds the original bytes, and the event carries a
        // locator plus a fingerprint for them. Inlining the text as well makes
        // every event carry its own source a second time — measured at roughly
        // a 2x expansion of the output stream on real perimeter logs. Keep the
        // fingerprint and size unconditionally, since those are what prove the
        // retrieved bytes are the right ones; inline the text only when there is
        // no vault to retrieve from, or when the operator asks.
        let fingerprint = Fingerprint::over_raw(hash, raw);
        builder = if *inline_raw || raw_ref.is_none() {
            builder.raw(raw, fingerprint)
        } else {
            builder.raw_reference(raw.len(), fingerprint)
        };

        // Reserved paths are consumed by the builder itself.
        const RESERVED: [&str; 6] = [
            "class_uid",
            "activity_id",
            "time",
            "severity_id",
            "category_uid",
            "type_uid",
        ];

        let mut observables: Vec<Observable> = Vec::new();
        for (path, spec) in &self.mapping {
            if RESERVED.contains(&path.as_str()) {
                continue;
            }
            let Some(value) = self.resolve(fields, spec)? else {
                continue;
            };
            if let CompiledSpec::Field(f) = spec {
                if let (Some(ty), Some(s)) = (f.observable, value.as_str()) {
                    observables.push(Observable::new(path.clone(), ty, s));
                }
            }
            builder = builder.set(path, value).map_err(|e| PackError::Mapping {
                pack: self.id.clone(),
                path: path.clone(),
                detail: e.to_string(),
            })?;
        }

        let mut event = builder.build().map_err(|e| PackError::Mapping {
            pack: self.id.clone(),
            path: "<base>".into(),
            detail: e.to_string(),
        })?;

        for obs in observables {
            event.push_observable(obs);
        }

        // Anything extracted but not mapped is kept rather than discarded, so a
        // later pack revision can pick it up without reparsing the archive.
        // Only the candidate that actually supplied a value is consumed. If a
        // pack says `from: [src, sourceAddress]` and both fields are present,
        // the second one remains in `unmapped` instead of silently vanishing.
        let used_fields: std::collections::HashSet<&str> = self
            .mapping
            .iter()
            .filter_map(|(_, spec)| match spec {
                CompiledSpec::Field(field) => field
                    .candidates
                    .iter()
                    .find(|name| fields.get_present(name).is_some())
                    .map(String::as_str),
                CompiledSpec::Literal(_) => None,
            })
            .collect();
        for (key, value) in fields.iter() {
            if used_fields.contains(key) || value.is_empty_marker() {
                continue;
            }
            event.set_unmapped(key, value_to_json(value));
        }

        Ok(event)
    }

    fn required_int(&self, fields: &FieldMap<'_>, path: &str) -> Result<i64> {
        self.lookup(fields, path)?
            .and_then(|v| v.as_i64())
            .ok_or_else(|| PackError::Mapping {
                pack: self.id.clone(),
                path: path.into(),
                detail: "required attribute is absent or not an integer".into(),
            })
    }

    fn lookup(&self, fields: &FieldMap<'_>, path: &str) -> Result<Option<serde_json::Value>> {
        match self.mapping.iter().find(|(p, _)| p == path) {
            Some((_, spec)) => self.resolve(fields, spec),
            None => Ok(None),
        }
    }

    fn resolve(
        &self,
        fields: &FieldMap<'_>,
        spec: &CompiledSpec,
    ) -> Result<Option<serde_json::Value>> {
        let field = match spec {
            CompiledSpec::Literal(v) => return Ok(Some(v.clone())),
            CompiledSpec::Field(f) => f,
        };

        let found = field
            .candidates
            .iter()
            .find_map(|name| fields.get_present(name));

        let Some(value) = found else {
            return Ok(field.default.clone());
        };

        // Enum lookup happens on the raw string, before any cast, because the
        // table keys are what the device actually wrote.
        if let Some(table_name) = &field.enum_table {
            let table = self.enums.get(table_name).ok_or_else(|| {
                PackError::Invalid(format!("mapping references unknown enum `{table_name}`"))
            })?;
            // Enum keys are YAML strings, but the extracted value may be a
            // number - a numeric status code, a severity level, or the index of
            // the regex alternative that matched. Look the value up in its own
            // form and in its decimal form, so `"2": 3` matches both.
            let mut candidates: Vec<String> = Vec::new();
            if let Some(key) = value.as_str() {
                candidates.push(key.to_string());
                candidates.push(key.to_ascii_lowercase());
            }
            if let Some(n) = value.as_int() {
                candidates.push(n.to_string());
            }
            for key in &candidates {
                if let Some(mapped) = table.get(key) {
                    return Ok(Some(mapped.clone()));
                }
            }
            return Ok(field.default.clone());
        }

        if let Some(format) = field.format {
            return match parse_time(value, format) {
                Some(nanos) => Ok(Some(serde_json::json!(nanos))),
                None => Ok(field.default.clone()),
            };
        }

        let out = match field.cast {
            Some(Cast::Int) => value.as_int().map(|i| serde_json::json!(i)),
            Some(Cast::Float) => value.as_float().map(|f| serde_json::json!(f)),
            Some(Cast::Bool) => value.as_bool().map(|b| serde_json::json!(b)),
            Some(Cast::String) => Some(serde_json::json!(value_to_string(value))),
            None => Some(value_to_json(value)),
        };
        Ok(out.or_else(|| field.default.clone()))
    }
}

fn compile_field(f: &FieldSpec, pack: &Pack) -> Result<CompiledField> {
    if f.from.candidates().is_empty()
        || f.from
            .candidates()
            .iter()
            .any(|name| name.trim().is_empty())
    {
        return Err(PackError::Invalid(
            "mapping `from` must name at least one non-empty source field".into(),
        ));
    }
    if f.format.is_some() && (f.cast.is_some() || f.enum_table.is_some()) {
        return Err(PackError::Invalid(
            "a mapping with `format` cannot also declare `as` or `enum`".into(),
        ));
    }
    if let Some(table) = &f.enum_table {
        if !pack.enums.contains_key(table) {
            return Err(PackError::Invalid(format!(
                "mapping references unknown enum `{table}`"
            )));
        }
    }
    let observable = match f.observable.as_deref() {
        None => None,
        Some(name) => Some(parse_observable(name)?),
    };
    Ok(CompiledField {
        candidates: f.from.candidates().to_vec(),
        cast: f.cast,
        format: f.format,
        enum_table: f.enum_table.clone(),
        default: f.default.clone(),
        observable,
    })
}

fn validate_target_path(path: &str, entry: &MapSpec) -> Result<()> {
    if path.trim().is_empty()
        || path.starts_with('.')
        || path.ends_with('.')
        || path.split('.').any(str::is_empty)
    {
        return Err(PackError::Invalid(format!(
            "mapping target `{path}` is not a valid dotted OCSF path"
        )));
    }

    const FRAMEWORK_OWNED: [&str; 6] = [
        "metadata",
        "raw_data",
        "raw_data_hash",
        "raw_data_size",
        "attestation_list",
        "observables",
    ];
    if FRAMEWORK_OWNED
        .iter()
        .any(|reserved| path == *reserved || path.starts_with(&format!("{reserved}.")))
    {
        return Err(PackError::Invalid(format!(
            "mapping target `{path}` is owned by the ULPF pipeline"
        )));
    }
    if matches!(path, "category_uid" | "type_uid") {
        return Err(PackError::Invalid(format!(
            "mapping target `{path}` is derived from class_uid/activity_id"
        )));
    }

    // A mapping-shaped object that failed FieldSpec deserialization would
    // otherwise fall through the untagged enum as a JSON literal, hiding YAML
    // typos such as `form:`. Reject those objects explicitly.
    if let MapSpec::Literal(serde_json::Value::Object(object)) = entry {
        let mapping_words = [
            "from",
            "form",
            "as",
            "format",
            "enum",
            "default",
            "observable",
        ];
        if object
            .keys()
            .any(|key| mapping_words.contains(&key.as_str()))
        {
            return Err(PackError::Invalid(format!(
                "mapping target `{path}` contains an invalid field specification"
            )));
        }
    }
    Ok(())
}

fn parse_observable(name: &str) -> Result<ObservableType> {
    Ok(match name {
        "hostname" => ObservableType::Hostname,
        "ip" => ObservableType::IpAddress,
        "mac" => ObservableType::MacAddress,
        "user" | "username" => ObservableType::UserName,
        "email" => ObservableType::Email,
        "url" => ObservableType::Url,
        "domain" => ObservableType::DomainName,
        "port" => ObservableType::Port,
        other => {
            return Err(PackError::Invalid(format!(
                "unknown observable type `{other}`"
            )))
        }
    })
}

fn build_decoder(step: &crate::spec::ExtractStep) -> Result<Box<dyn Decoder>> {
    use ulpf_decode::{csv::CsvDecoder, keyvalue::KeyValueDecoder, regex_dec::RegexDecoder};

    // Parameterised decoders are constructed directly so a pack can tune them;
    // the rest come from the built-in registry.
    match step.decoder.as_str() {
        "keyvalue" => Ok(Box::new(KeyValueDecoder {
            separator: step.sep.unwrap_or('='),
            delimiter: step.delim.unwrap_or(' '),
            unquote: true,
        })),
        "regex" => {
            if step.patterns.is_empty() {
                return Err(PackError::Invalid(
                    "the `regex` decoder requires at least one entry in `patterns`".into(),
                ));
            }
            // Compiling here means an invalid pattern fails at pack load, not
            // on the first event that happens to reach it in production.
            let d = RegexDecoder::new(&step.patterns)
                .map_err(|e| PackError::Invalid(format!("invalid regex in pack: {e}")))?
                .record_which(step.patterns.len() > 1);
            Ok(Box::new(d))
        }
        "csv" => Ok(Box::new(CsvDecoder {
            delimiter: step.delim.unwrap_or(','),
            headers: step.headers.clone(),
            keep_positional: true,
        })),
        other => {
            ulpf_decode::builtin(other).ok_or_else(|| PackError::UnknownDecoder(other.to_string()))
        }
    }
}

fn value_to_json(v: &Value<'_>) -> serde_json::Value {
    match v {
        Value::Str(s) => serde_json::Value::String(s.to_string()),
        Value::Int(i) => serde_json::json!(i),
        Value::Float(f) => serde_json::json!(f),
        Value::Bool(b) => serde_json::json!(b),
        Value::Null => serde_json::Value::Null,
    }
}

fn value_to_string(v: &Value<'_>) -> String {
    match v {
        Value::Str(s) => s.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
    }
}
