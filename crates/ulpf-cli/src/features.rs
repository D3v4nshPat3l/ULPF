//! A columnar feature table with a stable column contract.
//!
//! This is requirement (h) — AI/ML-ready analytics. The Parquet archive in
//! [`crate::sinks`] preserves whole OCSF documents, which is right for
//! retention and wrong for training: a consumer has to re-derive every field
//! from JSON, and the shape they derive shifts whenever a pack changes what it
//! maps. A model trained last month then sees different columns this month
//! with nothing to signal it.
//!
//! The contract here is fixed in code and versioned. [`COLUMNS`] is the whole
//! of it. A pack that starts mapping a new attribute does not add a column; a
//! pack that stops mapping one leaves its column present and empty. Adding a
//! column is a deliberate change to this file, recorded in
//! `docs/FEATURE_TABLE.md` and reflected in [`CONTRACT_VERSION`].
//!
//! Every column is required rather than nullable, because a feature table is
//! consumed densely and a null costs the reader a branch on every row.
//! Absence is therefore a documented sentinel: `-1` for a number that cannot
//! be negative in its own right, the empty string for text. Both are stated in
//! the contract so a reader never has to guess whether `0` means "zero" or
//! "missing".

use std::path::Path;

use ulpf_ocsf::OcsfEvent;

use crate::parquet::{ColumnSpec, ColumnType, ParquetWriter, Value};

/// Bumped whenever [`COLUMNS`] changes. A consumer that pins this knows the
/// shape it was trained against.
pub const CONTRACT_VERSION: u32 = 1;

/// A number that is absent rather than zero.
pub const ABSENT_NUMBER: i64 = -1;

/// The column contract. Order is part of it.
pub const COLUMNS: &[ColumnSpec] = &[
    // --- lineage: what produced this row, and can it be reproduced ---------
    ColumnSpec::new("event_uid", ColumnType::Utf8),
    ColumnSpec::new("time_ns", ColumnType::Int64),
    ColumnSpec::new("epoch_seconds", ColumnType::Int64),
    ColumnSpec::new("pack_id", ColumnType::Utf8),
    ColumnSpec::new("vendor", ColumnType::Utf8),
    ColumnSpec::new("product", ColumnType::Utf8),
    ColumnSpec::new("disposition", ColumnType::Utf8),
    // --- classification ----------------------------------------------------
    ColumnSpec::new("class_uid", ColumnType::Int64),
    ColumnSpec::new("category_uid", ColumnType::Int64),
    ColumnSpec::new("activity_id", ColumnType::Int64),
    ColumnSpec::new("type_uid", ColumnType::Int64),
    ColumnSpec::new("severity_id", ColumnType::Int64),
    // --- network -----------------------------------------------------------
    ColumnSpec::new("src_ip", ColumnType::Utf8),
    ColumnSpec::new("src_port", ColumnType::Int64),
    ColumnSpec::new("dst_ip", ColumnType::Utf8),
    ColumnSpec::new("dst_port", ColumnType::Int64),
    ColumnSpec::new("protocol", ColumnType::Utf8),
    ColumnSpec::new("device_hostname", ColumnType::Utf8),
    // --- derived: cheap here, and otherwise recomputed by every consumer ---
    ColumnSpec::new("hour_of_day", ColumnType::Int64),
    ColumnSpec::new("day_of_week", ColumnType::Int64),
    ColumnSpec::new("src_is_private", ColumnType::Int64),
    ColumnSpec::new("dst_is_private", ColumnType::Int64),
    // --- finding -----------------------------------------------------------
    ColumnSpec::new("is_alert", ColumnType::Int64),
    ColumnSpec::new("finding_uid", ColumnType::Utf8),
];

pub struct FeatureSink {
    writer: ParquetWriter,
}

impl FeatureSink {
    pub fn create(dir: &Path, batch_size: usize) -> anyhow::Result<Self> {
        Ok(Self {
            // The contract version travels in the footer, so a consumer can
            // check what a file was written against rather than assuming.
            writer: ParquetWriter::create(
                dir,
                "features",
                COLUMNS,
                format!("ulpf feature table v{CONTRACT_VERSION}"),
                batch_size,
            )?,
        })
    }

    pub fn write(&mut self, event: &OcsfEvent) -> anyhow::Result<()> {
        self.writer.push(row_for(event))
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.writer.flush()
    }

    pub fn finish(self) -> anyhow::Result<()> {
        self.writer.finish()
    }
}

fn text(event: &OcsfEvent, path: &str) -> Value {
    Value::Text(
        event
            .get_path(path)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
    )
}

fn number(event: &OcsfEvent, path: &str) -> Value {
    Value::Int(
        event
            .get_path(path)
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(ABSENT_NUMBER),
    )
}

/// True when an address is in a range that never appears on the public
/// internet. Kept deliberately simple and total: an address that will not
/// parse is treated as not private rather than as an error, because a feature
/// row must exist for every event including the malformed ones.
fn is_private(addr: &str) -> Option<bool> {
    if addr.is_empty() {
        return None;
    }
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            Some(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified())
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            // `is_unique_local` and `is_unicast_link_local` are unstable, so
            // the two prefixes are matched directly: fc00::/7 and fe80::/10.
            let segments = v6.segments();
            Some(
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (segments[0] & 0xfe00) == 0xfc00
                    || (segments[0] & 0xffc0) == 0xfe80,
            )
        }
        Err(_) => Some(false),
    }
}

fn private_flag(addr: &Value) -> Value {
    let Value::Text(text) = addr else {
        return Value::Int(ABSENT_NUMBER);
    };
    match is_private(text) {
        Some(true) => Value::Int(1),
        Some(false) => Value::Int(0),
        None => Value::Int(ABSENT_NUMBER),
    }
}

fn row_for(event: &OcsfEvent) -> Vec<Value> {
    let time_ns = event
        .get_path("time")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(ABSENT_NUMBER);

    // Seconds as well as nanoseconds, because nanoseconds since the epoch
    // exceed 2^53 and any consumer going through JSON or JavaScript rounds
    // them. Both are carried so neither audience has to convert.
    let (epoch_seconds, hour, weekday) = if time_ns > 0 {
        let seconds = time_ns / 1_000_000_000;
        match chrono::DateTime::from_timestamp(seconds, 0) {
            Some(dt) => {
                use chrono::{Datelike, Timelike};
                (
                    seconds,
                    i64::from(dt.hour()),
                    dt.weekday().num_days_from_monday() as i64,
                )
            }
            None => (seconds, ABSENT_NUMBER, ABSENT_NUMBER),
        }
    } else {
        (ABSENT_NUMBER, ABSENT_NUMBER, ABSENT_NUMBER)
    };

    let src_ip = text(event, "src_endpoint.ip");
    let dst_ip = text(event, "dst_endpoint.ip");
    let src_private = private_flag(&src_ip);
    let dst_private = private_flag(&dst_ip);

    // Only a record the pipeline could not fully handle carries a disposition;
    // anything else got here by being parsed.
    let disposition = event
        .get_path("unmapped.ulpf_disposition")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("parsed")
        .to_string();

    let is_alert = match event
        .get_path("is_alert")
        .and_then(serde_json::Value::as_bool)
    {
        Some(true) => 1,
        Some(false) => 0,
        None => ABSENT_NUMBER,
    };

    vec![
        text(event, "metadata.uid"),
        Value::Int(time_ns),
        Value::Int(epoch_seconds),
        text(event, "metadata.log_provider"),
        text(event, "metadata.product.vendor_name"),
        text(event, "metadata.product.name"),
        Value::Text(disposition),
        number(event, "class_uid"),
        number(event, "category_uid"),
        number(event, "activity_id"),
        number(event, "type_uid"),
        number(event, "severity_id"),
        src_ip,
        number(event, "src_endpoint.port"),
        dst_ip,
        number(event, "dst_endpoint.port"),
        text(event, "connection_info.protocol_name"),
        text(event, "device.hostname"),
        Value::Int(hour),
        Value::Int(weekday),
        src_private,
        dst_private,
        Value::Int(is_alert),
        text(event, "finding_info.uid"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ulpf_ocsf::types::{Metadata, Product, Severity};
    use ulpf_ocsf::EventBuilder;

    fn event() -> OcsfEvent {
        let mut metadata = Metadata::new(
            ulpf_ocsf::SCHEMA_VERSION,
            Product::new("Snort", "Snort NIDS"),
        );
        metadata.uid = Some("uid-1".into());
        metadata.log_provider = Some("snort-nids-alert".into());
        EventBuilder::new()
            .class(2004)
            .activity(1)
            .time(1_756_636_800_000_000_000)
            .severity(Severity::High)
            .metadata(metadata)
            .set("src_endpoint.ip", json!("10.1.2.3"))
            .unwrap()
            .set("dst_endpoint.ip", json!("8.8.8.8"))
            .unwrap()
            .set("src_endpoint.port", json!(4455))
            .unwrap()
            .build()
            .unwrap()
    }

    fn column(row: &[Value], name: &str) -> Value {
        let index = COLUMNS
            .iter()
            .position(|c| c.name == name)
            .expect("column is in the contract");
        row[index].clone()
    }

    #[test]
    fn a_row_has_exactly_one_value_per_column() {
        assert_eq!(row_for(&event()).len(), COLUMNS.len());
    }

    #[test]
    fn column_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for spec in COLUMNS {
            assert!(seen.insert(spec.name), "duplicate column {}", spec.name);
        }
    }

    #[test]
    fn values_match_their_declared_types() {
        let row = row_for(&event());
        for (spec, value) in COLUMNS.iter().zip(&row) {
            match (spec.ty, value) {
                (ColumnType::Int64, Value::Int(_)) | (ColumnType::Utf8, Value::Text(_)) => {}
                _ => panic!(
                    "{} declares {:?} but produced {value:?}",
                    spec.name, spec.ty
                ),
            }
        }
    }

    #[test]
    fn known_fields_are_carried_through() {
        let row = row_for(&event());
        assert_eq!(column(&row, "event_uid"), Value::Text("uid-1".into()));
        assert_eq!(
            column(&row, "pack_id"),
            Value::Text("snort-nids-alert".into())
        );
        assert_eq!(column(&row, "class_uid"), Value::Int(2004));
        assert_eq!(column(&row, "src_ip"), Value::Text("10.1.2.3".into()));
        assert_eq!(column(&row, "src_port"), Value::Int(4455));
        assert_eq!(column(&row, "disposition"), Value::Text("parsed".into()));
    }

    /// Absence has to be distinguishable from a real zero, or a model cannot
    /// tell "port 0" from "no port".
    #[test]
    fn absent_values_use_the_documented_sentinels() {
        let row = row_for(&event());
        assert_eq!(column(&row, "dst_port"), Value::Int(ABSENT_NUMBER));
        assert_eq!(column(&row, "protocol"), Value::Text(String::new()));
        assert_eq!(column(&row, "finding_uid"), Value::Text(String::new()));
        assert_eq!(column(&row, "is_alert"), Value::Int(ABSENT_NUMBER));
    }

    #[test]
    fn private_ranges_are_recognised() {
        assert_eq!(is_private("10.1.2.3"), Some(true));
        assert_eq!(is_private("192.168.0.1"), Some(true));
        assert_eq!(is_private("172.16.5.4"), Some(true));
        assert_eq!(is_private("127.0.0.1"), Some(true));
        assert_eq!(is_private("169.254.1.1"), Some(true));
        assert_eq!(is_private("8.8.8.8"), Some(false));
        assert_eq!(is_private("11.11.79.100"), Some(false));
        assert_eq!(is_private("fd00::1"), Some(true));
        assert_eq!(is_private("fe80::1"), Some(true));
        assert_eq!(is_private("2001:4860::8888"), Some(false));
        assert_eq!(is_private(""), None);
        // A value that is not an address at all still yields a row.
        assert_eq!(is_private("not-an-address"), Some(false));
    }

    #[test]
    fn the_row_reflects_privacy_of_both_endpoints() {
        let row = row_for(&event());
        assert_eq!(column(&row, "src_is_private"), Value::Int(1));
        assert_eq!(column(&row, "dst_is_private"), Value::Int(0));
    }

    /// The time columns are derived, so they have to agree with each other.
    #[test]
    fn derived_time_columns_agree_with_the_timestamp() {
        let row = row_for(&event());
        let Value::Int(ns) = column(&row, "time_ns") else {
            panic!("time_ns is a number")
        };
        let Value::Int(seconds) = column(&row, "epoch_seconds") else {
            panic!("epoch_seconds is a number")
        };
        assert_eq!(seconds, ns / 1_000_000_000);

        let Value::Int(hour) = column(&row, "hour_of_day") else {
            panic!("hour_of_day is a number")
        };
        let Value::Int(weekday) = column(&row, "day_of_week") else {
            panic!("day_of_week is a number")
        };
        assert!((0..24).contains(&hour), "hour {hour} out of range");
        assert!((0..7).contains(&weekday), "weekday {weekday} out of range");
    }

    /// An event with almost nothing on it must still produce a full row: a
    /// feature table with holes in it is not a table.
    #[test]
    fn a_nearly_empty_event_still_produces_a_full_row() {
        let event = EventBuilder::new()
            .class(4001)
            .activity(6)
            .time(0)
            .severity(Severity::Informational)
            .metadata(Metadata::new(
                ulpf_ocsf::SCHEMA_VERSION,
                Product::new("", ""),
            ))
            .build()
            .unwrap();
        let row = row_for(&event);
        assert_eq!(row.len(), COLUMNS.len());
        assert_eq!(column(&row, "epoch_seconds"), Value::Int(ABSENT_NUMBER));
        assert_eq!(column(&row, "hour_of_day"), Value::Int(ABSENT_NUMBER));
        assert_eq!(column(&row, "src_is_private"), Value::Int(ABSENT_NUMBER));
    }
}
