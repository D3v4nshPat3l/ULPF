//! Source Packs: declarative, hot-loadable log source definitions.
//!
//! One pack file describes a log source completely — how to recognise it, how
//! to pull fields out, how those fields become OCSF, and what the result must
//! look like for a set of sample lines. Adding a source means dropping a file
//! into a directory: no recompile, no plugin ABI, no restart. That is
//! requirement (e), and the reason requirement (i) is achievable at all.
//!
//! Because fixtures ship inside the pack, [`PackLibrary::test_all`] can score
//! the entire library in CI, and a pack drafted by the generator arrives with a
//! coverage and accuracy number attached before a human is asked to approve it.

pub mod compiled;
pub mod error;
pub mod library;
pub mod spec;
pub mod time;

pub use compiled::{CompiledPack, NormalizeCtx};
pub use error::{PackError, Result};
pub use library::{FixtureFailure, PackLibrary, PackTestReport};
pub use spec::{Detector, Fixture, Identity, Pack};

#[cfg(test)]
mod tests {
    use super::*;
    use ulpf_core::{Envelope, Transport};
    use ulpf_ocsf::types::HashAlgorithm;

    const FORTIGATE: &str = r#"
identity:
  id: fortinet-fortigate-traffic
  vendor: Fortinet
  product: FortiGate
  log_format: syslog-keyvalue
  detect:
    - contains_all: ["devname=", "type=traffic"]
extract:
  - decoder: syslog
  - decoder: keyvalue
map:
  class_uid: 4001
  activity_id:
    from: action
    enum: fg_action
    default: 6
  severity_id:
    from: level
    enum: fg_level
    default: 1
  time:
    from: [eventtime, date]
    format: epoch_s
  src_endpoint.ip:
    from: srcip
    observable: ip
  src_endpoint.port:
    from: srcport
    as: int
  dst_endpoint.ip:
    from: dstip
    observable: ip
  dst_endpoint.port:
    from: dstport
    as: int
  traffic.bytes_out:
    from: sentbyte
    as: int
  traffic.bytes_in:
    from: rcvdbyte
    as: int
enums:
  fg_action:
    accept: 6
    deny: 3
    close: 2
  fg_level:
    notice: 1
    warning: 3
    critical: 5
fixtures:
  - raw: '<134>date=2026-08-31 time=10:23:45 devname="FGT-DEL-01" type=traffic subtype=forward level=warning eventtime=1756636800 srcip=10.2.4.7 srcport=52341 dstip=8.8.8.8 dstport=443 proto=6 action=accept sentbyte=2500 rcvdbyte=2200'
    expect:
      class_uid: 4001
      src_endpoint.ip: 10.2.4.7
      dst_endpoint.port: 443
"#;

    fn pack() -> CompiledPack {
        let spec: Pack = serde_yaml::from_str(FORTIGATE).unwrap();
        CompiledPack::compile(spec).unwrap()
    }

    const LINE: &str = r#"<134>date=2026-08-31 time=10:23:45 devname="FGT-DEL-01" type=traffic subtype=forward level=warning eventtime=1756636800 srcip=10.2.4.7 srcport=52341 dstip=8.8.8.8 dstport=443 proto=6 action=accept sentbyte=2500 rcvdbyte=2200"#;

    fn normalize(p: &CompiledPack, line: &str) -> ulpf_ocsf::OcsfEvent {
        let fields = p.extract(line).unwrap();
        let envelope = Envelope::new(Transport::SyslogUdp, "r1");
        let ctx = NormalizeCtx::new(&envelope, "test-uid").with_hash(HashAlgorithm::Sha256);
        p.normalize(&fields, line.as_bytes(), &ctx).unwrap()
    }

    #[test]
    fn detects_its_own_source() {
        let p = pack();
        assert!(p.claims(LINE));
        assert!(!p.claims("<134>date=2026-08-31 devname=\"FGT\" type=event"));
    }

    #[test]
    fn extracts_through_the_decoder_chain() {
        let p = pack();
        let f = p.extract(LINE).unwrap();
        // From the syslog envelope...
        assert_eq!(f.get("syslog.priority").unwrap().as_int(), Some(134));
        // ...and from the key-value body.
        assert_eq!(f.get_str("srcip"), Some("10.2.4.7"));
        assert_eq!(f.get_str("devname"), Some("FGT-DEL-01"));
    }

    #[test]
    fn normalizes_to_a_valid_ocsf_event() {
        let ev = normalize(&pack(), LINE);
        assert_eq!(ev.class_uid(), Some(4001));
        assert_eq!(ev.type_uid(), Some(400106)); // accept -> Traffic (6)
        assert_eq!(ev.as_map()["category_uid"], serde_json::json!(4));
        assert_eq!(ev.get_path("src_endpoint.ip").unwrap(), "10.2.4.7");
        assert_eq!(ev.get_path("src_endpoint.port").unwrap(), 52341);
        assert_eq!(ev.get_path("dst_endpoint.ip").unwrap(), "8.8.8.8");
        assert_eq!(ev.get_path("traffic.bytes_out").unwrap(), 2500);
    }

    #[test]
    fn maps_the_device_timestamp_not_the_receipt_time() {
        let ev = normalize(&pack(), LINE);
        assert_eq!(
            ev.as_map()["time"],
            serde_json::json!(1_756_636_800_000_000_000i64)
        );
    }

    #[test]
    fn enum_lookup_translates_device_vocabulary() {
        let p = pack();
        let denied = LINE.replace("action=accept", "action=deny");
        let ev = normalize(&p, &denied);
        // deny -> Reset (3), which is how OCSF models a middlebox drop.
        assert_eq!(ev.as_map()["activity_id"], serde_json::json!(3));
        assert_eq!(ev.type_uid(), Some(400103));
    }

    #[test]
    fn unknown_enum_value_falls_back_to_the_default() {
        let p = pack();
        let odd = LINE.replace("action=accept", "action=quarantine");
        let ev = normalize(&p, &odd);
        assert_eq!(ev.as_map()["activity_id"], serde_json::json!(6));
    }

    #[test]
    fn raw_data_is_carried_with_its_fingerprint() {
        let ev = normalize(&pack(), LINE);
        assert_eq!(ev.as_map()["raw_data"], serde_json::json!(LINE));
        assert_eq!(ev.as_map()["raw_data_size"], serde_json::json!(LINE.len()));
        assert!(ev.as_map()["raw_data_hash"]["value"].is_string());
    }

    #[test]
    fn observables_are_emitted_for_marked_fields() {
        let ev = normalize(&pack(), LINE);
        let obs = ev.as_map()["observables"].as_array().unwrap();
        let ips: Vec<&str> = obs.iter().filter_map(|o| o["value"].as_str()).collect();
        assert!(ips.contains(&"10.2.4.7"));
        assert!(ips.contains(&"8.8.8.8"));
        assert!(obs.iter().all(|o| o["type_id"] == 2));
    }

    #[test]
    fn unmapped_fields_are_preserved_rather_than_dropped() {
        // `subtype` and `proto` have no mapping, but the information must not
        // vanish — a later pack revision should be able to use them.
        let ev = normalize(&pack(), LINE);
        let unmapped = ev.as_map()["unmapped"].as_object().unwrap();
        assert_eq!(unmapped["subtype"], serde_json::json!("forward"));
        assert_eq!(unmapped["proto"], serde_json::json!("6"));
        assert_eq!(unmapped["devname"], serde_json::json!("FGT-DEL-01"));
    }

    #[test]
    fn a_missing_timestamp_falls_back_to_receipt_time() {
        let p = pack();
        let no_time = LINE.replace("eventtime=1756636800 ", "");
        let fields = p.extract(&no_time).unwrap();
        let envelope = Envelope::new(Transport::SyslogUdp, "r1");
        let ctx = NormalizeCtx::new(&envelope, "uid").with_hash(HashAlgorithm::Sha256);
        let ev = p.normalize(&fields, no_time.as_bytes(), &ctx).unwrap();
        // The `date` candidate is not epoch seconds, so receipt time is used.
        assert_eq!(ev.as_map()["time"], serde_json::json!(envelope.received_at));
    }

    #[test]
    fn metadata_records_provenance_of_the_normalization() {
        let ev = normalize(&pack(), LINE);
        assert_eq!(
            ev.get_path("metadata.product.vendor_name").unwrap(),
            "Fortinet"
        );
        assert_eq!(
            ev.get_path("metadata.log_format").unwrap(),
            "syslog-keyvalue"
        );
        assert_eq!(
            ev.get_path("metadata.log_provider").unwrap(),
            "fortinet-fortigate-traffic"
        );
        assert_eq!(ev.get_path("metadata.version").unwrap(), "1.9.0");
    }

    #[test]
    fn compilation_rejects_an_unknown_decoder() {
        let yaml = r#"
identity: { id: t, vendor: v, product: p, detect: [{ contains_all: [probe] }] }
extract: [{ decoder: protobuf }]
map: { class_uid: 4001, activity_id: 1, time: 1 }
"#;
        let spec: Pack = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            CompiledPack::compile(spec),
            Err(PackError::UnknownDecoder(_))
        ));
    }

    #[test]
    fn compilation_rejects_an_empty_extract_chain() {
        let yaml = r#"
identity: { id: t, vendor: v, product: p }
extract: []
map: { class_uid: 4001 }
"#;
        let spec: Pack = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            CompiledPack::compile(spec),
            Err(PackError::Invalid(_))
        ));
    }

    #[test]
    fn compilation_rejects_an_unknown_observable_type() {
        let yaml = r#"
identity: { id: t, vendor: v, product: p, detect: [{ contains_all: [srcip=] }] }
extract: [{ decoder: keyvalue }]
map:
  src_endpoint.ip: { from: srcip, observable: teapot }
"#;
        let spec: Pack = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            CompiledPack::compile(spec),
            Err(PackError::Invalid(_))
        ));
    }

    #[test]
    fn parent_paths_are_written_before_children() {
        // A mapping that sets both `src_endpoint` and `src_endpoint.ip` must
        // not fail depending on BTreeMap iteration order.
        let yaml = r#"
identity: { id: t, vendor: v, product: p, detect: [{ contains_all: [srcip=] }] }
extract: [{ decoder: keyvalue }]
map:
  class_uid: 4001
  activity_id: 6
  time: 1756636800000000000
  src_endpoint.ip: { from: srcip }
  src_endpoint.port: { from: srcport, as: int }
"#;
        let spec: Pack = serde_yaml::from_str(yaml).unwrap();
        let p = CompiledPack::compile(spec).unwrap();
        let ev = normalize(&p, "srcip=10.0.0.1 srcport=443");
        assert_eq!(ev.get_path("src_endpoint.ip").unwrap(), "10.0.0.1");
        assert_eq!(ev.get_path("src_endpoint.port").unwrap(), 443);
    }
}
