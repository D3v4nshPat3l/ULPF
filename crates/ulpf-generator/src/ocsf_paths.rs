//! Checks a generated pack's mapped OCSF attribute paths against the real
//! schema, instead of trusting that a path which compiles is a path that
//! means something.
//!
//! `ulpf-pack` happily compiles `map: { url: { from: request } }` — it
//! writes whatever JSON path a pack names, and nothing downstream of that
//! stops it. But `url` is an *object* in OCSF 1.9 (`url_string`, `hostname`,
//! `path`, ...), not a string, so that mapping sets an object-typed
//! attribute to a bare string: it passes a fixture that only checks the
//! string survived, and produces an event no OCSF-aware consumer reads
//! correctly. This module is what catches that class of mistake — found by
//! checking exactly this path against `schema/ocsf/objects/url.json` — before
//! a candidate reaches approval rather than after.
//!
//! # Why a hand-verified table, not a schema resolver
//!
//! The vendored schema uses `extends` chains and `$include` partials to
//! avoid repeating shared attributes across objects, and fully resolving
//! that generically is a bigger job than the one problem this needs to
//! solve. The generator can currently only ever target the handful of paths
//! `llm::ALLOWED_FIELDS` and `llm::infer_field_map` name — every one of
//! those was checked by hand against `schema/ocsf/dictionary.json` and the
//! relevant `schema/ocsf/objects/*.json` files at the vendored 1.9.0
//! version, and that is the table below. Adding a new target path to the
//! generator means adding it here too, checked the same way — the module
//! doc-comment above shows exactly the mistake skipping that check leads to.
//!
//! # Scope: the generator's own output, not arbitrary hand-written packs
//!
//! This is wired into `heuristic::draft_pack` and the model-backed drafting
//! path, not into `/api/approve`. An operator-edited or hand-written pack
//! can legitimately target OCSF paths this table has never enumerated —
//! `linux-iptables-firewall.yaml` maps `src_endpoint.interface_name` and a
//! class-specific `count`, neither of which the generator has ever
//! produced. Gating approval on this table would reject correct, working
//! packs for the sin of using a path nobody taught the generator about.

use std::collections::BTreeSet;

use ulpf_pack::Pack;

/// Every dotted OCSF path the generator can currently target, verified by
/// hand against the vendored schema (see the module doc comment). Keep this
/// in lockstep with `llm::ALLOWED_FIELDS` and the paths named in
/// `llm::infer_field_map`'s rule table.
const KNOWN_PATHS: &[&str] = &[
    // Always present, from a `MapSpec::Literal`, not a field lookup — listed
    // anyway so validating *any* pack's map keys needs no special case for
    // "the three envelope fields every event carries."
    "class_uid",
    "activity_id",
    "severity_id",
    // schema/ocsf/dictionary.json: `message` -> type `string_t` (scalar).
    "message",
    // schema/ocsf/dictionary.json: `src_endpoint` -> type `network_endpoint`;
    // schema/ocsf/objects/network_endpoint.json extends `endpoint`, which
    // declares `ip` and (via its own dictionary-typed fields) `port`.
    "src_endpoint.ip",
    "src_endpoint.port",
    "dst_endpoint.ip",
    "dst_endpoint.port",
    // dictionary.json: `connection_info` -> type `network_connection_info`;
    // objects/network_connection_info.json declares `protocol_name` directly.
    "connection_info.protocol_name",
    // dictionary.json: `device` -> type `device`; objects/device.json
    // declares `hostname` directly.
    "device.hostname",
    // dictionary.json: `actor` -> type `actor`; objects/actor.json declares
    // `user` -> type `user`; objects/user.json declares `name` directly.
    "actor.user.name",
    // dictionary.json: `url` -> type `url` (an object, not `string_t`);
    // objects/url.json declares `url_string` directly. The bug this module
    // exists to catch: an earlier version of the generator mapped straight
    // to bare `url`.
    "url.url_string",
];

/// Whether `path` is one of the paths above.
pub fn is_known_path(path: &str) -> bool {
    KNOWN_PATHS.contains(&path)
}

/// The three envelope literals every OCSF class carries, from `base_event`.
const ENVELOPE_PATHS: &[&str] = &["class_uid", "activity_id", "severity_id"];

/// Which *root* attributes each class the profiler can suggest actually
/// declares, resolved by hand from the vendored 1.9.0 schema through
/// `extends`, `$include` and profile attributes.
///
/// `KNOWN_PATHS` says a path is real. It does not say a path is real *on the
/// class the pack claims to be*, and until the profiler started varying
/// `class_uid` nothing needed it to: every draft was Network Activity (4001),
/// which is the one class here that declares all seven roots. Once a family
/// inference can pick 2004 instead, a drafted map carrying `src_endpoint.ip`
/// becomes a Detection Finding with an attribute Detection Finding does not
/// have — the same "compiles, means nothing" failure the module doc describes,
/// one level up.
///
/// Verified against `schema/ocsf/`:
///
/// * `events/network/network_activity.json` declares `url` directly and
///   inherits `src_endpoint`, `dst_endpoint` and `connection_info` from
///   `network.json`. It is the only class below with `url`.
/// * `events/network/http_activity.json` also extends `network`, but carries
///   its URL inside `http_request`, not as a top-level `url`.
/// * `events/iam/authentication.json`, `events/network/email_activity.json`
///   and `events/system/event_log_activity.json` declare both endpoints but
///   no `connection_info`.
/// * `events/findings/detection_finding.json` extends `finding.json`, which
///   extends `base_event`: it has neither endpoint, no `connection_info` and
///   no `url`.
/// * `device` and `actor` reach all six through the shared `$include`, and
///   `message` through `base_event`.
const CLASS_ROOTS: &[(i64, &[&str])] = &[
    // Network Activity
    (
        4001,
        &[
            "src_endpoint",
            "dst_endpoint",
            "connection_info",
            "device",
            "actor",
            "url",
            "message",
        ],
    ),
    // HTTP Activity — no top-level `url`.
    (
        4002,
        &[
            "src_endpoint",
            "dst_endpoint",
            "connection_info",
            "device",
            "actor",
            "message",
        ],
    ),
    // Authentication
    (
        3002,
        &["src_endpoint", "dst_endpoint", "device", "actor", "message"],
    ),
    // Email Activity
    (
        4009,
        &["src_endpoint", "dst_endpoint", "device", "actor", "message"],
    ),
    // Event Log Activity
    (
        1008,
        &["src_endpoint", "dst_endpoint", "device", "actor", "message"],
    ),
    // Detection Finding — no endpoints at all.
    (2004, &["device", "actor", "message"]),
];

/// Whether `class_uid` declares the root attribute `path` targets.
///
/// An unlisted class answers `false` for everything but the envelope
/// literals: a class this table has never been checked against is exactly the
/// case where a draft should not be trusted to carry field mappings.
pub fn class_accepts(class_uid: i64, path: &str) -> bool {
    if ENVELOPE_PATHS.contains(&path) {
        return true;
    }
    let root = path.split('.').next().unwrap_or(path);
    CLASS_ROOTS
        .iter()
        .find(|(uid, _)| *uid == class_uid)
        .is_some_and(|(_, roots)| roots.contains(&root))
}

/// Whether every mapped path is one `class_uid` declares.
pub fn class_accepts_all<'a>(class_uid: i64, paths: impl Iterator<Item = &'a str>) -> bool {
    paths.into_iter().all(|p| class_accepts(class_uid, p))
}

/// The class a draft should carry: the profiler's suggestion when the drafted
/// map fits it, and Network Activity otherwise.
///
/// Network Activity is the fallback rather than "no class" because a pack must
/// name one, it accepts every path the generator can produce, and it is what
/// every draft carried before family inference existed.
pub fn provisional_class<'a>(suggested: Option<i64>, paths: impl Iterator<Item = &'a str>) -> i64 {
    const NETWORK_ACTIVITY: i64 = 4001;
    match suggested {
        Some(uid) if uid != NETWORK_ACTIVITY && class_accepts_all(uid, paths) => uid,
        _ => NETWORK_ACTIVITY,
    }
}

/// Every key in `pack.map` that is not a recognized OCSF path, sorted and
/// deduplicated for a stable, readable report.
pub fn unknown_paths(pack: &Pack) -> Vec<String> {
    pack.map
        .keys()
        .filter(|path| !is_known_path(path))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use ulpf_pack::spec::{Detector, ExtractStep, FieldSpec, Identity, MapSpec, OneOrMany};

    fn pack_with_paths(paths: &[&str]) -> Pack {
        let mut map = BTreeMap::new();
        for path in paths {
            map.insert(
                path.to_string(),
                MapSpec::Field(FieldSpec {
                    from: OneOrMany::One("x".to_string()),
                    cast: None,
                    format: None,
                    enum_table: None,
                    default: None,
                    observable: None,
                }),
            );
        }
        Pack {
            identity: Identity {
                id: "test".into(),
                vendor: "Test".into(),
                product: "Test".into(),
                version: None,
                log_format: None,
                detect: vec![Detector {
                    contains_all: vec!["x".into()],
                    contains_any: Vec::new(),
                    contains_none: Vec::new(),
                    starts_with: None,
                }],
                priority: 1000,
            },
            extract: vec![ExtractStep {
                decoder: "keyvalue".into(),
                sep: None,
                delim: None,
                headers: Vec::new(),
                patterns: Vec::new(),
                optional: false,
            }],
            map,
            enums: BTreeMap::new(),
            fixtures: Vec::new(),
            provenance: None,
        }
    }

    #[test]
    fn detection_finding_does_not_accept_endpoints() {
        // schema/ocsf/events/findings/detection_finding.json extends
        // finding.json, which extends base_event. No endpoint appears in any
        // of the three.
        assert!(!class_accepts(2004, "src_endpoint.ip"));
        assert!(!class_accepts(2004, "dst_endpoint.port"));
        assert!(!class_accepts(2004, "connection_info.protocol_name"));
        assert!(class_accepts(2004, "device.hostname"));
        assert!(class_accepts(2004, "message"));
    }

    #[test]
    fn http_activity_has_no_top_level_url() {
        // Its URL lives inside `http_request`, so `url.url_string` is a
        // Network Activity path, not an HTTP Activity one.
        assert!(class_accepts(4001, "url.url_string"));
        assert!(!class_accepts(4002, "url.url_string"));
        assert!(class_accepts(4002, "connection_info.protocol_name"));
    }

    #[test]
    fn the_envelope_literals_are_accepted_everywhere() {
        for uid in [1008, 2004, 3002, 4001, 4002, 4009] {
            for path in ENVELOPE_PATHS {
                assert!(class_accepts(uid, path), "{uid} rejected {path}");
            }
        }
    }

    #[test]
    fn network_activity_accepts_every_path_the_generator_can_produce() {
        // The fallback has to be total, or `provisional_class` could return a
        // class that rejects the map it was given.
        for path in KNOWN_PATHS {
            assert!(class_accepts(4001, path), "4001 rejected {path}");
        }
    }

    #[test]
    fn a_class_this_table_has_never_seen_is_not_trusted() {
        assert!(!class_accepts(9999, "src_endpoint.ip"));
        assert_eq!(
            provisional_class(Some(9999), ["src_endpoint.ip"].into_iter()),
            4001
        );
    }

    #[test]
    fn a_suggested_class_is_kept_only_when_the_map_fits_it() {
        // An authentication draft that mapped nothing network-shaped keeps 3002.
        assert_eq!(
            provisional_class(Some(3002), ["actor.user.name", "message"].into_iter()),
            3002
        );
        // The same suggestion with a protocol mapping does not: Authentication
        // has no `connection_info`.
        assert_eq!(
            provisional_class(
                Some(3002),
                ["actor.user.name", "connection_info.protocol_name"].into_iter()
            ),
            4001
        );
        // No suggestion at all is Network Activity, as before.
        assert_eq!(provisional_class(None, ["message"].into_iter()), 4001);
    }

    #[test]
    fn every_path_the_generator_can_produce_is_known() {
        // Mirrors llm::ALLOWED_FIELDS plus the three literal envelope
        // fields. If this fails, either this table or ALLOWED_FIELDS has
        // drifted from the other.
        for path in [
            "class_uid",
            "activity_id",
            "severity_id",
            "src_endpoint.ip",
            "src_endpoint.port",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "connection_info.protocol_name",
            "device.hostname",
            "actor.user.name",
            "url.url_string",
            "message",
        ] {
            assert!(is_known_path(path), "{path} should be a known OCSF path");
        }
    }

    #[test]
    fn the_bare_url_object_mistake_is_rejected() {
        // The exact bug this module was written to catch: `url` alone is an
        // object, not a string.
        assert!(!is_known_path("url"));
        let pack = pack_with_paths(&["url", "src_endpoint.ip"]);
        let unknown = unknown_paths(&pack);
        assert_eq!(unknown, vec!["url".to_string()]);
    }

    #[test]
    fn a_hallucinated_path_is_reported() {
        let pack = pack_with_paths(&["src_endpoint.ip", "not_a_real_ocsf_attribute"]);
        assert_eq!(
            unknown_paths(&pack),
            vec!["not_a_real_ocsf_attribute".to_string()]
        );
    }

    #[test]
    fn a_fully_valid_pack_reports_no_unknown_paths() {
        let pack = pack_with_paths(&[
            "src_endpoint.ip",
            "dst_endpoint.port",
            "device.hostname",
            "url.url_string",
        ]);
        assert!(unknown_paths(&pack).is_empty());
    }
}
