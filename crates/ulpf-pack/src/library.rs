//! A directory of packs, loaded and scored.
//!
//! The library is what makes onboarding "drop a file in a folder": it reads
//! every `.yaml` in a directory, compiles each one, and orders them so the most
//! specific detector wins. [`PackLibrary::test_all`] then runs every pack's own
//! fixtures, which is both the CI gate for hand-written packs and the scoring
//! harness that a generated pack must pass before anyone approves it.

use std::path::{Path, PathBuf};

use ulpf_core::{Envelope, Transport};
use ulpf_ocsf::types::HashAlgorithm;

use crate::compiled::{CompiledPack, NormalizeCtx};
use crate::error::{PackError, Result};
use crate::spec::Pack;

/// A loaded set of packs.
pub struct PackLibrary {
    packs: Vec<CompiledPack>,
}

impl PackLibrary {
    pub fn new() -> Self {
        Self { packs: Vec::new() }
    }

    /// Load every `.yaml`/`.yml` file in a directory.
    ///
    /// Returns the library alongside per-file errors rather than failing the
    /// whole load: one malformed pack should not take a collector offline.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<(Self, Vec<(PathBuf, PackError)>)> {
        let dir = dir.as_ref();
        let mut library = Self::new();
        let mut errors = Vec::new();

        let entries = std::fs::read_dir(dir)?;
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == "yaml" || e == "yml")
            })
            .collect();
        // Deterministic load order, so ties between equal-priority packs are
        // stable across machines.
        paths.sort();

        for path in paths {
            match Self::load_file(&path) {
                Ok(pack) => library.push(pack),
                Err(e) => errors.push((path, e)),
            }
        }
        Ok((library, errors))
    }

    pub fn load_file(path: impl AsRef<Path>) -> Result<CompiledPack> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        let spec: Pack = serde_yaml::from_str(&text).map_err(|source| PackError::Yaml {
            path: path.display().to_string(),
            source,
        })?;
        CompiledPack::compile(spec)
    }

    pub fn push(&mut self, pack: CompiledPack) {
        self.packs.push(pack);
        // Lower priority number first; a pack can therefore be placed ahead of
        // a broader one that would otherwise shadow it.
        self.packs.sort_by_key(|p| p.priority);
    }

    pub fn len(&self) -> usize {
        self.packs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packs.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CompiledPack> {
        self.packs.iter()
    }

    pub fn get(&self, id: &str) -> Option<&CompiledPack> {
        self.packs.iter().find(|p| p.id == id)
    }

    /// The first pack claiming `raw`, in priority order.
    pub fn identify(&self, raw: &str) -> Option<&CompiledPack> {
        self.packs.iter().find(|p| p.claims(raw))
    }

    /// Run every pack's fixtures.
    pub fn test_all(&self) -> PackTestReport {
        let mut report = PackTestReport::default();
        for pack in &self.packs {
            report.merge(test_pack(pack));
        }
        report
    }
}

impl Default for PackLibrary {
    fn default() -> Self {
        Self::new()
    }
}

/// Run one pack's fixtures against itself.
pub fn test_pack(pack: &CompiledPack) -> PackTestReport {
    let mut report = PackTestReport::default();
    let envelope = Envelope::new(Transport::File, "fixture");

    for (i, fixture) in pack.spec.fixtures.iter().enumerate() {
        report.total += 1;

        // A fixture that the pack's own detector does not claim is a bug in the
        // detector, and worth catching before it silently matches nothing in
        // production.
        if !pack.claims(&fixture.raw) {
            report.failures.push(FixtureFailure {
                pack: pack.id.clone(),
                fixture: i,
                path: "<detect>".into(),
                detail: "pack does not claim its own fixture".into(),
            });
            continue;
        }

        let fields = match pack.extract(&fixture.raw) {
            Ok(f) => f,
            Err(e) => {
                report.failures.push(FixtureFailure {
                    pack: pack.id.clone(),
                    fixture: i,
                    path: "<extract>".into(),
                    detail: e.to_string(),
                });
                continue;
            }
        };

        // Fixtures have no vault, so the raw text is inlined and the event
        // stays self-contained — which is what a reviewer wants to read.
        let ctx =
            NormalizeCtx::new(&envelope, format!("fixture-{i}")).with_hash(HashAlgorithm::Sha256);
        let event = match pack.normalize(&fields, fixture.raw.as_bytes(), &ctx) {
            Ok(ev) => ev,
            Err(e) => {
                report.failures.push(FixtureFailure {
                    pack: pack.id.clone(),
                    fixture: i,
                    path: "<normalize>".into(),
                    detail: e.to_string(),
                });
                continue;
            }
        };

        let mut ok = true;
        for (path, expected) in &fixture.expect {
            report.assertions += 1;
            match event.get_path(path) {
                Some(actual) if values_match(actual, expected) => report.assertions_passed += 1,
                Some(actual) => {
                    ok = false;
                    report.failures.push(FixtureFailure {
                        pack: pack.id.clone(),
                        fixture: i,
                        path: path.clone(),
                        detail: format!("expected {expected}, got {actual}"),
                    });
                }
                None => {
                    ok = false;
                    report.failures.push(FixtureFailure {
                        pack: pack.id.clone(),
                        fixture: i,
                        path: path.clone(),
                        detail: format!("expected {expected}, attribute absent"),
                    });
                }
            }
        }
        if ok {
            report.passed += 1;
        }
    }
    report
}

/// Compare an expected value with an actual one, tolerating YAML's habit of
/// reading `10.2.4.7` as a string and `443` as an integer.
fn values_match(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    if actual == expected {
        return true;
    }
    match (actual, expected) {
        (serde_json::Value::Number(a), serde_json::Value::String(b))
        | (serde_json::Value::String(b), serde_json::Value::Number(a)) => a.to_string() == *b,
        _ => false,
    }
}

/// One fixture assertion that did not hold.
#[derive(Debug, Clone)]
pub struct FixtureFailure {
    pub pack: String,
    pub fixture: usize,
    pub path: String,
    pub detail: String,
}

/// Aggregate result of running fixtures.
#[derive(Debug, Clone, Default)]
pub struct PackTestReport {
    /// Fixtures run.
    pub total: usize,
    /// Fixtures where every assertion held.
    pub passed: usize,
    /// Individual attribute assertions checked.
    pub assertions: usize,
    pub assertions_passed: usize,
    pub failures: Vec<FixtureFailure>,
}

impl PackTestReport {
    pub fn merge(&mut self, other: PackTestReport) {
        self.total += other.total;
        self.passed += other.passed;
        self.assertions += other.assertions;
        self.assertions_passed += other.assertions_passed;
        self.failures.extend(other.failures);
    }

    pub fn is_ok(&self) -> bool {
        self.failures.is_empty()
    }

    /// Share of fixtures that fully passed. This is the number a reviewer sees
    /// next to a generated pack.
    pub fn fixture_score(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.passed as f64 / self.total as f64
    }

    /// Share of individual attribute assertions that held. More granular than
    /// [`Self::fixture_score`]: a pack getting 9 of 10 fields right on every
    /// line scores 0.9 here and 0.0 there.
    pub fn field_accuracy(&self) -> f64 {
        if self.assertions == 0 {
            return 0.0;
        }
        self.assertions_passed as f64 / self.assertions as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    const GOOD: &str = r#"
identity:
  id: good-pack
  vendor: Acme
  product: Firewall
  detect:
    - contains_all: ["acme_fw"]
extract:
  - decoder: keyvalue
map:
  class_uid: 4001
  activity_id: 6
  time: { from: ts, format: epoch_s }
  src_endpoint.ip: { from: src }
fixtures:
  - raw: 'acme_fw ts=1756636800 src=10.0.0.1'
    expect:
      src_endpoint.ip: 10.0.0.1
      class_uid: 4001
"#;

    #[test]
    fn loads_a_directory_and_runs_fixtures() {
        let dir = tempdir();
        write(dir.path(), "good.yaml", GOOD);

        let (lib, errors) = PackLibrary::load_dir(dir.path()).unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(lib.len(), 1);

        let report = lib.test_all();
        assert!(report.is_ok(), "{:?}", report.failures);
        assert_eq!(report.total, 1);
        assert_eq!(report.passed, 1);
        assert_eq!(report.fixture_score(), 1.0);
        assert_eq!(report.field_accuracy(), 1.0);
    }

    #[test]
    fn a_broken_pack_does_not_stop_the_others_loading() {
        let dir = tempdir();
        write(dir.path(), "good.yaml", GOOD);
        write(dir.path(), "broken.yaml", "identity: {{{ not yaml");

        let (lib, errors) = PackLibrary::load_dir(dir.path()).unwrap();
        assert_eq!(lib.len(), 1, "the valid pack should still load");
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn a_wrong_expectation_is_reported_with_both_values() {
        let dir = tempdir();
        write(
            dir.path(),
            "wrong.yaml",
            &GOOD.replace("src_endpoint.ip: 10.0.0.1", "src_endpoint.ip: 10.0.0.99"),
        );

        let (lib, _) = PackLibrary::load_dir(dir.path()).unwrap();
        let report = lib.test_all();
        assert!(!report.is_ok());
        assert_eq!(report.passed, 0);
        let f = &report.failures[0];
        assert_eq!(f.path, "src_endpoint.ip");
        assert!(f.detail.contains("10.0.0.99"), "{}", f.detail);
        assert!(f.detail.contains("10.0.0.1"), "{}", f.detail);
    }

    #[test]
    fn a_pack_that_does_not_claim_its_own_fixture_fails() {
        let dir = tempdir();
        write(
            dir.path(),
            "mismatch.yaml",
            &GOOD.replace(
                r#"contains_all: ["acme_fw"]"#,
                r#"contains_all: ["never_present"]"#,
            ),
        );

        let (lib, _) = PackLibrary::load_dir(dir.path()).unwrap();
        let report = lib.test_all();
        assert!(!report.is_ok());
        assert_eq!(report.failures[0].path, "<detect>");
    }

    #[test]
    fn identification_respects_priority_order() {
        let mut lib = PackLibrary::new();
        let broad = GOOD
            .replace("id: good-pack", "id: broad")
            .replace("priority: 0", "");
        let specific = GOOD
            .replace("id: good-pack", "id: specific")
            .replace("  detect:", "  priority: -10\n  detect:");

        lib.push(CompiledPack::compile(serde_yaml::from_str(&broad).unwrap()).unwrap());
        lib.push(CompiledPack::compile(serde_yaml::from_str(&specific).unwrap()).unwrap());

        let found = lib.identify("acme_fw ts=1 src=10.0.0.1").unwrap();
        assert_eq!(found.id, "specific");
    }

    #[test]
    fn unidentified_input_returns_none() {
        let dir = tempdir();
        write(dir.path(), "good.yaml", GOOD);
        let (lib, _) = PackLibrary::load_dir(dir.path()).unwrap();
        assert!(lib.identify("something entirely different").is_none());
    }

    #[test]
    fn field_accuracy_is_finer_grained_than_fixture_score() {
        let dir = tempdir();
        // Two assertions, one of which is wrong: 0 of 1 fixtures, 1 of 2 fields.
        // Only the *fixture expectation* is changed, not the mapping — the
        // indentation distinguishes them, since `class_uid: 4001` appears in
        // both sections.
        let broken = GOOD.replace("      class_uid: 4001", "      class_uid: 9999");
        assert!(
            broken.contains("  class_uid: 4001"),
            "mapping must be untouched"
        );
        write(dir.path(), "partial.yaml", &broken);
        let (lib, _) = PackLibrary::load_dir(dir.path()).unwrap();
        let report = lib.test_all();
        assert_eq!(report.fixture_score(), 0.0);
        assert_eq!(report.field_accuracy(), 0.5);
    }

    // Minimal temp-dir helper so this crate does not take a dev-dependency
    // solely for two tests.
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        // A process id and a timestamp are not enough. Tests run in parallel
        // threads of one process, and `as_nanos()` is only as fine as the
        // platform clock — on macOS that is microseconds, so two tempdirs
        // created in the same instant collided, both packs loaded from one
        // directory, and whichever assertion read `failures[0]` saw the other
        // pack's failure. It surfaced as a rare `<detect>` mismatch. The
        // counter makes the name unique regardless of clock resolution.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "ulpf-pack-test-{}-{}-{:?}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        TempDir(base)
    }
}
