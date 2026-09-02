//! Automated Pack Scorer
//!
//! Automatically runs `ulpf_pack::library::test_pack` against generated packs
//! to ensure they pass their own fixtures before presenting them to a human analyst.

use ulpf_pack::Pack;
use ulpf_pack::library::PackReport;

pub struct Scorer;

impl Scorer {
    pub fn score(pack: &Pack) -> PackReport {
        ulpf_pack::library::test_pack(pack)
    }
}
