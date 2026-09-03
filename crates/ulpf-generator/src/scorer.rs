//! Automated Pack Scorer
//!
//! Automatically runs `ulpf_pack::library::test_pack` against generated packs
//! to ensure they pass their own fixtures before presenting them to a human analyst.

use ulpf_pack::compiled::CompiledPack;
use ulpf_pack::library::PackTestReport;
use ulpf_pack::Pack;

pub struct Scorer;

impl Scorer {
    pub fn score(pack: &Pack) -> PackTestReport {
        if let Ok(compiled) = CompiledPack::compile(pack.clone()) {
            ulpf_pack::library::test_pack(&compiled)
        } else {
            PackTestReport::default()
        }
    }
}
