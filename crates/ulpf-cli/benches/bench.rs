//! Per-stage benchmarks for the normalization hot path.
//!
//! An earlier version of this file claimed to measure "pipeline throughput"
//! while actually timing two `serde_json::Map` inserts — it never touched a
//! decoder, a pack or the canonicalizer, so its numbers described nothing and
//! could not regress when the real code got slower.
//!
//! What matters for the published EPS figure is the per-event work that runs
//! once for every record: detect which pack claims the line, run the decoder
//! chain, map the fields onto OCSF, then canonicalize and hash the result.
//! Those four are measured separately here so a regression names its own
//! stage. Vault and socket costs are deliberately excluded — they are I/O, and
//! `docs/THROUGHPUT.md` measures them end to end where they belong.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use ulpf_core::{Envelope, Transport};
use ulpf_ocsf::types::HashAlgorithm;
use ulpf_ocsf::{jcs, Attestor};
use ulpf_pack::{CompiledPack, NormalizeCtx, Pack};

/// A real netfilter line from the Honeynet SotM30 capture — the same corpus
/// the iptables pack was written against, so the benchmark exercises the
/// branches production traffic actually takes.
const IPTABLES: &str = "Feb  1 00:00:02 bridge kernel: INBOUND TCP: IN=br0 PHYSIN=eth0 OUT=br0 \
PHYSOUT=eth1 SRC=192.150.249.87 DST=11.11.11.84 LEN=40 TOS=0x00 PREC=0x00 TTL=110 ID=12973 \
PROTO=TCP SPT=220 DPT=6129 WINDOW=16384 RES=0x00 SYN URGP=0";

fn pack() -> CompiledPack {
    let yaml = std::fs::read_to_string("packs/linux-iptables-firewall.yaml")
        .expect("run benchmarks from the repository root, where packs/ lives");
    let spec: Pack = serde_yaml::from_str(&yaml).expect("the shipped pack parses");
    CompiledPack::compile(spec).expect("the shipped pack compiles")
}

fn bench_stages(c: &mut Criterion) {
    let pack = pack();
    let envelope = Envelope::new(Transport::SyslogUdp, "bench");

    let mut group = c.benchmark_group("per_event");
    group.throughput(Throughput::Bytes(IPTABLES.len() as u64));

    // Stage 1: does this pack claim the line? Runs for every pack in priority
    // order until one matches, so it is the cost paid even by unparsed records.
    group.bench_function("detect", |b| {
        b.iter(|| std::hint::black_box(pack.claims(std::hint::black_box(IPTABLES))));
    });

    // Stage 2: syslog envelope, then a regex for the verdict, then key-value.
    group.bench_function("extract_chain", |b| {
        b.iter(|| std::hint::black_box(pack.extract(std::hint::black_box(IPTABLES)).unwrap()));
    });

    // Stage 3: field map onto OCSF attributes, including observables.
    let fields = pack.extract(IPTABLES).unwrap();
    group.bench_function("normalize_to_ocsf", |b| {
        b.iter(|| {
            let ctx = NormalizeCtx::new(&envelope, "bench-uid").with_hash(HashAlgorithm::Sha256);
            std::hint::black_box(pack.normalize(&fields, IPTABLES.as_bytes(), &ctx).unwrap())
        });
    });

    // Stage 4: RFC 8785 canonicalization, which every attestation depends on.
    let ctx = NormalizeCtx::new(&envelope, "bench-uid").with_hash(HashAlgorithm::Sha256);
    let event = pack.normalize(&fields, IPTABLES.as_bytes(), &ctx).unwrap();
    group.bench_function("canonicalize_jcs", |b| {
        b.iter(|| std::hint::black_box(jcs::canonicalize_map_bytes(event.as_map()).unwrap()));
    });

    // Stage 5: fingerprint plus chain link. Attesting mutates the event, so
    // each iteration gets its own copy and the clone is excluded from timing.
    group.bench_function("attest", |b| {
        let mut attestor = Attestor::new("bench-node", "bench-chain");
        b.iter_batched_ref(
            || event.clone(),
            |ev| std::hint::black_box(attestor.attest(ev).unwrap()),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// The same work end to end, which is the number to compare against the EPS
/// ceiling in `docs/THROUGHPUT.md`.
fn bench_end_to_end(c: &mut Criterion) {
    let pack = pack();
    let envelope = Envelope::new(Transport::SyslogUdp, "bench");
    let mut attestor = Attestor::new("bench-node", "bench-chain");

    let mut group = c.benchmark_group("end_to_end");
    group.throughput(Throughput::Elements(1));
    group.bench_function("detect_extract_normalize_attest", |b| {
        b.iter(|| {
            assert!(pack.claims(IPTABLES));
            let fields = pack.extract(IPTABLES).unwrap();
            let ctx = NormalizeCtx::new(&envelope, uuid::Uuid::now_v7().to_string())
                .with_hash(HashAlgorithm::Sha256);
            let mut event = pack.normalize(&fields, IPTABLES.as_bytes(), &ctx).unwrap();
            attestor.attest(&mut event).unwrap();
            std::hint::black_box(event)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_stages, bench_end_to_end);
criterion_main!(benches);
