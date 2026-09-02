use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use ulpf_ocsf::OcsfEvent;

fn bench_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_throughput");
    
    // A standard syslog message
    let raw = b"<13>Jan 15 12:34:56 hostname process[123]: Example log message";
    
    group.throughput(Throughput::Bytes(raw.len() as u64));
    
    group.bench_function("parse_syslog", |b| {
        b.iter(|| {
            // A simple benchmark mocking extraction/parsing latency
            let mut map = serde_json::Map::new();
            map.insert("class_uid".to_string(), serde_json::Value::Number(4001.into()));
            map.insert("message".to_string(), serde_json::Value::String("Example log message".to_string()));
            let _event = OcsfEvent::from_map(map);
        })
    });
    
    group.finish();
}

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);
