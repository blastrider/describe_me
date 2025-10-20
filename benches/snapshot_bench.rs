use criterion::{criterion_group, criterion_main, Criterion};
use decribe_me::SystemSnapshot;

fn bench_capture(c: &mut Criterion) {
    c.bench_function("snapshot_capture", |b| b.iter(|| SystemSnapshot::capture()));
}

criterion_group!(benches, bench_capture);
criterion_main!(benches);
