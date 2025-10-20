use criterion::{criterion_group, criterion_main, Criterion};
use describe_me::SystemSnapshot;
// Optionnel mais conseillé pour éviter toute DCE agressive :
// use std::hint::black_box;

fn bench_capture(c: &mut Criterion) {
    // Version minimale conforme clippy :
    c.bench_function("snapshot_capture", |b| b.iter(SystemSnapshot::capture));

    // Variante avec black_box si tu veux être plus strict sur l'optimisation :
    // c.bench_function("snapshot_capture_bb", |b| b.iter(|| black_box(SystemSnapshot::capture())));
}

criterion_group!(benches, bench_capture);
criterion_main!(benches);
