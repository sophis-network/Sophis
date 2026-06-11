use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rand_chacha::{
    ChaCha8Rng,
    rand_core::{RngCore, SeedableRng},
};

use sophis_muhash::MuHash;

fn bench_muhash(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::from_seed([42u8; 32]);
    let mut rand_set = MuHash::new();

    let mut data = [0u8; 100];
    rng.fill_bytes(&mut data);
    rand_set.add_element(&data);
    rng.fill_bytes(&mut data);
    rand_set.remove_element(&data);

    rng.fill_bytes(&mut data);

    c.bench_function("MuHash::add_element", |b| {
        let mut muhash = MuHash::new();
        b.iter(|| {
            black_box(&mut data);
            muhash.add_element(&data);
        });
        black_box(muhash);
    });

    c.bench_function("MuHash::remove_element", |b| {
        let mut muhash = MuHash::new();
        b.iter(|| {
            black_box(&mut data);
            muhash.remove_element(&data);
        });
        black_box(muhash);
    });

    c.bench_function("MuHash::combine", |b| {
        let mut muhash = MuHash::new();
        b.iter(|| {
            black_box((&mut rand_set, &mut muhash));
            muhash.combine(&rand_set);
        });
        black_box(muhash);
    });

    c.bench_function("MuHash::clone", |b| {
        b.iter(|| {
            black_box(&mut rand_set);
            rand_set.clone()
        });
    });

    c.bench_function("MuHash::serialize", |b| b.iter(|| black_box(rand_set.clone()).to_bytes()));

    c.bench_function("MuHash::finalize", |b| {
        b.iter(|| black_box(rand_set.clone()).finalize());
    });
}

criterion_group!(benches, bench_muhash);
criterion_main!(benches);
