#[macro_use]
extern crate criterion;

use criterion::Criterion;
// use criterion::black_box;

extern crate sis_gadget;
extern crate bellman_ce as bellman;
extern crate sapling_crypto_ce as sapling_crypto;

use sapling_crypto::group_hash::{Keccak256Hasher};
use bellman::pairing::bn256::Bn256;

use sis_gadget::{BinarySISAccumulator, BinarySISParams};

fn criterion_benchmark_generation(c: &mut Criterion) {
    c.bench_function("generate params BN254", |b| b.iter(|| BinarySISParams::<Bn256>::new::<Keccak256Hasher>(b"hello", 32512u32, 128u32, 1024)));
}

criterion_group!(benches, criterion_benchmark_generation);
criterion_main!(benches);