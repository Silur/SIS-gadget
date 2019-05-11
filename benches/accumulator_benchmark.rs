#[macro_use]
extern crate criterion;

// use criterion::Criterion;
use criterion::*;
// use criterion::black_box;

extern crate sis_gadget;
extern crate bellman_ce as bellman;
extern crate sapling_crypto_ce as sapling_crypto;
extern crate rand;

#[macro_use]
extern crate lazy_static;

use sapling_crypto::group_hash::{Keccak256Hasher};
use bellman::pairing::bn256::Bn256;
use rand::{Rng, thread_rng};

use sis_gadget::{BinarySISAccumulator, BinarySISParams};

fn criterion_benchmark_generation(c: &mut Criterion) {
    c.bench("generate params BN254", Benchmark::new("", |b| b.iter(|| BinarySISParams::<Bn256>::new::<Keccak256Hasher>(b"hello", black_box(32512u32), 128u32, 1024))).sample_size(2));
}

lazy_static!{
    pub static ref BN256_PARAMS: BinarySISParams<Bn256> = BinarySISParams::<Bn256>::new::<Keccak256Hasher>(b"hello", 32512u32, 128u32, 1024);
}

fn criterion_benchmark_hashing(c: &mut Criterion) {
    let accumulator = BinarySISAccumulator::new(&BN256_PARAMS);
    let mut values = vec![];
    let rng = &mut thread_rng();
    for _ in 0..10 {
        let value: Vec<bool> = (0..32512u32).map(|_| rng.gen()).collect();
        values.push(value);
    }
    c.bench("hash 10", Benchmark::new("", move |b| b.iter(|| {
        for v in values.iter() {
            accumulator.hash(&v);
        }
    })).sample_size(10)
    );
}

criterion_group!(benches_generation, criterion_benchmark_generation);
criterion_group!(benches_functionality, criterion_benchmark_hashing);
// criterion_main!(benches_generation);
criterion_main!(benches_functionality);