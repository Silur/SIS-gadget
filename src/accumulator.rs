use bellman::pairing::{
    Engine
};

use bellman::pairing::ff::{
    Field,
    PrimeField,
    PrimeFieldRepr
};

use super::params::BinarySISParams;
// use std::collections::HashSet;

/// This structure defines parameters for SIS accumulator that expects
/// binary(!) string as input
pub struct BinarySISAccumulator<'a, E: Engine> {
    pub params: &'a BinarySISParams<E>,
    pub accumulated_value: Vec<E::Fr>,
    // pub elements: HashSet<Vec<u8>>
}

impl<'a, E: Engine> BinarySISAccumulator<'a, E> {
    pub fn new(params: &'a BinarySISParams<E>) -> Self {
        Self {
            params: params,
            accumulated_value: vec![E::Fr::zero(); params.n as usize]
        }
    }

    // hashes an element, calculated value for acculumation
    pub fn hash(&self, value: &[bool]) -> Vec<E::Fr> {
        assert!(value.len() == self.params.m as usize, "expected to acculumate binary string of specific size!");
        let mut result = vec![E::Fr::zero(); self.params.n as usize];
        for row in 0..self.params.n {
            let mut accumulated = E::Fr::zero();
            for column in 0..self.params.m {
                if value[column as usize] {
                    accumulated.add_assign(&
                    self.params.a_matrix[(row as usize)*(self.params.n as usize) + (column as usize)])
                }
            }
            result[row as usize] = accumulated;

        }

        result
    }

    // accumulates an element into the internal state and provides a witness
    pub fn acculumate(&mut self, value: &[bool]) {
        assert!(value.len() == self.params.m as usize, "expected to acculumate binary string of specific size!");
        let h = self.hash(value);
        for (v, h) in self.accumulated_value.iter_mut().zip(h.iter()) {
            v.add_assign(&h);
        }


    }

    pub fn calculate_witness(&self, value: &[bool]) -> Vec<E::Fr> {
        let mut h = self.hash(value);
        for (v, h) in self.accumulated_value.iter().zip(h.iter_mut()) {
            h.negate();
            h.add_assign(&v);
        }
        // witness is acculumated value + A(-e))

        h
    }

    pub fn check_inclusion(&self, value: &[bool], witness: &[E::Fr]) -> bool {
        assert!(value.len() == self.params.m as usize, "expected to acculumate binary string of specific size!");
        let mut h = self.hash(value);
        for (h, w) in h.iter_mut().zip(witness.iter()) {
            h.add_assign(&w);
        }

        h == self.accumulated_value
    }

    fn batch_inversion(v: &mut [E::Fr]) {
        // Montgomery’s Trick and Fast Implementation of Masked AES
        // Genelle, Prouff and Quisquater
        // Section 3.2

        // First pass: compute [a, ab, abc, ...]
        let mut prod = Vec::with_capacity(v.len());
        let mut tmp = E::Fr::one();
        for g in v.iter()
            // Ignore zero elements
            .filter(|g| !g.is_zero())
        {
            tmp.mul_assign(&g);
            prod.push(tmp);
        }

        // Invert `tmp`.
        tmp = tmp.inverse().unwrap(); // Guaranteed to be nonzero.

        // Second pass: iterate backwards to compute inverses
        for (g, s) in v.iter_mut()
                        // Backwards
                        .rev()
                        // Ignore normalized elements
                        .filter(|g| !g.is_zero())
                        // Backwards, skip last element, fill in one for last term.
                        .zip(prod.into_iter().rev().skip(1).chain(Some(E::Fr::one())))
        {
            // tmp := tmp * g.z; g.z := tmp * s = 1/z
            let mut newtmp = tmp;
            newtmp.mul_assign(&g);
            *g = tmp;
            g.mul_assign(&s);
            tmp = newtmp;
        }
    }
}

#[cfg(test)]
mod test {
    use sapling_crypto::group_hash::{GroupHasher, Keccak256Hasher};
    use bellman::pairing::bn256::Bn256;
    use crate::{BinarySISAccumulator, BinarySISParams};
    use rand::{Rng, Rand, thread_rng};
    #[test]
    fn test_accumulator() {
        let n = 128u32;
        let m = 32512u32;
        let rng = &mut thread_rng();
        let params = BinarySISParams::<Bn256>::new::<Keccak256Hasher>(b"hello", m, n);
        let mut accumulator = BinarySISAccumulator::new(&params);
        let mut values = vec![];
        let mut witnesses = vec![];
        for _ in 0..10 {
            let value: Vec<bool> = (0..m).map(|_| rng.gen()).collect();
            accumulator.acculumate(&value);
            values.push(value);
        }

        for v in values.iter() {
            witnesses.push(accumulator.calculate_witness(v));
        }

        for (w, v) in witnesses.iter().zip(values.iter()) {
            assert!(accumulator.check_inclusion(v, w));
        }
    }
}