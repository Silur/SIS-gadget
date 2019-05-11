use bellman::pairing::{
    Engine
};

use bellman::pairing::ff::{
    Field,
    PrimeField,
    PrimeFieldRepr
};

use sapling_crypto::group_hash::{GroupHasher};
use byteorder::{ByteOrder, LittleEndian};

/// This structure defines parameters for SIS accumulator that expects
/// binary(!) string as input
pub struct BinarySISParams<E: Engine> {
    pub m: u32,
    pub n: u32,
    pub a_matrix: Vec<E::Fr>,
    pub capacity: usize,
    pub(crate) element_norm_squared: E::Fr,
    pub(crate) witness_element_squared: E::Fr,
    pub(crate) witness_norm_squared: E::Fr
}

impl<E: Engine> BinarySISParams<E> {
    pub fn new<G: GroupHasher> (
        personalization: &[u8],
        m: u32, 
        n: u32,
        capacity: usize,
    ) -> Self {
        let mut a_matrix = vec![E::Fr::zero(); (m as usize)*(n as usize)];
        {
            let mut row_buffer = [0u8; 4];
            let mut column_buffer = [0u8; 4];
            let mut nonce_buffer = [0u8; 8];
            
            for row in 0..n {
                LittleEndian::write_u32(&mut row_buffer[..], row);
                for column in 0..m {
                    LittleEndian::write_u32(&mut column_buffer[..], column);
                    let mut h = G::new(&personalization);
                    h.update(&row_buffer);
                    h.update(&column_buffer);
                    let seed = h.finalize();
                    // this is temporary solution only for Fr close to 2^256
                    // we brute force through nonce until we get some LE value that is smaller than modulus
                    for nonce in 0..2048u64 {
                        let mut h = G::new(&seed);
                        LittleEndian::write_u64(&mut nonce_buffer[..], nonce);
                        h.update(&nonce_buffer);
                        let h = h.finalize();
                        let mut repr = <E::Fr as PrimeField>::Repr::default();
                        if let Ok(()) = repr.read_le(&h[..]) {
                            if let Ok(fe) = E::Fr::from_repr(repr) {
                                a_matrix[(row as usize)*(n as usize) + (column as usize)] = fe;
                                break;
                            }
                        }
                    } 
                }
            }

            // TODO: these are temporary, will be properly recalculated or hardcoded
            let mut element_norm = E::Fr::one();
            element_norm.mul_assign(&E::Fr::from_str(&m.to_string()).unwrap());

            let mut witness_element_squared = E::Fr::one();
            witness_element_squared.mul_assign(&E::Fr::from_str(&capacity.to_string()).unwrap());

            let mut witness_norm = element_norm;
            witness_norm.mul_assign(&E::Fr::from_str(&capacity.to_string()).unwrap());

            assert!(element_norm.into_repr().num_bits() <= E::Fr::CAPACITY / 2 - Self::log_2(m as u32) - Self::log_2(capacity as u32));
            assert!(witness_element_squared.into_repr().num_bits() <= E::Fr::CAPACITY / 2 - Self::log_2(capacity as u32));
            assert!(witness_norm.into_repr().num_bits() <= E::Fr::CAPACITY / 2);

            element_norm.square();
            witness_element_squared.square();
            witness_norm.square();

            Self {
                m: m,
                n: n,
                a_matrix: a_matrix,
                capacity: capacity,
                element_norm_squared: element_norm,
                witness_element_squared: witness_element_squared,
                witness_norm_squared: witness_norm
            }
        }
    }

    fn log_2(value: u32) -> u32 {
        return f64::from(value).log2().ceil() as u32
    }
}