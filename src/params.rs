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
}

impl<E: Engine> BinarySISParams<E> {
    pub fn new<G: GroupHasher> (
        personalization: &[u8],
        m: u32, 
        n: u32
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

            Self {
                m: m,
                n: n,
                a_matrix: a_matrix
            }
        }
    }
}