use dashu::integer::UBig;
use solana_bn254::compression::prelude::alt_bn128_g1_decompress;

use super::g1_point::G1Point;
use crate::{consts::*, errors::BLSError};

pub trait HashToCurve {
    fn try_hash_to_curve<T: AsRef<[u8]>>(message: T) -> Result<G1Point, BLSError>;
}

pub struct Sha256;

impl HashToCurve for Sha256 {
    fn try_hash_to_curve<T: AsRef<[u8]>>(message: T) -> Result<G1Point, BLSError> {
        (0..255)
            .find_map(|n: u8| {
                // Create a hash
                let hash = solana_nostd_sha256::hashv(&[message.as_ref(), &[n]]);

                // Convert hash to a Ubig for Bigint operations
                let hash_ubig = UBig::from_be_bytes(&hash);

                // Check if the hash is higher than our normalization modulus of Fq * 5
                if hash_ubig >= NORMALIZE_MODULUS {
                    return None;
                }

                let modulus_ubig = hash_ubig % &MODULUS;

                // Decompress the point
                match alt_bn128_g1_decompress(&modulus_ubig.to_be_bytes()) {
                    Ok(p) => Some(G1Point(p)),
                    Err(_) => None,
                }
            })
            .ok_or(BLSError::HashToCurveError)
    }
}
