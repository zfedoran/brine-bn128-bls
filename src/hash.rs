use dashu::integer::UBig;
use solana_bn254::compression::prelude::alt_bn128_g1_decompress;

use crate::consts::{MODULUS, NORMALIZE_MODULUS};
use crate::errors::BLSError;
use crate::g1::G1Point;

pub fn hash_to_curve<T: AsRef<[u8]>>(message: T) -> Result<G1Point, BLSError> {
    (0..255)
        .find_map(|n: u8| {
            let hash = solana_nostd_sha256::hashv(&[message.as_ref(), &[n]]);
            let hash_ubig = UBig::from_be_bytes(&hash);

            if hash_ubig >= NORMALIZE_MODULUS {
                return None;
            }

            let modulus_ubig = hash_ubig % &MODULUS;

            match alt_bn128_g1_decompress(&modulus_ubig.to_be_bytes()) {
                Ok(p) => Some(G1Point(p)),
                Err(_) => None,
            }
        })
        .ok_or(BLSError::HashToCurveError)
}
