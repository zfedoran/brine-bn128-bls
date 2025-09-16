#[cfg(not(target_os = "solana"))]
use dashu::integer::UBig;
#[cfg(not(target_os = "solana"))]
use solana_bn254::compression::prelude::alt_bn128_g2_decompress;
#[cfg(not(target_os = "solana"))]
use crate::consts::{MODULUS, NORMALIZE_MODULUS};

use super::g2_point::G2Point;
use crate::errors::BLSError;

#[cfg(not(target_os = "solana"))]
use {
    ark_bn254,
    ark_ec::models::short_weierstrass::SWCurveConfig,
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate},
};

pub trait HashToCurve {
    fn try_hash_to_curve<T: AsRef<[u8]>>(message: T) -> Result<G2Point, BLSError>;
}

pub struct Sha256;

#[cfg(not(target_os = "solana"))]
impl HashToCurve for Sha256 {
    fn try_hash_to_curve<T: AsRef<[u8]>>(message: T) -> Result<G2Point, BLSError> {
        for n in 0u8..=254 {
            // two independent hashes for Fq2.x limbs
            let h0 = solana_nostd_sha256::hashv(&[message.as_ref(), &[n], b"c0"]);
            let h1 = solana_nostd_sha256::hashv(&[message.as_ref(), &[n], b"c1"]);

            // rejection sampling to avoid modulo bias
            let u0 = UBig::from_be_bytes(&h0);
            let u1 = UBig::from_be_bytes(&h1);

            if u0 >= NORMALIZE_MODULUS || u1 >= NORMALIZE_MODULUS {
                continue;
            }

            // reduce modulo p to canonical Fq elements
            let x0 = (u0 % &MODULUS).to_be_bytes();
            let x1 = (u1 % &MODULUS).to_be_bytes();

            // compose 64B "compressed" (as expected by alt_bn128_g2_decompress)
            let mut comp = [0u8; 64];
            comp[..32].copy_from_slice(&pad32(&x0));
            comp[32..].copy_from_slice(&pad32(&x1));

            // try to decompress to 128B uncompressed "host layout"
            let uncompressed = match alt_bn128_g2_decompress(&comp) {
                Ok(p) => p,
                Err(_) => continue, // try next nonce
            };

            let mut ark_uncompressed = uncompressed;
            ark_uncompressed[..64].reverse();
            ark_uncompressed[64..].reverse();

            let ark_uncompressed_with_mode = [&ark_uncompressed[..], &[0u8][..]].concat();

            // Deserialize WITHOUT validation (we'll fix subgroup manually)
            let h2c_unchecked = ark_bn254::G2Affine::deserialize_with_mode(
                &ark_uncompressed_with_mode[..],
                Compress::No,
                Validate::No,
            )
            .map_err(|_| BLSError::G2PointDecompressionError)?;

            // clear cofactor to land in the prime-order subgroup
            let h2c_cleared =
                <ark_bn254::g2::Config as SWCurveConfig>::clear_cofactor(&h2c_unchecked);

            // serialize back to 128B uncompressed (Arkworks layout)
            let mut ark_out = [0u8; 128];
            h2c_cleared.x.c0.serialize_with_mode(&mut ark_out[0..32], Compress::No)
                .map_err(|_| BLSError::SerializationError)?;
            h2c_cleared.x.c1.serialize_with_mode(&mut ark_out[32..64], Compress::No)
                .map_err(|_| BLSError::SerializationError)?;
            h2c_cleared.y.c0.serialize_with_mode(&mut ark_out[64..96], Compress::No)
                .map_err(|_| BLSError::SerializationError)?;
            h2c_cleared.y.c1.serialize_with_mode(&mut ark_out[96..128], Compress::No)
                .map_err(|_| BLSError::SerializationError)?;

            ark_out[..64].reverse();
            ark_out[64..].reverse();

            return Ok(G2Point(ark_out));
        }

        Err(BLSError::HashToCurveError)
    }
}

#[inline]
fn pad32(x: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let ofs = 32 - x.len();
    out[ofs..].copy_from_slice(x);
    out
}
