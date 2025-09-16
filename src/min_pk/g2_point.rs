#[cfg(not(target_os="solana"))]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(not(target_os="solana"))]
use num::CheckedAdd;

use solana_bn254::compression::prelude::{alt_bn128_g2_compress, alt_bn128_g2_decompress};

use crate::errors::BLSError;
use super::BLSSignature;

#[derive(Clone)]
pub struct G2Point(pub [u8; 128]);

#[derive(Clone)]
pub struct G2CompressedPoint(pub [u8; 64]);

#[cfg(not(target_os = "solana"))]
impl core::ops::Add for G2Point {
    type Output = G2Point;

    fn add(self, rhs: Self) -> G2Point {
        self.checked_add(&rhs).expect("G2Point addition failed")
    }
}

#[cfg(not(target_os = "solana"))]
impl CheckedAdd for G2Point {
    fn checked_add(&self, rhs: &Self) -> Option<Self> {
        let result = (|| -> Result<Self, BLSError> {
            let mut s0 = G2CompressedPoint::try_from(self)?.0;
            let mut s1 = G2CompressedPoint::try_from(rhs)?.0;

            s0.reverse();
            s1.reverse();

            let g2_agg = ark_bn254::G2Affine::deserialize_compressed(&s0[..])
                .map_err(|_| BLSError::G2PointCompressionError)?
                + ark_bn254::G2Affine::deserialize_compressed(&s1[..])
                    .map_err(|_| BLSError::G2PointCompressionError)?;

            let mut g2_agg_bytes = [0u8; 64];
            g2_agg
                .serialize_compressed(&mut &mut g2_agg_bytes[..])
                .map_err(|_| BLSError::SerializationError)?;

            g2_agg_bytes.reverse();

            G2Point::try_from(&G2CompressedPoint(g2_agg_bytes))
                .map_err(|_| BLSError::G2PointDecompressionError)
        })();

        result.ok()
    }
}

impl TryFrom<&G2Point> for G2CompressedPoint {
    type Error = BLSError;

    fn try_from(value: &G2Point) -> Result<Self, Self::Error> {
        Ok(G2CompressedPoint(
            alt_bn128_g2_compress(&value.0).map_err(|_| BLSError::G2PointCompressionError)?,
        ))
    }
}

impl TryFrom<&G2CompressedPoint> for G2Point {
    type Error = BLSError;

    fn try_from(value: &G2CompressedPoint) -> Result<Self, Self::Error> {
        Ok(G2Point(
            alt_bn128_g2_decompress(&value.0).map_err(|_| BLSError::G2PointDecompressionError)?,
        ))
    }
}

impl BLSSignature for G2Point {
    fn to_bytes(&self) -> Result<[u8; 128], BLSError> {
        Ok(self.0)
    }
}

impl BLSSignature for G2CompressedPoint {
    fn to_bytes(&self) -> Result<[u8; 128], BLSError> {
        Ok(G2Point::try_from(self)?.0)
    }
}
