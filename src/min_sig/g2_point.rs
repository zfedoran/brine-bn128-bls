#[cfg(not(target_os="solana"))]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(not(target_os="solana"))]
use num::CheckedAdd;
#[cfg(not(target_os="solana"))]
use ark_bn254::Fr;
#[cfg(not(target_os="solana"))]
use ark_ec::AffineRepr;

use solana_bn254::{
    compression::prelude::{alt_bn128_g2_compress, alt_bn128_g2_decompress},
    prelude::alt_bn128_pairing,
};

use crate::{errors::BLSError, consts::G2_MINUS_ONE};
use super::{BLSSignature, HashToCurve};

#[derive(Clone)]
pub struct G2Point(pub [u8; 128]);

#[derive(Clone)]
pub struct G2CompressedPoint(pub [u8; 64]);

impl G2Point {
    pub fn verify_signature<H: HashToCurve, T: AsRef<[u8]>, S: BLSSignature>(
        self,
        signature: S,
        message: T,
    ) -> Result<(), BLSError> {
        let mut input = [0u8; 384];

        // 1) Hash message to curve
        input[..64].clone_from_slice(&H::try_hash_to_curve(message)?.0);
        // 2) Decompress our public key
        input[64..192].clone_from_slice(&self.0);
        // 3) Decompress our signature
        input[192..256].clone_from_slice(&signature.to_bytes()?);
        // 4) Pair with -G2::one()
        input[256..].clone_from_slice(&G2_MINUS_ONE);

        // Calculate result
        if let Ok(r) = alt_bn128_pairing(&input) {
            if r.eq(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ]) {
                Ok(())
            } else {
                Err(BLSError::BLSVerificationError)
            }
        } else {
            Err(BLSError::AltBN128PairingError)
        }
    }
}

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

            G2Point::try_from(G2CompressedPoint(g2_agg_bytes))
                .map_err(|_| BLSError::G2PointDecompressionError)
        })();

        result.ok()
    }
}

impl G2CompressedPoint {
    pub fn verify_signature<H: HashToCurve, T: AsRef<[u8]>, S: BLSSignature>(
        self,
        signature: S,
        message: T,
    ) -> Result<(), BLSError> {
        let mut input = [0u8; 384];

        // 1) Hash message to curve
        input[..64].clone_from_slice(&H::try_hash_to_curve(message)?.0);
        // 2) Decompress our public key
        input[64..192].clone_from_slice(&G2Point::try_from(self)?.0);
        // 3) Decompress our signature
        input[192..256].clone_from_slice(&signature.to_bytes()?);
        // 4) Pair with -G2::one()
        input[256..].clone_from_slice(&G2_MINUS_ONE);

        // Calculate result
        if let Ok(r) = alt_bn128_pairing(&input) {
            if r.eq(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ]) {
                Ok(())
            } else {
                Err(BLSError::BLSVerificationError)
            }
        } else {
            Err(BLSError::AltBN128PairingError)
        }
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<&super::PrivKey> for G2CompressedPoint {
    type Error = BLSError;

    fn try_from(value: &super::PrivKey) -> Result<G2CompressedPoint, Self::Error> {
        let mut pk = value.0;

        pk.reverse();

        let secret_key =
            Fr::deserialize_compressed(&pk[..]).map_err(|_| BLSError::SecretKeyError)?;

        let g2_public_key = ark_bn254::G2Affine::generator() * secret_key;

        let mut g2_public_key_bytes = [0u8; 64];

        g2_public_key
            .serialize_compressed(&mut &mut g2_public_key_bytes[..])
            .map_err(|_| BLSError::G2PointCompressionError)?;

        g2_public_key_bytes.reverse();

        Ok(Self(g2_public_key_bytes))
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<&super::PrivKey> for G2Point {
    type Error = BLSError;

    fn try_from(value: &super::PrivKey) -> Result<G2Point, Self::Error> {
        Ok(G2Point(
            alt_bn128_g2_decompress(&G2CompressedPoint::try_from(value)?.0)
                .map_err(|_| BLSError::G2PointDecompressionError)?,
        ))
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

impl TryFrom<G2CompressedPoint> for G2Point {
    type Error = BLSError;

    fn try_from(value: G2CompressedPoint) -> Result<Self, Self::Error> {
        Ok(G2Point(
            alt_bn128_g2_decompress(&value.0).map_err(|_| BLSError::G2PointDecompressionError)?,
        ))
    }
}
