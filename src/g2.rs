#[cfg(not(target_os = "solana"))]
use ark_bn254::Fr;
#[cfg(not(target_os = "solana"))]
use ark_ec::AffineRepr;
#[cfg(not(target_os = "solana"))]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(not(target_os = "solana"))]
use num::CheckedAdd;

use solana_bn254::{
    compression::prelude::{alt_bn128_g2_compress, alt_bn128_g2_decompress},
    prelude::alt_bn128_pairing,
};

use crate::consts::G2_MINUS_ONE;
use crate::errors::BLSError;
use crate::g1::G1Point;
use crate::hash::hash_to_curve;

#[derive(Clone, Copy)]
pub struct G2Point(pub [u8; 128]);

#[derive(Clone, Copy)]
pub struct G2CompressedPoint(pub [u8; 64]);

impl G2Point {
    pub fn verify<T: AsRef<[u8]>>(&self, signature: &G1Point, message: T) -> Result<(), BLSError> {
        let mut input = [0u8; 384];

        // Hash message to curve
        input[..64].clone_from_slice(&hash_to_curve(message)?.0);
        // Public key (uncompressed)
        input[64..192].clone_from_slice(&self.0);
        // Signature (uncompressed)
        input[192..256].clone_from_slice(&signature.0);
        // Pair with negative generator in G2
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

impl G2CompressedPoint {
    pub fn verify<T: AsRef<[u8]>>(
        &self,
        signature: &G1Point,
        message: T,
    ) -> Result<(), BLSError> {
        let mut input = [0u8; 384];

        // Hash message to curve
        input[..64].clone_from_slice(&hash_to_curve(message)?.0);
        // Decompress public key
        input[64..192].clone_from_slice(&G2Point::try_from(*self)?.0);
        // Signature (uncompressed)
        input[192..256].clone_from_slice(&signature.0);
        // Pair with negative generator in G2
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

#[cfg(not(target_os = "solana"))]
impl TryFrom<&crate::privkey::PrivKey> for G2CompressedPoint {
    type Error = BLSError;

    fn try_from(value: &crate::privkey::PrivKey) -> Result<G2CompressedPoint, Self::Error> {
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
impl TryFrom<&crate::privkey::PrivKey> for G2Point {
    type Error = BLSError;

    fn try_from(value: &crate::privkey::PrivKey) -> Result<G2Point, Self::Error> {
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

#[cfg(test)]
mod tests {
    use super::{G2CompressedPoint, G2Point};
    use crate::g1::{G1CompressedPoint, G1Point};
    use crate::privkey::PrivKey;

    #[test]
    fn g2_keygen_roundtrip_random() {
        let sk = PrivKey::from_random();
        let pk_uncompressed = G2Point::try_from(&sk).expect("g2 from sk");
        let pk_compressed = G2CompressedPoint::try_from(&sk).expect("g2c from sk");

        let decomp = G2Point::try_from(pk_compressed).expect("decompress g2");
        assert_eq!(decomp.0, pk_uncompressed.0, "G2 compress/decompress mismatch");
    }

    #[test]
    fn signature_verification_random() {
        let sk = PrivKey::from_random();
        let msg = b"g2-verify";
        let sig = sk.sign(msg).expect("sign");
        let pk = G2Point::try_from(&sk).expect("g2 from sk");
        pk.verify(&sig, msg).expect("verify");
    }

    #[test]
    fn perps_aggregation_random() {
        let msg = b"agg-test";

        let sk1 = PrivKey::from_random();
        let sk2 = PrivKey::from_random();
        let sk3 = PrivKey::from_random();

        let sig1 = sk1.sign(msg).expect("s1");
        let sig2 = sk2.sign(msg).expect("s2");
        let sig3 = sk3.sign(msg).expect("s3");

        let pk1 = G2Point::try_from(&sk1).expect("pk1");
        let pk2 = G2Point::try_from(&sk2).expect("pk2");
        let pk3 = G2Point::try_from(&sk3).expect("pk3");

        let s_agg = sig1 + sig2 + sig3;
        let pk_agg = pk1 + pk2 + pk3;

        pk_agg.verify(&s_agg, msg).expect("aggregate verify");
    }

    #[test]
    fn signature_compress_decompress_roundtrip() {
        let sk = PrivKey::from_random();
        let msg = b"sig-rt";
        let sig = sk.sign(msg).expect("sign");
        let sig_c = G1CompressedPoint::try_from(sig.clone()).expect("compress sig");
        let sig_rt = G1Point::try_from(&sig_c).expect("decompress sig");
        assert_eq!(sig.0, sig_rt.0, "G1 sig compress/decompress mismatch");
    }
}
