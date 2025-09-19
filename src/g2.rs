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

#[cfg(all(test, not(target_os = "solana")))]
mod tests {
    use super::{G2CompressedPoint, G2Point};
    use crate::g1::{G1Point, G1CompressedPoint};
    use crate::privkey::PrivKey;

    #[test]
    fn keygen_g2_compressed() {
        let privkey = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);
        let pubkey = G2CompressedPoint::try_from(&privkey).expect("Invalid private key");
        assert_eq!(
            [0x8b, 0x1a, 0xc6, 0x3e, 0x24, 0x4f, 0xa4, 0x19, 0x78, 0xf2, 0x84, 0xb4, 0x69, 0xa6,
            0xcb, 0xe4, 0xa8, 0xba, 0xeb, 0x71, 0x06, 0x30, 0xad, 0xcc, 0xf6, 0x9b, 0x27, 0xd4,
            0xbd, 0x12, 0xf5, 0x76, 0x1e, 0x88, 0xed, 0x4a, 0xeb, 0xd8, 0x43, 0x85, 0x3b, 0xf0,
            0x24, 0x9c, 0x7c, 0x2b, 0x37, 0xfb, 0xb0, 0xd1, 0x77, 0xdb, 0x37, 0xe6, 0xab, 0x29,
            0xd8, 0x9d, 0x4e, 0x29, 0x72, 0xdf, 0xff, 0x24],
            pubkey.0
        );
    }

    #[test]
    fn keygen_g2_uncompressed() {
        let privkey = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);

        let pubkey = G2Point::try_from(&privkey).expect("Invalid private key");

        assert_eq!(
            [0x0b, 0x1a, 0xc6, 0x3e, 0x24, 0x4f, 0xa4, 0x19, 0x78, 0xf2, 0x84, 0xb4, 0x69, 0xa6,
            0xcb, 0xe4, 0xa8, 0xba, 0xeb, 0x71, 0x06, 0x30, 0xad, 0xcc, 0xf6, 0x9b, 0x27, 0xd4,
            0xbd, 0x12, 0xf5, 0x76, 0x1e, 0x88, 0xed, 0x4a, 0xeb, 0xd8, 0x43, 0x85, 0x3b, 0xf0,
            0x24, 0x9c, 0x7c, 0x2b, 0x37, 0xfb, 0xb0, 0xd1, 0x77, 0xdb, 0x37, 0xe6, 0xab, 0x29,
            0xd8, 0x9d, 0x4e, 0x29, 0x72, 0xdf, 0xff, 0x24, 0x2d, 0x43, 0xaa, 0x4d, 0xd4, 0x93,
            0xe0, 0x9a, 0x03, 0xb6, 0x8c, 0x16, 0x7f, 0x19, 0x5b, 0x59, 0x1e, 0xbc, 0xca, 0x6c,
            0x2d, 0x43, 0x82, 0x01, 0xfc, 0x4b, 0xfd, 0x9f, 0x9c, 0x0c, 0x3d, 0xda, 0x0a, 0xb8,
            0x48, 0xa4, 0x9c, 0x6f, 0xde, 0xdc, 0x9d, 0xe6, 0x08, 0x3a, 0xff, 0x53, 0x5a, 0xc6,
            0x5a, 0xfd, 0x29, 0x8a, 0xf2, 0xa7, 0x27, 0x67, 0xc1, 0x9a, 0xd2, 0xae, 0xf5, 0xc4,
            0x91, 0x2c],
            pubkey.0
        );
    }

    #[test]
    fn perps_aggregation() {
        let msg = [&50_000u64.to_le_bytes()[..], b"BTCUSD<"].concat();

        let privkey_1 = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);
        let privkey_2 = PrivKey([
            0x22, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);
        let privkey_3 = PrivKey([
            0x23, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);

        let sig_1 = privkey_1.sign(&msg).unwrap();
        let sig_2 = privkey_2.sign(&msg).unwrap();
        let sig_3 = privkey_3.sign(&msg).unwrap();

        let pubkey_1 = G2Point::try_from(&privkey_1).expect("Invalid private key");
        let pubkey_2 = G2Point::try_from(&privkey_2).expect("Invalid private key");
        let pubkey_3 = G2Point::try_from(&privkey_3).expect("Invalid private key");

        let sig_agg = sig_1 + sig_2 + sig_3;

        let pubkey_agg = pubkey_1 + pubkey_2 + pubkey_3;

        pubkey_agg.verify(&sig_agg, &msg).expect("Failed to verify signature");
    }

    #[test]
    fn signature_verification() {
        let privkey = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);

        let signature = privkey.sign("sample").expect("Signature error");

        let signature_compressed =
            G1CompressedPoint::try_from(signature).expect("Failed to compress G1 point");

        let pubkey = G2CompressedPoint::try_from(&privkey).expect("Invalid private key");

        assert!(pubkey.verify(&G1Point::try_from(&signature_compressed).unwrap(), "sample").is_ok());
    }
}
