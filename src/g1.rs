use core::ops::Add;
use num::CheckedAdd;
use solana_bn254::{
    compression::prelude::{alt_bn128_g1_compress, alt_bn128_g1_decompress},
    prelude::{alt_bn128_addition, alt_bn128_multiplication},
};

use crate::errors::BLSError;
use crate::privkey::PrivKey;

#[derive(Clone)]
pub struct G1Point(pub [u8; 64]);

#[derive(Clone)]
pub struct G1CompressedPoint(pub [u8; 32]);

impl Add for G1Point {
    type Output = G1Point;

    fn add(self, rhs: Self) -> G1Point {
        self.checked_add(&rhs).expect("G1Point addition failed")
    }
}

impl CheckedAdd for G1Point {
    fn checked_add(&self, rhs: &Self) -> Option<Self> {
        let mut combined_input = [0u8; 128];

        unsafe {
            *(combined_input.as_mut_ptr() as *mut [u8; 64]) = self.0;
            *(combined_input.as_mut_ptr().add(64) as *mut [u8; 64]) = rhs.0;
        }

        let result = (|| -> Result<Self, BLSError> {
            let result =
                alt_bn128_addition(&combined_input).map_err(|_| BLSError::AltBN128AddError)?;
            Ok(G1Point(
                result.try_into().map_err(|_| BLSError::AltBN128AddError)?,
            ))
        })();

        result.ok()
    }
}

impl TryFrom<PrivKey> for G1CompressedPoint {
    type Error = BLSError;

    fn try_from(value: PrivKey) -> Result<Self, Self::Error> {
        let input = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            value.0[0],  value.0[1],  value.0[2],  value.0[3],  value.0[4],  value.0[5],  value.0[6],
            value.0[7],  value.0[8],  value.0[9],  value.0[10], value.0[11], value.0[12], value.0[13],
            value.0[14], value.0[15], value.0[16], value.0[17], value.0[18], value.0[19],
            value.0[20], value.0[21], value.0[22], value.0[23], value.0[24], value.0[25],
            value.0[26], value.0[27], value.0[28], value.0[29], value.0[30], value.0[31],
        ];

        let mut g1_sol_uncompressed = [0; 64];
        g1_sol_uncompressed.clone_from_slice(
            &alt_bn128_multiplication(&input).map_err(|_| BLSError::AltBN128MulError)?,
        );
        let compressed =
            alt_bn128_g1_compress(&g1_sol_uncompressed).map_err(|_| BLSError::SecretKeyError)?;
        Ok(G1CompressedPoint(compressed))
    }
}

impl TryFrom<PrivKey> for G1Point {
    type Error = BLSError;

    fn try_from(value: PrivKey) -> Result<Self, Self::Error> {
        let input = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            value.0[0],  value.0[1],  value.0[2],  value.0[3],  value.0[4],  value.0[5],  value.0[6],
            value.0[7],  value.0[8],  value.0[9],  value.0[10], value.0[11], value.0[12], value.0[13],
            value.0[14], value.0[15], value.0[16], value.0[17], value.0[18], value.0[19],
            value.0[20], value.0[21], value.0[22], value.0[23], value.0[24], value.0[25],
            value.0[26], value.0[27], value.0[28], value.0[29], value.0[30], value.0[31],
        ];

        let mut g1_sol_uncompressed = [0; 64];
        g1_sol_uncompressed.clone_from_slice(
            &alt_bn128_multiplication(&input).map_err(|_| BLSError::SecretKeyError)?,
        );
        Ok(G1Point(g1_sol_uncompressed))
    }
}

impl TryFrom<G1Point> for G1CompressedPoint {
    type Error = BLSError;

    fn try_from(value: G1Point) -> Result<Self, Self::Error> {
        Ok(G1CompressedPoint(
            alt_bn128_g1_compress(&value.0).map_err(|_| BLSError::G1PointCompressionError)?,
        ))
    }
}

impl TryFrom<&G1CompressedPoint> for G1Point {
    type Error = BLSError;

    fn try_from(value: &G1CompressedPoint) -> Result<Self, Self::Error> {
        Ok(G1Point(
            alt_bn128_g1_decompress(&value.0).map_err(|_| BLSError::G1PointDecompressionError)?,
        ))
    }
}

#[cfg(all(test, not(target_os = "solana")))]
mod tests {
    use super::{G1CompressedPoint, G1Point};
    use crate::privkey::PrivKey;

    #[test]
    fn keygen_g1_compressed() {
        let privkey = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);

        let pubkey = G1CompressedPoint::try_from(privkey).expect("Invalid private key");

        assert_eq!(
            [0x1d, 0xc6, 0x38, 0x33, 0x8a, 0xa8, 0xdf, 0xf2, 0xfd, 0x75, 0xdf, 0x80, 0x9e, 0x9f,
            0x33, 0x5d, 0x1b, 0x97, 0x96, 0x90, 0xe7, 0xe0, 0x2f, 0x49, 0x8f, 0x10, 0xbb, 0x7d,
            0x2c, 0x4a, 0x50, 0xeb],
            pubkey.0
        );
    }

    #[test]
    fn keygen_g1_uncompressed() {
        let privkey = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);

        let pubkey = G1Point::try_from(privkey).expect("Invalid private key");

        assert_eq!(
            [0x1d, 0xc6, 0x38, 0x33, 0x8a, 0xa8, 0xdf, 0xf2, 0xfd, 0x75, 0xdf, 0x80, 0x9e, 0x9f,
            0x33, 0x5d, 0x1b, 0x97, 0x96, 0x90, 0xe7, 0xe0, 0x2f, 0x49, 0x8f, 0x10, 0xbb, 0x7d,
            0x2c, 0x4a, 0x50, 0xeb, 0x08, 0x25, 0x1a, 0x23, 0xad, 0x51, 0xac, 0xbc, 0x01, 0xe3,
            0x46, 0x94, 0x1a, 0x72, 0x4e, 0x47, 0x95, 0xc1, 0x13, 0x48, 0x1b, 0x5a, 0x81, 0xa6,
            0xf5, 0x26, 0xdb, 0x3d, 0xf4, 0xd2, 0x00, 0x0b],
            pubkey.0
        );
    }
}
