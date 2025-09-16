#[cfg(not(target_os = "solana"))]
use rand::RngCore;

#[cfg(not(target_os = "solana"))]
use ark_bn254::{self, Fr};
#[cfg(not(target_os = "solana"))]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

#[cfg(not(target_os = "solana"))]
use crate::consts::MODULUS;
#[cfg(not(target_os = "solana"))]
use super::{g2_point::G2Point, hash::HashToCurve};

#[cfg(not(target_os = "solana"))]
use crate::errors::BLSError;

pub struct PrivKey(pub [u8; 32]);

#[cfg(not(target_os = "solana"))]
impl PrivKey {
    pub fn from_random() -> PrivKey {

        loop {
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            
            let num = dashu::integer::UBig::from_be_bytes(&bytes);
            if num < MODULUS {
                return Self(bytes);
            }
        }
    }

    pub fn sign<H: HashToCurve, T: AsRef<[u8]>>(&self, message: T) -> Result<G2Point, BLSError> {
        // hash to curve (already subgroup-cleared)
        let hm_host = H::try_hash_to_curve(message)?.0; // 128B host layout

        let mut hm_ark = hm_host;
        hm_ark[..64].reverse();
        hm_ark[64..].reverse();
        let ark_uncompressed_with_mode = [&hm_ark[..], &[0u8][..]].concat();

        // deserialize WITHOUT validation (we already cleared the cofactor in HashToCurve)
        let hm_affine = ark_bn254::G2Affine::deserialize_with_mode(
            &ark_uncompressed_with_mode[..],
            Compress::No,
            Validate::No,
        ).map_err(|_| BLSError::G2PointDecompressionError)?;

        let mut sk_bytes = self.0;
        sk_bytes.reverse();
        let sk = Fr::deserialize_compressed(&sk_bytes[..])
            .map_err(|_| BLSError::SecretKeyError)?;

        let sig_proj = hm_affine * sk;
        let sig_affine: ark_bn254::G2Affine = sig_proj.into();

        // serialize Arkworks → 128B uncompressed (x.c0 | x.c1 | y.c0 | y.c1)
        let mut out_ark = [0u8; 128];
        sig_affine.x.c0.serialize_with_mode(&mut out_ark[0..32],   Compress::No)
            .map_err(|_| BLSError::SerializationError)?;
        sig_affine.x.c1.serialize_with_mode(&mut out_ark[32..64],  Compress::No)
            .map_err(|_| BLSError::SerializationError)?;
        sig_affine.y.c0.serialize_with_mode(&mut out_ark[64..96],  Compress::No)
            .map_err(|_| BLSError::SerializationError)?;
        sig_affine.y.c1.serialize_with_mode(&mut out_ark[96..128], Compress::No)
            .map_err(|_| BLSError::SerializationError)?;

        out_ark[..64].reverse();
        out_ark[64..].reverse();

        Ok(G2Point(out_ark))
    }
}

#[cfg(all(test, not(target_os = "solana")))]
mod test {
    use crate::min_pk::{
        PrivKey,
        G2CompressedPoint, 
        Sha256,
        G1Point, 
        G2Point,
    };

    #[test]
    fn sign() {
        let privkey = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);

        let _signature = privkey
            .sign::<Sha256, &[u8; 6]>(b"sample")
            .expect("Failed to sign");

        // assert_eq!([0x02, 0x6e, 0x58, 0x71, 0x6e, 0xd0, 0x10, 0x01, 0x81, 0x14, 0x8b, 0x56, 0x47, 0xe8, 0xf0, 0x79, 0x99, 0xa3, 0x63, 0x99, 0x11, 0x70, 0x95, 0x9e, 0x71, 0x82, 0x80, 0x14, 0x48, 0x5a, 0xa4, 0x2c, 0x2e, 0xcd, 0x1d, 0xf1, 0x73, 0x22, 0x8c, 0x3f, 0x2a, 0x5c, 0x9f, 0xd2, 0x0d, 0x44, 0x18, 0xca, 0x6c, 0x10, 0x8b, 0x50, 0xe0, 0x76, 0x63, 0x09, 0x16, 0xcc, 0x57, 0x0e, 0xc1, 0x5a, 0x77, 0x2a], signature.0);
    }

    #[test]
    fn sign_random() {
        let message = b"sample";
        let privkey = PrivKey::from_random();
        let signature = privkey
            .sign::<Sha256, &[u8; 6]>(&message)
            .expect("Failed to sign");

        let pubkey = G1Point::try_from(privkey).expect("Invalid private key");

        println!("Sig: {:?}\n, Pub: {:?}", &signature.0, &pubkey.0);
        assert!(pubkey.verify_signature::<Sha256, &[u8], G2Point>(signature, message).is_ok());
    }

    #[test]
    fn sign_compressed() {
        let privkey = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);

        let _signature = G2CompressedPoint::try_from(
            &privkey
                .sign::<Sha256, &[u8; 6]>(b"sample")
                .unwrap(),
        )
        .unwrap();

        // assert_eq!(
        //     [0x82, 0x6e, 0x58, 0x71, 0x6e, 0xd0, 0x10, 0x01, 0x81, 0x14, 0x8b, 0x56, 0x47, 0xe8, 0xf0, 0x79, 0x99, 0xa3, 0x63, 0x99, 0x11, 0x70, 0x95, 0x9e, 0x71, 0x82, 0x80, 0x14, 0x48, 0x5a, 0xa4, 0x2c],
        //     signature.0,
        // );
    }
}
