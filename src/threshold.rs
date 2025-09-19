use crate::consts::G2_MINUS_ONE;
use crate::errors::BLSError;
use crate::g1::G1Point;
use crate::g2::G2Point;
use crate::hash::hash_to_curve;

use solana_bn254::prelude::{
    alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing
};

pub fn bls_partial_sign(
    sk_be_32: &[u8; 32],
    message: impl AsRef<[u8]>,
) -> Result<G1Point, BLSError> {
    let h_g1 = hash_to_curve(message)?.0;

    let mut inbuf = [0u8; 96];
    inbuf[..64].copy_from_slice(&h_g1);
    inbuf[64..].copy_from_slice(&sk_be_32[..]);

    let out = alt_bn128_multiplication(&inbuf).map_err(|_| BLSError::AltBN128MulError)?;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&out[..64]);
    Ok(G1Point(sig))
}

pub fn aggregate_partials(partials: &[G1Point]) -> Result<G1Point, BLSError> {
    if partials.is_empty() {
        return Err(BLSError::SerializationError);
    }
    let mut acc = partials[0].0;

    for s in &partials[1..] {
        let mut inbuf = [0u8; 128];
        inbuf[..64].copy_from_slice(&acc);
        inbuf[64..].copy_from_slice(&s.0);
        let out = alt_bn128_addition(&inbuf).map_err(|_| BLSError::AltBN128AddError)?;
        acc.copy_from_slice(&out[..64]);
    }
    Ok(G1Point(acc))
}

pub trait PubkeyProvider {
    fn g2_by_index(&self, idx: u16) -> Result<G2Point, BLSError>;
}

pub fn verify_a1_with_indices<M: AsRef<[u8]>>(
    message: M,
    signer_indices: &[u16],
    s_sum: G1Point,
    pk_provider: &impl PubkeyProvider,
) -> Result<(), BLSError> {
    let k = signer_indices.len();
    if k == 0 {
        return Err(BLSError::SerializationError);
    }

    // Hash message to G1 (64B)
    let h_g1 = hash_to_curve(message.as_ref())?.0;

    // Allocate (k + 1) pairs
    let mut input = vec![0u8; 192 * (k + 1)];

    // Pairs (H(m), PK_i)
    for (i, idx) in signer_indices.iter().enumerate() {
        let pk = pk_provider.g2_by_index(*idx)?;
        let off = 192 * i;
        input[off..off + 64].copy_from_slice(&h_g1);
        input[off + 64..off + 192].copy_from_slice(&pk.0);
    }

    // Final pair: (S_sum, negative generator)
    let off = 192 * k;
    input[off..off + 64].copy_from_slice(&s_sum.0);
    input[off + 64..off + 192].copy_from_slice(&G2_MINUS_ONE);

    let r = alt_bn128_pairing(&input).map_err(|_| BLSError::AltBN128PairingError)?;
    let ok = r.iter().take(31).all(|&b| b == 0) && r[31] == 1;
    if ok {
        Ok(())
    } else {
        Err(BLSError::BLSVerificationError)
    }
}

#[cfg(all(test, not(target_os = "solana")))]
mod tests {
    use super::{
        aggregate_partials, 
        bls_partial_sign, 
        verify_a1_with_indices, 
        PubkeyProvider
    };
    use crate::g1::G1Point;
    use crate::g2::G2Point;
    use crate::privkey::PrivKey;
    use crate::errors::BLSError;

    #[test]
    fn a1_threshold() {
        let msg = [&50_000u64.to_le_bytes()[..], b"BTCUSD<"].concat();

        let total_keys = 100;
        let signer_count = 75;

        let mut privkeys: Vec<PrivKey> = Vec::with_capacity(total_keys);
        for _ in 0..total_keys {
            privkeys.push(PrivKey::from_random());
        }

        let mut pubkeys_g2: Vec<G2Point> = Vec::with_capacity(total_keys);
        for pk in &privkeys {
            pubkeys_g2.push(G2Point::try_from(pk).expect("g2 from sk"));
        }

        let signer_indices: Vec<u16> = (0..signer_count as u16).collect();

        let mut partials: Vec<G1Point> = Vec::with_capacity(signer_count);
        for i in 0..signer_count {
            partials.push(
                bls_partial_sign(&privkeys[i].0, &msg).expect("partial sign"),
            );
        }

        let s_sum = aggregate_partials(&partials).expect("aggregate");

        struct VecPkProvider<'a> {
            pks: &'a [G2Point],
        }
        impl<'a> PubkeyProvider for VecPkProvider<'a> {
            fn g2_by_index(&self, idx: u16) -> Result<G2Point, BLSError> {
                self.pks
                    .get(idx as usize)
                    .copied()
                    .ok_or(BLSError::SerializationError)
            }
        }
        let provider = VecPkProvider { pks: &pubkeys_g2 };

        verify_a1_with_indices(&msg, &signer_indices, s_sum, &provider)
            .expect("A1 threshold verify failed");
    }
}
