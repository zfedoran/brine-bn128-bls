// BLS multi-signature helpers.
//
// These functions provide a way to prove that “at least t specific people signed this message”
// without uploading a pile of signatures. Each chosen signer makes a small partial signature.
// Someone off-chain combines those partials into one short, aggregated signature and sends that
// plus the list of who signed (using a bitmap). On-chain, the program already knows everyone’s
// public keys (with PoP), it checks that this one signature really corresponds to the message and
// exactly the listed people. If it passes, you’ve shown both that enough people signed (threshold)
// and exactly which people did (attribution).
//
// For example, a 2-of-3 committee with public keys PK1, PK2, PK3 
// (Solana can do ~100 sigs in one tx)
//
// Committee:
//   PK1, PK2, PK3 in G2
// Threshold:
//   t = 2
//
// Signing:
//   Signers 1 and 3 each create a partial in G1 for message m:
//     s1, s3
//   Aggregator sums the partials off-chain:
//     S_sum = s1 + s3
//   Aggregator submits:
//     - indices: [1, 3]
//     - aggregated signature: S_sum
//
// On-chain verification:
//   1) Compute H(m) in G1
//   2) Look up PK1 and PK3 from the committee registry
//   3) Build pairing input with three pairs:
//        (H(m), PK1)
//        (H(m), PK3)
//        (S_sum, -G2_one)
//   4) Run the pairing check; if it returns 1, the signature is valid
//
// Result:
//   Valid and attributable to indices {1, 3} because only PK1 and PK3 were used

use crate::consts::G2_MINUS_ONE;
use crate::errors::BLSError;
use crate::g1::G1Point;
use crate::g2::G2Point;
use crate::hash::hash_to_curve;

use solana_bn254::prelude::{
    alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing,
};

/// Compute a BLS partial signature in G1.
/// Input:
/// - sk: 32 byte big-endian secret key
/// - message: message bytes
/// Output:
/// - S_i = H(message) * sk_i as a G1 point (uncompressed 64 bytes)
/// Notes:
/// - This is used for fast aggregate verify. See verify_fast_aggregate below.
/// - For production, add domain separation to your message.
/// - BN254 has about 100-bit security.
pub fn bls_partial_sign(
    sk: &[u8; 32],
    message: impl AsRef<[u8]>,
) -> Result<G1Point, BLSError> {
    let h_g1 = hash_to_curve(message)?.0;

    let mut inbuf = [0u8; 96];
    inbuf[..64].copy_from_slice(&h_g1);
    inbuf[64..].copy_from_slice(&sk[..]);

    let out = alt_bn128_multiplication(&inbuf).map_err(|_| BLSError::AltBN128MulError)?;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&out[..64]);
    Ok(G1Point(sig))
}

/// Compute an augmented BLS partial signature in G1.
/// Input:
/// - sk: 32 byte big-endian secret key
/// - message: message bytes
/// - signer_pk_g2: the signer's public key in G2 (uncompressed 128 bytes)
/// Output:
/// - S_i = H(pk_i || message) * sk_i as a G1 point
/// Notes:
/// - Augmented signing binds the public key into the hash. This prevents rogue-key attacks
///   without requiring a proof of possession (PoP).
/// - This is slower than fast aggregate verify because the verifer must hash per signer.
pub fn bls_partial_sign_augmented(
    sk: &[u8; 32],
    message: impl AsRef<[u8]>,
    signer_pk_g2: &G2Point,
) -> Result<G1Point, BLSError> {
    let mut m = Vec::with_capacity(3 + 128 + message.as_ref().len());
    m.extend_from_slice(&signer_pk_g2.0);
    m.extend_from_slice(message.as_ref());

    let h_g1 = hash_to_curve(&m)?.0;

    let mut inbuf = [0u8; 96];
    inbuf[..64].copy_from_slice(&h_g1);
    inbuf[64..].copy_from_slice(&sk[..]);

    let out = alt_bn128_multiplication(&inbuf).map_err(|_| BLSError::AltBN128MulError)?;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&out[..64]);
    Ok(G1Point(sig))
}

/// Sum a list of partial signatures in G1.
/// Input:
/// - partials: list of S_i points
/// Output:
/// - S_sum = sum of all S_i (G1 point)
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

/// Helper to check that a list of G2 pubkeys has no duplicates.
fn check_no_duplicate_pubkeys(pubkeys: &[G2Point]) -> bool {
    for i in 0..pubkeys.len() {
        for j in (i + 1)..pubkeys.len() {
            if pubkeys[i].0 == pubkeys[j].0 {
                return false;
            }
        }
    }
    true
}

/// Fast aggregate verify for BLS multi-signatures.
/// Input:
/// - message: message bytes
/// - signer_pubkeys: the exact G2 public keys that supposedly signed
/// - s_sum: aggregated G1 signature = sum of signers' partial signatures
/// Output:
/// - Ok if the aggregate verifies, Err otherwise
/// Important:
/// - This fast path is only safe if every public key is registered with a proof of possession (PoP).
/// - Without PoP, a malicious signer can craft a rogue key and make it look like others signed.
pub fn verify_fast_aggregate<M: AsRef<[u8]>>(
    message: M,
    signer_pubkeys: &[G2Point],
    s_sum: &G1Point,
) -> Result<(), BLSError> {
    let k = signer_pubkeys.len();
    if k == 0 {
        return Err(BLSError::SerializationError);
    }
    if !check_no_duplicate_pubkeys(signer_pubkeys) {
        return Err(BLSError::SerializationError);
    }

    // Hash message to G1 once
    let h_g1 = hash_to_curve(message.as_ref())?.0;

    // Build input for pairing:
    // For each signer: pair (H(m), PK_i)
    // Final pair: (S_sum, -G2).
    let mut input = vec![0u8; 192 * (k + 1)];

    for (i, pk) in signer_pubkeys.iter().enumerate() {
        let off = 192 * i;
        input[off..off + 64].copy_from_slice(&h_g1);
        input[off + 64..off + 192].copy_from_slice(&pk.0);
    }

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

/// Augmented aggregate verify for BLS multi-signatures.
/// Input:
/// - message: message bytes
/// - signer_pubkeys: the exact G2 public keys that supposedly signed
/// - s_sum: aggregated G1 signature = sum of augmented partial signatures
/// Output:
/// - Ok if the aggregate verifies, Err otherwise
/// Notes:
/// - This scheme binds each signer public key into the message hash. That prevents rogue-key
///   attacks without requiring PoP.
/// - Each signer must have signed with bls_partial_sign_augmented.
/// - Duplicate pubkeys are rejected to prevent counting the same signer more than once.
/// - This is slower than the fast path because it hashes once per signer.
pub fn verify_augmented<M: AsRef<[u8]>>(
    message: M,
    signer_pubkeys: &[G2Point],
    s_sum: &G1Point,
) -> Result<(), BLSError> {
    let k = signer_pubkeys.len();
    if k == 0 {
        return Err(BLSError::SerializationError);
    }
    if !check_no_duplicate_pubkeys(signer_pubkeys) {
        return Err(BLSError::SerializationError);
    }

    // Build input pairs
    let mut input = vec![0u8; 192 * (k + 1)];

    // For each signer: H(pk_i || message), pair with pk_i
    // Final pair: S_sum with -G2
    for (i, pk) in signer_pubkeys.iter().enumerate() {
        let mut m = Vec::with_capacity(3 + 128 + message.as_ref().len());
        m.extend_from_slice(&pk.0);
        m.extend_from_slice(message.as_ref());

        let h_g1 = hash_to_curve(&m)?.0;

        let off = 192 * i;
        input[off..off + 64].copy_from_slice(&h_g1);
        input[off + 64..off + 192].copy_from_slice(&pk.0);
    }

    let off = 192 * k;
    input[off..off + 64].copy_from_slice(&s_sum.0);
    input[off + 64..off + 192].copy_from_slice(&G2_MINUS_ONE);

    // This is ~13k CU per pairing after an initial ~39k CU for the first one.
    let r = alt_bn128_pairing(&input).map_err(|_| BLSError::AltBN128PairingError)?;
    let ok = r.iter().take(31).all(|&b| b == 0) && r[31] == 1;
    if ok {
        Ok(())
    } else {
        Err(BLSError::BLSVerificationError)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_partials,
        bls_partial_sign,
        bls_partial_sign_augmented,
        verify_fast_aggregate,
        verify_augmented,
    };
    use crate::g1::G1Point;
    use crate::g2::G2Point;
    use crate::privkey::PrivKey;

    #[test]
    fn fast_aggregate_random() {
        // In prod, ensure every pk has a PoP, or use the augmented variant.
        let msg = b"fast-agg";

        let keys: Vec<PrivKey> = (0..8).map(|_| PrivKey::from_random()).collect();
        let pks: Vec<G2Point> = keys.iter().map(|k| G2Point::try_from(k).unwrap()).collect();

        let partials: Vec<G1Point> = keys.iter()
            .map(|k| bls_partial_sign(&k.0, msg).unwrap())
            .collect();

        let s_sum = aggregate_partials(&partials).expect("aggregate");

        verify_fast_aggregate(msg, &pks, &s_sum).expect("fast agg verify");
    }

    #[test]
    fn fast_aggregate_wrong_message_fails() {
        let m1 = b"m1";
        let m2 = b"m2";

        let keys: Vec<PrivKey> = (0..4).map(|_| PrivKey::from_random()).collect();
        let pks: Vec<G2Point> = keys.iter().map(|k| G2Point::try_from(k).unwrap()).collect();

        let partials: Vec<G1Point> = keys.iter()
            .map(|k| bls_partial_sign(&k.0, m1).unwrap())
            .collect();

        let s_sum = aggregate_partials(&partials).expect("aggregate");
        let err = verify_fast_aggregate(m2, &pks, &s_sum).unwrap_err();
        assert_eq!(err, crate::errors::BLSError::BLSVerificationError);
    }

    #[test]
    fn fast_aggregate_rejects_duplicate_pubkeys() {
        let msg = b"dup-pk";

        let sk = PrivKey::from_random();
        let pk = G2Point::try_from(&sk).unwrap();

        // Create a valid partial signature
        let s = bls_partial_sign(&sk.0, msg).unwrap();
        let s_sum = aggregate_partials(&[s.clone(), s]).unwrap();

        // Duplicate pks must be rejected
        let err = verify_fast_aggregate(msg, &[pk, pk], &s_sum).unwrap_err();
        assert_eq!(err, crate::errors::BLSError::SerializationError);
    }

    #[test]
    fn augmented_random() {
        // Augmented path: no PoP required. PK is bound into the hashed message.
        let msg = b"aug-agg";

        let keys: Vec<PrivKey> = (0..7).map(|_| PrivKey::from_random()).collect();
        let pks: Vec<G2Point> = keys.iter().map(|k| G2Point::try_from(k).unwrap()).collect();

        let partials: Vec<G1Point> = keys.iter()
            .zip(pks.iter())
            .map(|(k, pk)| bls_partial_sign_augmented(&k.0, msg, pk).unwrap())
            .collect();

        let s_sum = aggregate_partials(&partials).expect("aggregate");
        verify_augmented(msg, &pks, &s_sum).expect("aug verify");
    }

    #[test]
    fn augmented_wrong_message_fails() {
        let m1 = b"aug-m1";
        let m2 = b"aug-m2";

        let sk = PrivKey::from_random();
        let pk = G2Point::try_from(&sk).unwrap();

        let s = bls_partial_sign_augmented(&sk.0, m1, &pk).unwrap();
        let s_sum = aggregate_partials(&[s]).unwrap();

        let err = verify_augmented(m2, &[pk], &s_sum).unwrap_err();
        assert_eq!(err, crate::errors::BLSError::BLSVerificationError);
    }
}
