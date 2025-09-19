#![allow(unexpected_cfgs)]

use brine_bn128_bls::{
    G1CompressedPoint, G1Point, G2CompressedPoint, G2Point,
    threshold::{verify_a1_with_indices, PubkeyProvider},
};
use pinocchio::{
    account_info::AccountInfo, entrypoint, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

#[no_mangle]
pub static IDL: &str = "https://github.com/org/repo/idl.json";

entrypoint!(process_instruction);

const PK_COUNT: usize = 3;       // three signers in this threshold demo
const PK_LEN: usize = 64;        // G2CompressedPoint (64 bytes)
const SIG_LEN: usize = 32;       // G1CompressedPoint (32 bytes)

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    ix: &[u8],
) -> ProgramResult {
    // Expect: [pk0(64) | pk1(64) | pk2(64) | sig_c(32) | msg(..)]
    let header_len = PK_COUNT * PK_LEN + SIG_LEN;
    if ix.len() < header_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Parse 3 compressed G2 pubkeys
    let mut pks_g2 = [G2Point([0u8; 128]); PK_COUNT];
    for i in 0..PK_COUNT {
        let start = i * PK_LEN;
        let end = start + PK_LEN;
        let pk_c = G2CompressedPoint(
            ix[start..end]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );
        // Decompress to uncompressed G2Point (128 bytes) for pairing
        let pk = G2Point::try_from(pk_c)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        pks_g2[i] = pk;
    }

    // Parse aggregated signature (compressed G1)
    let sig_off = PK_COUNT * PK_LEN;
    let sig_c = G1CompressedPoint(
        ix[sig_off..sig_off + SIG_LEN]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    let s_sum = G1Point::try_from(&sig_c)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Message is the remainder
    let msg = &ix[header_len..];

    // Simple provider over our three pubkeys
    struct StaticPkProvider([G2Point; PK_COUNT]);
    impl PubkeyProvider for StaticPkProvider {
        fn g2_by_index(&self, idx: u16) ->
            Result<G2Point, brine_bn128_bls::errors::BLSError> {
            self.0
                .get(idx as usize)
                .copied()
                .ok_or(brine_bn128_bls::errors::BLSError::SerializationError)
        }
    }
    let provider = StaticPkProvider(pks_g2);

    // Indices for all three signers in order
    let indices = [0u16, 1u16, 2u16];

    // Verify A1 equation: e(S_sum, -G2::one()) * prod e(H(m), PK_i) == 1
    verify_a1_with_indices(msg, &indices, s_sum, &provider)
        .map_err(|_| ProgramError::MissingRequiredSignature)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mollusk_svm::Mollusk;
    use brine_bn128_bls::PrivKey;
    use solana_sdk::{
        account::AccountSharedData,
        instruction::{AccountMeta, Instruction},
        pubkey,
        pubkey::Pubkey,
    };

    fn msg_bytes() -> Vec<u8> {
        [&50_000u64.to_le_bytes()[..], b"BTCUSD<"].concat()
    }

    #[test]
    fn onchain_verify_threshold_3_pks() {
        // Program id and VM
        let program_id = pubkey!("B1sA1tBn128111111111111111111111111111111111");
        let mollusk = Mollusk::new(&program_id, "target/deploy/brine_bn128_bls_test");

        // Three deterministic privkeys (same as your g2 tests)
        let sk1 = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8,
            0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9,
        ]);
        let sk2 = PrivKey([
            0x22, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8,
            0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9,
        ]);
        let sk3 = PrivKey([
            0x23, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8,
            0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9,
        ]);

        // Message
        let msg = msg_bytes();

        // Partial signatures in G1 (uncompressed)
        let s1 = sk1.sign(&msg).expect("s1");
        let s2 = sk2.sign(&msg).expect("s2");
        let s3 = sk3.sign(&msg).expect("s3");

        // Aggregate off-chain with G1 add (your G1Point implements Add via syscall wrapper)
        let s_sum = s1 + s2 + s3;

        // Compress aggregated G1 signature for the ix payload
        let sig_c = G1CompressedPoint::try_from(s_sum).expect("compress sig");

        // Compressed G2 pubkeys for payload
        let pk1_c = G2CompressedPoint::try_from(&sk1).expect("pk1");
        let pk2_c = G2CompressedPoint::try_from(&sk2).expect("pk2");
        let pk3_c = G2CompressedPoint::try_from(&sk3).expect("pk3");

        // Instruction data: [pk1_c | pk2_c | pk3_c | sig_c | msg]
        let mut ix_data = Vec::with_capacity(PK_COUNT * PK_LEN + SIG_LEN + msg.len());
        ix_data.extend_from_slice(&pk1_c.0);
        ix_data.extend_from_slice(&pk2_c.0);
        ix_data.extend_from_slice(&pk3_c.0);
        ix_data.extend_from_slice(&sig_c.0);
        ix_data.extend_from_slice(&msg);

        // Build and run
        let signer = Pubkey::new_unique();
        let ix = Instruction::new_with_bytes(
            program_id,
            &ix_data,
            vec![AccountMeta::new(signer, true)],
        );

        let _res: mollusk_svm::result::InstructionResult = mollusk.process_instruction(
            &ix,
            &[(signer, AccountSharedData::new(10_000, 0, &Pubkey::default()))],
        );
    }
}
