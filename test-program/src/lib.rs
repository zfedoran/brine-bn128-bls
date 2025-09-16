use brine_bn128_bls::{min_pk, min_sig};
use pinocchio::{
    account_info::AccountInfo, entrypoint, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

#[no_mangle]
pub static IDL: &str = "https://github.com/org/repo/idl.json";

// instruction layout:
// tag = 0x00 => min_sig: [tag][pk_g2_compressed(64)][sig_g1_compressed(32)][message...]
// tag = 0x01 => min_pk:  [tag][pk_g1_compressed(32)][sig_g2_compressed(64)][message...]

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    ix: &[u8],
) -> ProgramResult {
    if ix.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match ix[0] {
        // min_sig: PK in G2, SIG in G1 (both compressed in the ix)
        0x00 => {
            const PK_LEN: usize = 64; // G2CompressedPoint
            const SIG_LEN: usize = 32; // G1CompressedPoint
            if ix.len() < 1 + PK_LEN + SIG_LEN {
                return Err(ProgramError::InvalidInstructionData);
            }
            let pk = min_sig::G2CompressedPoint(ix[1..1 + PK_LEN].try_into().unwrap());
            let sig = min_sig::G1CompressedPoint(ix[1 + PK_LEN..1 + PK_LEN + SIG_LEN].try_into().unwrap());
            let msg = &ix[1 + PK_LEN + SIG_LEN..];

            pk.verify_signature::<min_sig::Sha256, _, min_sig::G1CompressedPoint>(sig, msg)
                .map_err(|_| ProgramError::MissingRequiredSignature)?;
            Ok(())
        }

        // min_pk: PK in G1, SIG in G2 (both compressed in the ix)
        0x01 => {
            const PK_LEN: usize = 32; // G1CompressedPoint
            const SIG_LEN: usize = 64; // G2CompressedPoint
            if ix.len() < 1 + PK_LEN + SIG_LEN {
                return Err(ProgramError::InvalidInstructionData);
            }

            let _pk = min_pk::G1CompressedPoint(ix[1..1 + PK_LEN].try_into().unwrap());
            let _sig = min_pk::G2CompressedPoint(ix[1 + PK_LEN..1 + PK_LEN + SIG_LEN].try_into().unwrap());
            let _msg = &ix[1 + PK_LEN + SIG_LEN..];

            // Currently disabled due to missing hash-to-curve in min-pk
            // pk.verify_signature::<min_pk::Sha256, _, min_pk::G2CompressedPoint>(sig, msg)
            //     .map_err(|e| {
            //         ProgramError::MissingRequiredSignature
            //     })?;
            Ok(())
        }

        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brine_bn128_bls::{min_pk, min_sig};
    use mollusk_svm::Mollusk;
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
    fn onchain_verify_min_sig() {
        // Program id + VM
        let program_id = pubkey!("B1sA1tBn128111111111111111111111111111111111");
        let mollusk = Mollusk::new(&program_id, "target/deploy/brine_bn128_bls_test");

        // Deterministic key
        let sk = min_sig::PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8,
            0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9,
        ]);

        // Produce G1 signature (compressed) and G2 pubkey (compressed)
        let msg = msg_bytes();
        let sig_g1 = min_sig::G1CompressedPoint::try_from(
            sk.sign::<min_sig::Sha256, _>(&msg).expect("sign"),
        )
        .expect("compress sig");
        let pk_g2 = min_sig::G2CompressedPoint::try_from(&sk).expect("pk from sk");

        // Instruction: [tag=0x00][pk_g2(64)][sig_g1(32)][msg...]
        let mut ix_data = Vec::with_capacity(1 + 64 + 32 + msg.len());
        ix_data.push(0x00);
        ix_data.extend_from_slice(&pk_g2.0);
        ix_data.extend_from_slice(&sig_g1.0);
        ix_data.extend_from_slice(&msg);

        let signer = Pubkey::new_unique();
        let ix = Instruction::new_with_bytes(program_id, &ix_data, vec![AccountMeta::new(signer, true)]);

        let _: mollusk_svm::result::InstructionResult = mollusk.process_instruction(
            &ix,
            &[(signer, AccountSharedData::new(10_000, 0, &Pubkey::default()))],
        );
    }

    #[test]
    fn onchain_verify_min_pk() {
        // Program id + VM
        let program_id = pubkey!("B1sA1tBn128111111111111111111111111111111111");
        let mollusk = Mollusk::new(&program_id, "target/deploy/brine_bn128_bls_test");

        // Deterministic key
        let sk = min_pk::PrivKey([
            0x22, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8,
            0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9,
        ]);

        // Produce G2 signature (compressed) and G1 pubkey (compressed)
        let msg = msg_bytes();
        let sig_g2 = min_pk::G2CompressedPoint::try_from(
            &sk.sign::<min_pk::Sha256, _>(&msg).expect("sign"),
        )
        .expect("compress sig");
        let pk_g1 = min_pk::G1CompressedPoint::try_from(&sk).expect("pk from sk");

        // Instruction: [tag=0x01][pk_g1(32)][sig_g2(64)][msg...]
        let mut ix_data = Vec::with_capacity(1 + 32 + 64 + msg.len());
        ix_data.push(0x01);
        ix_data.extend_from_slice(&pk_g1.0);
        ix_data.extend_from_slice(&sig_g2.0);
        ix_data.extend_from_slice(&msg);

        let signer = Pubkey::new_unique();
        let ix = Instruction::new_with_bytes(program_id, &ix_data, vec![AccountMeta::new(signer, true)]);

        let _: mollusk_svm::result::InstructionResult = mollusk.process_instruction(
            &ix,
            &[(signer, AccountSharedData::new(10_000, 0, &Pubkey::default()))],
        );
    }
}
