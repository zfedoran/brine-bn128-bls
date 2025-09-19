// Minimal Solana program example using brine-bn128-bls that verifies a single BLS signature.
// Instruction layout: [pk_c: 64 bytes | sig_c: 32 bytes | msg: remaining bytes]

#![allow(unexpected_cfgs)]

use brine_bn128_bls::{G1CompressedPoint, G1Point, G2CompressedPoint};
use pinocchio::{
    account_info::AccountInfo, entrypoint, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

#[no_mangle]
pub static IDL: &str = "https://github.com/org/repo/idl.json";

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    ix: &[u8],
) -> ProgramResult {
    if ix.len() < 64 + 32 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Parse compressed G2 pubkey
    let pk_c = G2CompressedPoint(
        ix[0..64].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Parse compressed G1 signature
    let sig_c = G1CompressedPoint(
        ix[64..96].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Remaining is message
    let msg = &ix[96..];

    // Decompress signature and verify against provided G2 pubkey
    let sig = G1Point::try_from(&sig_c).map_err(|_| ProgramError::InvalidInstructionData)?;
    pk_c.verify(&sig, msg).map_err(|_| ProgramError::MissingRequiredSignature)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use brine_bn128_bls::{G2CompressedPoint, PrivKey};
    use mollusk_svm::Mollusk;
    use solana_sdk::{
        account::AccountSharedData,
        instruction::{AccountMeta, Instruction},
        pubkey,
        pubkey::Pubkey,
    };

    #[test]
    fn svm_verifies_single_signature() {
        // Program id and VM
        let program_id = pubkey!("B1sA1tBn128111111111111111111111111111111111");
        // Update the path to your compiled program .so
        let mollusk = Mollusk::new(&program_id, "target/deploy/brine_bn128_bls_test");

        // Generate a key, sign a message, and compress both pubkey and signature
        let sk = PrivKey::from_random();
        let msg = b"minimal-example";
        let sig = sk.sign(msg).expect("sign");
        let sig_c = G1CompressedPoint::try_from(sig).expect("compress sig");
        let pk_c = G2CompressedPoint::try_from(&sk).expect("compress pk");

        // Build instruction data: [pk_c | sig_c | msg]
        let mut ix_data = Vec::with_capacity(64 + 32 + msg.len());
        ix_data.extend_from_slice(&pk_c.0);
        ix_data.extend_from_slice(&sig_c.0);
        ix_data.extend_from_slice(msg);

        // Execute
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
