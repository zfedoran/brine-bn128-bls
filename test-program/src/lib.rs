#![allow(unexpected_cfgs)]
use brine_bn128_bls::min_sig::*;
use pinocchio::{
    account_info::AccountInfo, entrypoint, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

#[no_mangle]
pub static IDL: &str = "https://github.com/org/repo/idl.json";

entrypoint!(process_instruction);

const PK_LEN: usize = 64; // G2CompressedPoint
const SIG_LEN: usize = 32; // G1CompressedPoint

use solana_bn254::prelude::alt_bn128_pairing;

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    ix: &[u8],
) -> ProgramResult {

    let pk = G2CompressedPoint(ix[..PK_LEN].try_into().unwrap());
    let sig = G1CompressedPoint(ix[PK_LEN..PK_LEN + SIG_LEN].try_into().unwrap());
    let msg = &ix[PK_LEN + SIG_LEN..];

    pk.verify_signature::<Sha256, _, G1CompressedPoint>(sig, msg)
       .map_err(|_| ProgramError::MissingRequiredSignature)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let sk = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8,
            0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9,
        ]);

        // Produce G1 signature (compressed) and G2 pubkey (compressed)
        let msg = msg_bytes();

        let sig_g1 = G1CompressedPoint::try_from(
            sk.sign::<Sha256, _>(&msg).expect("sign"),
        ).expect("compress sig");
        let pk_g2 = G2CompressedPoint::try_from(&sk).expect("pk from sk");

        let mut ix_data = vec![];
        ix_data.extend_from_slice(&pk_g2.0);
        ix_data.extend_from_slice(&sig_g1.0);
        ix_data.extend_from_slice(&msg);

        let signer = Pubkey::new_unique();
        let ix = Instruction::new_with_bytes(
            program_id, 
            &ix_data, 
            vec![AccountMeta::new(signer, true)
        ]);

        let _: mollusk_svm::result::InstructionResult = mollusk.process_instruction(
            &ix,
            &[(signer, AccountSharedData::new(10_000, 0, &Pubkey::default()))],
        );
    }
}


