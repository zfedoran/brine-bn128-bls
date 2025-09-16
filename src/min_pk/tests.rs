use super::{
    G1Point,
    G1CompressedPoint,
    G2Point,
    G2CompressedPoint,
    PrivKey,
    Sha256,
};

#[test]
fn perps_aggregation() {
    // same message as min_sig test
    let msg = [&50_000u64.to_le_bytes()[..], b"BTCUSD<"].concat();

    // three fixed keys
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

    // Sign in G2
    let sig_1 = privkey_1.sign::<Sha256, &[u8]>(&msg).unwrap();
    let sig_2 = privkey_2.sign::<Sha256, &[u8]>(&msg).unwrap();
    let sig_3 = privkey_3.sign::<Sha256, &[u8]>(&msg).unwrap();

    // Public keys in G1
    let pubkey_1 = G1Point::try_from(&privkey_1).expect("Invalid private key");
    let pubkey_2 = G1Point::try_from(&privkey_2).expect("Invalid private key");
    let pubkey_3 = G1Point::try_from(&privkey_3).expect("Invalid private key");

    // Aggregate
    let sig_agg = sig_1 + sig_2 + sig_3;
    let pubkey_agg = pubkey_1 + pubkey_2 + pubkey_3;

    // Verify aggregate
    pubkey_agg
        .verify_signature::<Sha256, &[u8], G2Point>(sig_agg, &msg)
        .expect("Failed to verify aggregated signature");
}

#[test]
fn signature_verification() {
    let privkey = PrivKey([
        0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
        0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
        0xba, 0xaf, 0xb5, 0xc9,
    ]);

    // Sign a message in G2
    let signature = privkey
        .sign::<Sha256, &str>("sample")
        .expect("Signature error");

    // Compress signature (G2) and public key (G1)
    let signature_compressed =
        G2CompressedPoint::try_from(&signature).expect("Failed to compress G2 point");
    let pubkey_compressed =
        G1CompressedPoint::try_from(&privkey).expect("Invalid private key");

    // Verify using compressed types
    assert!(
        pubkey_compressed
            .verify_signature::<Sha256, &str, G2CompressedPoint>(
                signature_compressed,
                "sample",
            )
            .is_ok()
    );
}
