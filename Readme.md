# Alt-BN128 BLS

A small BLS library over BN254 (alt_bn128) for Solana. It places signatures in G1 and public keys in G2, uses Solana’s bn128 precompiles, supports single-signing, signature aggregation, and two multi-sig verification modes: fast aggregate verify (requires proof-of-possession for each registered public key) and an augmented mode that avoids PoP by hashing the public key into the message. 

This is a small fork of Dean Little’s excellent [`solana-alt-bn128-bls`](https://github.com/deanmlittle/solana-alt-bn128-bls).
