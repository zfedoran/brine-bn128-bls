# Alt-BN128 BLS

This is a small fork of Dean Little’s excellent [`solana-alt-bn128-bls`](https://github.com/deanmlittle/solana-alt-bn128-bls).
The only changes here are structural: the library is split into two flavors so you can pick which group carries the public keys vs the signatures.

* **`min_sig/`** — *Public keys in G2, signatures in G1* (the original layout)
* **`min_pk/`** — *Public keys in G1, signatures in G2* (new, added in this fork)

Both variants target BN254 (a.k.a. alt-bn128) and use Solana’s alt-bn128 syscalls where available.

> [!Important]
> The `min_pk` variant unfortunately doesn't work. The G2 hash-to-curve implementation is broken without G2 syscall support.

