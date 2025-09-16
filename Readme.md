# Solana alt-bn128 BLS (min\_sig & min\_pk)

This is a small fork of **Dean Little’s** excellent [`solana-alt-bn128-bls`](https://github.com/deanmlittle/solana-alt-bn128-bls).
The only changes here are structural: the library is split into two flavors so you can pick which group carries the public keys vs the signatures.

* **`min_sig/`** — *Public keys in G2, signatures in G1* (the original layout)
* **`min_pk/`** — *Public keys in G1, signatures in G2* (new, added in this fork)

Both variants target BN254 (a.k.a. alt-bn128) and use Solana’s alt-bn128 syscalls where available.

> [!Important] The `min_pk` variant unfortunately doesn't work. The G2 hash-to-curve implementation is broken without G2 syscall support.

---

## Why two flavors?

BLS uses two groups, **G1** (smaller, faster arithmetic) and **G2** (larger, slower arithmetic).
You can place public keys in one group and signatures in the other; pairing still works either way.

* **G1 elements**: 64 bytes uncompressed (32+32 limbs), cheap add/mul.
* **G2 elements**: 128 bytes uncompressed (64+64 limbs), arithmetic \~3× slower.

### Trade-offs at a glance

| Variant   | Public keys | Signatures | On-chain aggregation |
| --------- | ----------- | ---------- | -------------------- |
| `min_sig` | **G2**      | **G1**     | **Signatures** (G1)  |
| `min_pk`  | **G1**      | **G2**     | **Public keys** (G1) |

Solana currently exposes syscalls for:

* **G1 addition / scalar mul** (`alt_bn128_addition`, `alt_bn128_multiplication`)
* **Pairing** (`alt_bn128_pairing`)

...and does **NOT** expose G2 add/mul syscalls.

---

## Security & status

This is experimental code meant to illustrate how to structure BLS on Solana with either group layout. It has **not** been audited. Use at your own risk.

---

## Acknowledgements

* Huge thanks to **Dean Little** — this is a direct fork of his repo with a minimal reorganization into `min_sig` and `min_pk`.

---

## License

Same as upstream unless stated otherwise. See `LICENSE` in the root of this repository.
