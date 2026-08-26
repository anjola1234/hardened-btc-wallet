# Hardened BTC Wallet

A from-scratch Bitcoin wallet built for a security bounty: fund it, open-source it,
and have someone actively try to hack it. This README, `SECURITY.md`, and
`THREAT_MODEL.md` together document what was built, why, and what its real limits are.

**No software wallet is provably unhackable.** This project's goal was to eliminate
every *known* class of wallet vulnerability, so that any successful attack requires a
genuinely novel exploit rather than a documented, avoidable mistake.

## What this is

- A BIP-39/BIP-32/BIP-84 hierarchical-deterministic Bitcoin wallet
- Two front-ends sharing one audited core: a native CLI and a browser-based website
  (client-side signing via WebAssembly -- the server never sees key material)
- Built from scratch: no wallet framework or boilerplate was used. Cryptographic
  primitives (elliptic curve math, hashing, encryption) come from established, audited
  libraries -- reimplementing those is a well-known way to introduce catastrophic bugs.

## Architecture

hardened-btc-wallet/
├── core/ -- shared wallet logic (Rust): key derivation, encryption, signing.
│ Network-agnostic; compiles to both native and WebAssembly unchanged.
├── cli/ -- native command-line front-end
└── web/ -- browser front-end (WASM), deployed as a static site


## Dependencies and why they're trusted

| Crate | Purpose | Why trusted |
|---|---|---|
| `bitcoin` | Bitcoin data structures, addresses, transactions | Maintained by the `rust-bitcoin` org; used throughout the Rust Bitcoin ecosystem |
| `secp256k1` (via `bitcoin`) | Elliptic curve signing | Rust bindings to Bitcoin Core's own `libsecp256k1` -- the most audited EC implementation in the Bitcoin ecosystem |
| `bip39` | Mnemonic seed phrases | `rust-bitcoin` org |
| `argon2` | Passphrase-based key derivation | RustCrypto org; Argon2id won the Password Hashing Competition |
| `chacha20poly1305` | Authenticated encryption at rest | RustCrypto org |
| `zeroize` | Guaranteed memory wiping of secrets | RustCrypto org |
| `rand` / `getrandom` | Cryptographically secure randomness | RustCrypto working group; wraps the OS CSPRNG (or the browser's `crypto.getRandomValues()` in WASM builds) |

All versions are pinned via `Cargo.lock`. Dependencies are checked against the RustSec
advisory database via `cargo audit` (see `SECURITY.md`).

## Key generation and derivation

- Entropy: OS CSPRNG only, read via `getrandom`. Fails closed (refuses to generate a
  key) if a real entropy source can't be obtained -- this directly targets a known
  real-world hardware wallet failure mode where a broken entropy path silently
  produced predictable output instead of erroring (documented in project history).
- Seed phrase: 24-word BIP-39 mnemonic (256 bits of entropy).
- Derivation: BIP-84 (native SegWit), path `m/84'/0'/0'/{chain}/{index}`.
  - Chain 0 = receiving addresses, chain 1 = change addresses.
  - A fresh address is used for every change output (found via blockchain scanning,
    not a locally persisted counter) to avoid the address-reuse privacy weakness.

## Storage

The mnemonic is never written to disk in plaintext. `wallet_mainnet.dat` contains:
`[16-byte salt][24-byte nonce][ciphertext]`, where the ciphertext is the mnemonic
encrypted with XChaCha20-Poly1305 (authenticated -- tampering is detected, not
silently accepted), using a key derived from your passphrase via Argon2id
(64 MiB memory, 3 iterations, 4-way parallelism -- OWASP's recommended baseline).

The encrypted file itself is not secret and is safe to share (e.g., with an
adversary trying to hack this wallet, or committed to this open-source repo) --
only the passphrase must stay secret.

## Signing

All ECDSA signatures use RFC 6979 deterministic nonces (via `secp256k1`'s built-in
signing, not any custom code) -- this eliminates an entire historical class of
nonce-reuse key-recovery bugs (see project history / threat model for specific
real-world incidents this pattern is based on).

Transactions may spend from multiple addresses at once; each input is signed with the
specific private key derived for the address it came from.

## How to build and run

**Prerequisites:** Rust (stable), the `wasm32-unknown-unknown` target, `wasm-pack`,
and a C compiler capable of targeting WebAssembly (Clang) for the web build.

```bash
# Native CLI
cargo build --release
cargo run --bin hardened-btc-wallet -- new       # create a wallet
cargo run --bin hardened-btc-wallet -- balance   # check balance (scans all addresses)
cargo run --bin hardened-btc-wallet -- send <address> <amount_sats>
cargo run --bin hardened-btc-wallet -- reveal    # view recovery phrase (local only)

# Web (WASM)
cd web
wasm-pack build --target web
python -m http.server 8000   # or any static file server
# open http://localhost:8000/index.html
```

## How to verify this yourself

- Read the source. Every file is short enough to review in full; nothing here is
  generated boilerplate.
- Run `cargo audit` to independently check the dependency tree against known
  vulnerabilities.
- Run `cargo build` / `wasm-pack build` yourself and diff the resulting binary's
  behavior against what's documented here.
- The `decode` CLI command independently parses any raw transaction hex through a
  separate code path from the one that builds/signs it -- useful for cross-checking
  a transaction before broadcasting.

## Known limitations (see `THREAT_MODEL.md` for full detail)

- No OS-level memory locking; secrets are zeroed on drop but could theoretically be
  paged to swap while in use.
- The web GUI trusts Vercel's hosting/build pipeline and the user's browser
  environment, same as any client-side web wallet.
- Sending currently requires the browser/CLI to scan a bounded range of addresses
  (gap limit) to find funds; a very large gap between used addresses could
  theoretically hide funds from the scan (mitigated by a generous default gap limit).

## License

MIT.
