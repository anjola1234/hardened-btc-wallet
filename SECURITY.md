# Security Policy

## Reporting an issue

If you find a security issue in this code, open an issue in this repository or
contact the maintainer directly. Please include:
- A description of the issue and its potential impact
- Steps to reproduce, if applicable
- Which component is affected (`core`, `cli`, or `web`)

This is a small, non-commercial project (built for a security bounty exercise), so
there's no formal bug bounty program, but genuine findings are taken seriously and
credited.

## What is guaranteed

- **Entropy**: all key material is generated exclusively from the OS cryptographically
  secure random number generator (or the browser's `crypto.getRandomValues()` in the
  WASM build). Generation fails closed -- it refuses to produce a key -- if a real
  entropy source can't be obtained, rather than silently falling back to something
  weaker.
- **Storage**: the mnemonic is never written to disk (or held in browser storage) in
  plaintext. It is encrypted at rest with XChaCha20-Poly1305 (authenticated: tampering
  is detected, not silently accepted), using a key derived from the user's passphrase
  via Argon2id with OWASP-recommended parameters.
- **Nonce generation**: all ECDSA signatures use RFC 6979 deterministic nonces via the
  underlying `secp256k1` library -- no custom nonce generation exists anywhere in this
  codebase, eliminating an entire historical class of nonce-reuse key-recovery bugs.
  This was specifically re-verified under multi-input signing (where each input
  requires its own key/signature) via successful real-network broadcasts.
- **Memory hygiene**: private key material, decrypted mnemonics, and passphrases are
  wrapped in types that guarantee zeroing on drop (`zeroize`/`Zeroizing`). No secret is
  intentionally logged, printed outside of the explicit, user-confirmed `reveal`
  command (CLI-only, deliberately not exposed on the public website), or written
  anywhere beyond its minimum necessary lifetime.
- **Address privacy**: the wallet derives fresh receiving and change addresses via
  blockchain scanning rather than reusing a single address, avoiding the standard
  address-reuse privacy weakness. Independently verified via block explorer analysis.
- **Client-side signing (web)**: the website never transmits a passphrase, mnemonic, or
  private key to any server. All decryption, key derivation, and signing happen
  entirely within the user's browser via WebAssembly. The hosting provider (Vercel)
  serves only static files and has no access to any key material at any point.
- **Dependency auditing**: all dependencies are pinned via a single workspace
  `Cargo.lock` and checked against the RustSec advisory database via `cargo audit`.
  Zero known vulnerabilities found across the full dependency tree (139 crates).
- **Transaction review**: both the CLI and web front-ends require explicit,
  human-readable review of a fully-built and signed transaction -- including a
  distinct, separately-worded confirmation step -- before anything is broadcast to the
  network. No transaction is ever sent automatically or silently.

## What is NOT guaranteed (explicit, accepted limitations)

- **No protection against a compromised OS, browser, or physical device.** If the
  machine running this software is already compromised at the OS level (malware with
  full system access, a live keylogger, a browser with a malicious extension that has
  page-content access), this software cannot defend against that. This is a limitation
  shared by essentially all software wallets, not specific to this implementation.
- **No OS-level memory locking (`mlock`-equivalent).** Secret material is zeroed
  immediately after use, but during that brief window it exists in ordinary process
  memory, which could theoretically be written to swap by the operating system. Full
  protection against this would require OS-level memory pinning, which is not
  implemented.
- **No protection against operator error.** Screenshotting a recovery phrase, typing
  a passphrase into a phishing site, or losing the encrypted wallet file with no
  separate backup are all outside what any wallet's code can prevent. This project's
  `reveal` command (CLI-only, intentionally not exposed on the public website) exists
  to let the operator make their own deliberate backup, but what they do with that
  backup afterward is entirely their responsibility.
- **No custom side-channel (timing/cache) hardening.** Constant-time behavior for
  elliptic curve operations is inherited entirely from the underlying `secp256k1`
  library (itself derived from Bitcoin Core's C implementation). No timing-sensitive
  code was written specifically for this project, which is the correct posture
  (don't hand-roll this), but it also means this guarantee is only as strong as that
  upstream library's.
- **Hosting and build-pipeline trust (web version only).** The live website depends on
  Vercel serving exactly the committed, unmodified static files. This is a standard,
  generally-accepted trust boundary (equivalent to trusting GitHub or any package
  registry already in scope for this project), but is named explicitly here since it
  did not exist for the CLI-only version.
- **Gap-limit address scanning.** Both front-ends scan a bounded number of addresses
  per derivation chain when checking balance or gathering funds to spend. A very large
  unused gap between historically-used addresses could theoretically cause funds to be
  missed by the scan. The default gap limit is generous for normal use but is not
  infinite.

See `THREAT_MODEL.md` for the full breakdown of in-scope vs. out-of-scope attacks and
the reasoning behind each decision above.

## Documented deliberate trade-off: development/funding machine

This project's threat model originally called for funding the wallet from a clean,
purpose-dedicated VM rather than a general-purpose daily-use machine, to minimize
unrelated attack surface (other installed software, browser extensions, etc.). After
weighing the cost (redoing the full Rust/WASM toolchain setup) against the realistic
benefit for a $10-scale bounty with no specific evidence of machine compromise, the
decision was made to proceed on the existing development laptop instead. This is a
conscious, documented trade-off, not an oversight -- noted here in the same spirit of
transparency as every other decision in this project.