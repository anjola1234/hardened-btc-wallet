# Threat Model

## 1. Assets (in order of criticality)

1. **The seed** (BIP-39 mnemonic / root entropy) -- compromise of this compromises everything derived from it, forever, even after "fixing" the wallet.
2. **Derived private keys** -- compromise of a single key only compromises funds at that key's address(es).
3. **The passphrase/password** protecting the encrypted seed file at rest -- this is the *only* secret that should be able to unlock #1.
4. **The $10 in BTC itself** -- the actual bounty asset.
5. **Integrity of the receiving address shown to the funder** -- if this is tampered with (e.g. clipboard hijacking), funds go to the attacker at funding time, before any wallet-security question even matters.
6. **Integrity of the signing/broadcast flow** -- an attacker who can modify a transaction between "user approves" and "network broadcasts" can redirect funds without ever touching the key.

## 2. Adversary: capabilities and assumptions

- **Full source code access, before funding.** No security property may depend on the adversary not knowing how the code works.
- **Possible network access.** May be able to intercept or tamper with network traffic, run MITM on outbound API calls, or attempt to interact with any listening service.
- **Possible local machine access**, at some unknown point in time -- could include reading arbitrary files, inspecting a running process's memory, or capturing a memory/disk image. We do **not** assume continuous real-time access (e.g., a live keylogger active at the exact moment the passphrase is typed) -- that level of compromise is explicitly out of scope, because no software design defeats it.
- **No assumed access to the human** (no assumption they can socially engineer the operator, though phishing-resilience is still a nice-to-have).

## 3. Explicit in-scope attacks

- Predictable/weak RNG in key or seed generation (Coldcard-class failure)
- Nonce reuse / non-deterministic-nonce signature bugs (mitigated via RFC 6979)
- Plaintext or weakly-encrypted key/seed storage at rest
- Weak KDF protecting the storage passphrase (must be memory-hard, e.g. Argon2id)
- Key material lingering in memory or logs longer than necessary
- Supply-chain compromise via unpinned or unverified dependencies
- Non-constant-time cryptographic operations (timing side channels) in our own code
- Address reuse where structurally avoidable
- Transaction malleability (mitigated via SegWit/Taproot)
- A file-read or single memory-inspection snapshot by an attacker with transient local access yielding the seed in plaintext
- Tampering with the receiving/change address shown to the user without detection

## 4. Explicit out-of-scope attacks (operational, not code, risk)

- The operator being phished, socially engineered, or tricked into typing their passphrase into a fake prompt
- The operator screenshotting, photographing, or cloud-syncing their seed phrase or passphrase
- A live keylogger or screen-recorder active on the machine *at the moment* secrets are entered
- Continuous/real-time attacker presence on the machine during a signing session (as opposed to a point-in-time file or memory grab)
- Physical theft of the machine while the wallet is unlocked and decrypted in memory
- Compromise of the underlying OS/kernel itself
- Compromise of the third-party blockchain API/node used to broadcast transactions, beyond what TLS + our own address verification catches

## 5. What "winning" looks like

- **Supervisor wins** if they extract the seed/private key or redirect the $10 to an address they control, via any attack **not listed as out-of-scope above**.
- **We win** if, after a good-faith attempt, the funds remain under the operator's control and no seed/key material was exposed -- *or* if the supervisor's successful attack falls strictly within an out-of-scope category we documented in advance.

## 6. Residual risk statement

No software wallet on a general-purpose OS is provably unhackable against an adversary with source access and potential local access. This threat model's goal is to ensure any successful attack requires either (a) a genuinely novel vulnerability class, or (b) exploiting an explicitly out-of-scope operational risk -- not a rediscovery of a known, documented wallet-security mistake.

## 7. Addendum: web GUI / Vercel deployment

The project was extended with a browser-based GUI, publicly deployed via Vercel, per an explicit requirement from the adversary (supervisor). This materially changes the adversary's reach and introduces genuinely new attack surface, documented here rather than silently absorbed into the original model.

### 7.1 What changed
- The adversary's capability set expands from "possible local/network access to a machine the operator controls" to **"unauthenticated access to a public URL, from anywhere."**
- **Architecture mitigation:** private key material is never transmitted to or held by any server. All decryption, key derivation, and transaction signing happen client-side, inside the browser, via WebAssembly compiled from the same `wallet-core` Rust library used by the CLI. Vercel's role is limited to serving static files -- it holds no secrets and has no signing capability.
- The user's `wallet.dat` file is never uploaded to any server; it is read locally via the browser's File API and stays in browser memory for the session only.

### 7.2 New in-scope risks introduced by the web layer
- **Cross-site scripting (XSS):** mitigated by keeping the front-end minimal, hand-written JavaScript with no third-party libraries, no `eval`, and no dynamic HTML construction from untrusted input.
- **Hosting/build-pipeline integrity:** the project now trusts Vercel's build and CDN pipeline to serve exactly the committed code, unmodified. A standard, generally-accepted trust boundary, newly named here.
- **Browser environment trust:** security now also depends on the browser itself not being compromised (e.g., malicious extensions with page access). Standard assumption for any web-based wallet.
- **In-memory session caching:** the loaded wallet bytes and passphrase are cached in JavaScript memory for the browser tab's session (never localStorage/sessionStorage/cookies), to avoid repeated re-uploads and re-typing between actions. Cleared on tab close or reload.

### 7.3 Explicitly still out of scope (unchanged from Section 4)
- Compromise of the user's browser or OS itself
- Live/real-time surveillance of the operator while using the site
- Physical device compromise

### 7.4 What "winning" looks like, updated
Unchanged in substance from Section 5 -- the adversary still wins by extracting key material or redirecting funds via an in-scope attack, whether that attack targets the CLI, the web GUI, or the underlying `wallet-core` logic they share.