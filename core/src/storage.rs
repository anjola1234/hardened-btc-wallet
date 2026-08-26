use argon2::{Argon2, Params};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroize;

const ARGON2_MEMORY_KIB: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Encrypts a plaintext mnemonic, returning the raw bytes that should be
/// written to a file (native) or offered as a browser download (web).
/// No filesystem access here -- this function works identically on any
/// target, which is exactly what lets it compile to both native and WASM.
pub fn encrypt_to_bytes(plaintext_mnemonic: &str, passphrase: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 16];
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut salt)
        .map_err(|e| format!("Failed to generate salt: {e}"))?;

    let mut key_bytes = [0u8; 32];
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(32))
        .map_err(|e| format!("Invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key_bytes)
        .map_err(|e| format!("Argon2 key derivation failed: {e}"))?;

    let cipher = XChaCha20Poly1305::new((&key_bytes).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext_mnemonic.as_bytes())
        .map_err(|e| format!("Encryption failed: {e}"))?;

    key_bytes.zeroize();

    let mut out = Vec::with_capacity(16 + 24 + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Decrypts wallet bytes (from a file, or from a browser-uploaded file)
/// given the correct passphrase. No filesystem access.
pub fn decrypt_from_bytes(data: &[u8], passphrase: &str) -> Result<String, String> {
    if data.len() < 16 + 24 + 16 {
        return Err("Wallet data is too short / corrupted.".to_string());
    }

    let salt = &data[0..16];
    let nonce_bytes = &data[16..40];
    let ciphertext = &data[40..];

    let mut key_bytes = [0u8; 32];
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(32))
        .map_err(|e| format!("Invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| format!("Argon2 key derivation failed: {e}"))?;

    let cipher = XChaCha20Poly1305::new((&key_bytes).into());
    let nonce = XNonce::from_slice(nonce_bytes);

    let result = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed: wrong passphrase, or data has been tampered with.".to_string());

    key_bytes.zeroize();

    let plaintext_bytes = result?;
    String::from_utf8(plaintext_bytes).map_err(|e| format!("Corrupted plaintext: {e}"))
}