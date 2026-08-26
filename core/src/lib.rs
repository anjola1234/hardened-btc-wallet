pub mod storage;
pub mod keys;
pub mod chain;
pub mod tx;

use bip39::Mnemonic;
use rand::rngs::OsRng;
use rand::RngCore;

/// Generates a fresh 24-word BIP-39 mnemonic from OS-grade entropy.
/// Shared by both the native CLI and the WASM build -- one implementation
/// of this security-critical step, not two to keep in sync.
pub fn generate_mnemonic() -> Result<Mnemonic, String> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| format!("FATAL: OS entropy source failed: {e}. Refusing to generate a key."))?;
    Mnemonic::from_entropy(&bytes).map_err(|e| format!("Failed to encode entropy as mnemonic: {e}"))
}