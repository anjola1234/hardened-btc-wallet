use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, CompressedPublicKey};
use bip39::Mnemonic;
use std::str::FromStr;
use zeroize::Zeroize;

pub struct DerivedWallet {
    pub xpriv: Xpriv,
    pub address: Address,
}

/// Derives a BIP-84 (native SegWit) wallet at an arbitrary chain/index.
///
/// `chain`: 0 = external (receiving addresses shown to others),
///          1 = internal (change addresses, never shown to anyone)
/// `index`: the address index within that chain (0, 1, 2, ...)
///
/// Using separate chains for receiving vs. change, and incrementing the
/// index each time, is what avoids the address-reuse privacy weakness
/// flagged in Phase 5 -- every transaction's change lands on a fresh
/// address instead of cycling back to the same one.
pub fn derive_wallet_at(mnemonic: &Mnemonic, network: Network, chain: u32, index: u32) -> Result<DerivedWallet, String> {
    let mut seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();

    let master_xpriv = Xpriv::new_master(network, &seed)
        .map_err(|e| format!("Failed to derive master key: {e}"))?;

    seed.zeroize();

    let path_str = format!("m/84'/0'/0'/{chain}/{index}");
    let path = DerivationPath::from_str(&path_str)
        .map_err(|e| format!("Invalid derivation path: {e}"))?;

    let child_xpriv = master_xpriv
        .derive_priv(&secp, &path)
        .map_err(|e| format!("Child key derivation failed: {e}"))?;

    let compressed_pubkey = CompressedPublicKey::from_private_key(&secp, &child_xpriv.to_priv())
        .map_err(|e| format!("Failed to derive public key: {e}"))?;

    let address = Address::p2wpkh(&compressed_pubkey, network);

    Ok(DerivedWallet {
        xpriv: child_xpriv,
        address,
    })
}

/// Convenience wrapper: the first receiving address (chain 0, index 0).
/// Kept for backward compatibility with existing "load"/"balance" flows
/// that show a single, stable primary address.
pub fn derive_wallet(mnemonic: &Mnemonic, network: Network) -> Result<DerivedWallet, String> {
    derive_wallet_at(mnemonic, network, 0, 0)
}