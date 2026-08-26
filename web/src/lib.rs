use wasm_bindgen::prelude::*;
use wallet_core::{storage, keys, chain, tx, generate_mnemonic};
use wallet_core::tx::SourcedUtxo;
use bip39::Mnemonic;
use bitcoin::{Address, Network};
use std::str::FromStr;

fn current_network() -> Network {
    Network::Bitcoin
}

#[wasm_bindgen]
pub struct NewWalletResult {
    wallet_bytes: Vec<u8>,
    address: String,
}

#[wasm_bindgen]
impl NewWalletResult {
    #[wasm_bindgen(getter)]
    pub fn wallet_bytes(&self) -> Vec<u8> { self.wallet_bytes.clone() }
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String { self.address.clone() }
}

#[wasm_bindgen]
pub fn create_new_wallet(passphrase: &str) -> Result<NewWalletResult, JsValue> {
    let mnemonic = generate_mnemonic().map_err(|e| JsValue::from_str(&e))?;
    let mnemonic_string = mnemonic.to_string();
    let wallet_bytes = storage::encrypt_to_bytes(&mnemonic_string, passphrase).map_err(|e| JsValue::from_str(&e))?;
    let wallet = keys::derive_wallet(&mnemonic, current_network()).map_err(|e| JsValue::from_str(&e))?;
    Ok(NewWalletResult { wallet_bytes, address: wallet.address.to_string() })
}

#[wasm_bindgen]
pub fn wallet_address_from_bytes(wallet_bytes: &[u8], passphrase: &str) -> Result<String, JsValue> {
    let decrypted = storage::decrypt_from_bytes(wallet_bytes, passphrase).map_err(|e| JsValue::from_str(&e))?;
    let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, &decrypted).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let wallet = keys::derive_wallet(&mnemonic, current_network()).map_err(|e| JsValue::from_str(&e))?;
    Ok(wallet.address.to_string())
}

#[wasm_bindgen]
pub fn balance_from_utxos_json(utxos_json: &str) -> Result<u64, JsValue> {
    let utxos: Vec<chain::Utxo> = serde_json::from_str(utxos_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(chain::confirmed_balance_sats(&utxos))
}

#[wasm_bindgen]
pub fn derive_address_at(wallet_bytes: &[u8], passphrase: &str, chain_num: u32, index: u32) -> Result<String, JsValue> {
    let decrypted = storage::decrypt_from_bytes(wallet_bytes, passphrase).map_err(|e| JsValue::from_str(&e))?;
    let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, &decrypted).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let wallet = keys::derive_wallet_at(&mnemonic, current_network(), chain_num, index).map_err(|e| JsValue::from_str(&e))?;
    Ok(wallet.address.to_string())
}

#[wasm_bindgen]
pub fn sign_transaction_multi(
    wallet_bytes: &[u8],
    passphrase: &str,
    sourced_utxos_json: &str,
    destination_str: &str,
    amount_sats: u64,
    change_address_str: &str,
) -> Result<String, JsValue> {
    let network = current_network();

    let destination = Address::from_str(destination_str)
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .require_network(network)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let change_address = Address::from_str(change_address_str)
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .require_network(network)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let decrypted = storage::decrypt_from_bytes(wallet_bytes, passphrase).map_err(|e| JsValue::from_str(&e))?;
    let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, &decrypted).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let sourced_utxos: Vec<SourcedUtxo> = serde_json::from_str(sourced_utxos_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse sourced UTXOs: {e}")))?;

    if sourced_utxos.is_empty() {
        return Err(JsValue::from_str("No confirmed UTXOs available to spend."));
    }

    let signed_tx = tx::build_and_sign_transaction(
        &mnemonic, network, &sourced_utxos, &destination, amount_sats, &change_address,
    ).map_err(|e| JsValue::from_str(&e))?;

    Ok(bitcoin::consensus::encode::serialize_hex(&signed_tx))
}