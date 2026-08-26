use bitcoin::{Address, Network, Transaction};
use bitcoin::consensus::encode::serialize_hex;
use bip39::Mnemonic;
use wallet_core::chain::Utxo;
use wallet_core::keys;
use wallet_core::tx::SourcedUtxo;

const API_BASE: &str = "https://blockstream.info/api";
const GAP_LIMIT: u32 = 20;

pub fn fetch_utxos(address: &Address) -> Result<Vec<Utxo>, String> {
    let url = format!("{API_BASE}/address/{address}/utxo");
    let response = ureq::get(&url).call().map_err(|e| format!("Failed to fetch UTXOs: {e}"))?;
    response.into_json().map_err(|e| format!("Failed to parse UTXO response: {e}"))
}

pub fn broadcast_transaction(tx: &Transaction) -> Result<String, String> {
    let url = format!("{API_BASE}/tx");
    let raw_hex = serialize_hex(tx);
    let response = ureq::post(&url).send_string(&raw_hex).map_err(|e| format!("Broadcast failed: {e}"))?;
    response.into_string().map(|s| s.trim().to_string()).map_err(|e| format!("Failed to read broadcast response: {e}"))
}

fn address_has_history(address: &Address) -> Result<bool, String> {
    let url = format!("{API_BASE}/address/{address}");
    let response = ureq::get(&url).call().map_err(|e| format!("Failed to check address history: {e}"))?;
    let json: serde_json::Value = response.into_json().map_err(|e| format!("Failed to parse address info: {e}"))?;
    let chain_count = json["chain_stats"]["tx_count"].as_u64().unwrap_or(0);
    let mempool_count = json["mempool_stats"]["tx_count"].as_u64().unwrap_or(0);
    Ok(chain_count + mempool_count > 0)
}

pub fn find_unused_address(mnemonic: &Mnemonic, network: Network, chain: u32) -> Result<(u32, Address), String> {
    for index in 0..100 {
        let wallet = keys::derive_wallet_at(mnemonic, network, chain, index)?;
        if !address_has_history(&wallet.address)? {
            return Ok((index, wallet.address));
        }
    }
    Err("No unused address found within gap limit.".to_string())
}

pub fn gather_all_utxos(mnemonic: &Mnemonic, network: Network) -> Result<Vec<SourcedUtxo>, String> {
    let mut all = Vec::new();
    for chain in [0u32, 1u32] {
        let mut consecutive_empty = 0;
        for index in 0..GAP_LIMIT {
            let wallet = keys::derive_wallet_at(mnemonic, network, chain, index)?;
            let utxos = fetch_utxos(&wallet.address)?;
            if utxos.is_empty() {
                consecutive_empty += 1;
                if consecutive_empty >= 3 { break; }
                continue;
            }
            consecutive_empty = 0;
            for utxo in utxos {
                all.push(SourcedUtxo { utxo, chain, index });
            }
        }
    }
    Ok(all)
}