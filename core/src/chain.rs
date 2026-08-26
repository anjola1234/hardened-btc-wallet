use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UtxoStatus {
    pub confirmed: bool,
}

pub fn confirmed_balance_sats(utxos: &[Utxo]) -> u64 {
    utxos
        .iter()
        .filter(|u| u.status.confirmed)
        .map(|u| u.value)
        .sum()
}