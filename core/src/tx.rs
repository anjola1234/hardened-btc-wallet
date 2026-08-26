use bitcoin::{
    absolute::LockTime, transaction::Version, Address, Amount, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin::secp256k1::{Secp256k1, Message};
use bitcoin::sighash::{SighashCache, EcdsaSighashType};
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::CompressedPublicKey;
use bitcoin::hashes::Hash;
use bitcoin::consensus::encode::serialize_hex;
use bip39::Mnemonic;
use serde::Deserialize;
use crate::chain::Utxo;
use crate::keys;
use std::str::FromStr;

const FEE_SATS: u64 = 500;
const DUST_LIMIT_SATS: u64 = 294;

/// A UTXO tagged with WHERE it came from (which chain/index derived the
/// address it sits at). Needed because, with multiple addresses in use,
/// each input may require a different private key to sign correctly.
#[derive(Deserialize)]
pub struct SourcedUtxo {
    pub utxo: Utxo,
    pub chain: u32,
    pub index: u32,
}

/// Builds and signs a transaction that may spend UTXOs from several
/// different addresses within the same wallet (same seed, different
/// chain/index). Each input is signed with the specific private key
/// derived for that input's own address -- not a single shared key.
pub fn build_and_sign_transaction(
    mnemonic: &Mnemonic,
    network: Network,
    sourced_utxos: &[SourcedUtxo],
    destination: &Address,
    amount_sats: u64,
    change_address: &Address,
) -> Result<Transaction, String> {
    let secp = Secp256k1::new();

    let input_total: u64 = sourced_utxos.iter().map(|s| s.utxo.value).sum();
    if input_total < amount_sats + FEE_SATS {
        return Err(format!(
            "Insufficient funds: have {input_total} sats, need {} sats (amount + fee).",
            amount_sats + FEE_SATS
        ));
    }
    let change_sats = input_total - amount_sats - FEE_SATS;

    let inputs: Vec<TxIn> = sourced_utxos
        .iter()
        .map(|s| {
            let txid = Txid::from_str(&s.utxo.txid).map_err(|e| format!("Bad txid from API: {e}"));
            txid.map(|txid| TxIn {
                previous_output: OutPoint { txid, vout: s.utxo.vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: destination.script_pubkey(),
    }];

    if change_sats > DUST_LIMIT_SATS {
        outputs.push(TxOut {
            value: Amount::from_sat(change_sats),
            script_pubkey: change_address.script_pubkey(),
        });
    }

    let mut unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    let per_input_wallets: Vec<keys::DerivedWallet> = sourced_utxos
        .iter()
        .map(|s| keys::derive_wallet_at(mnemonic, network, s.chain, s.index))
        .collect::<Result<Vec<_>, String>>()?;

    let sighash_type = EcdsaSighashType::All;

    for i in 0..sourced_utxos.len() {
        let input_wallet = &per_input_wallets[i];

        let mut cache = SighashCache::new(&unsigned_tx);
        let sighash = cache
            .p2wpkh_signature_hash(
                i,
                &input_wallet.address.script_pubkey(),
                Amount::from_sat(sourced_utxos[i].utxo.value),
                sighash_type,
            )
            .map_err(|e| format!("Failed to compute sighash for input {i}: {e}"))?;

        let msg = Message::from_digest(sighash.to_byte_array());
        let private_key = input_wallet.xpriv.to_priv();
        let sig = secp.sign_ecdsa(&msg, &private_key.inner);

        let compressed_pubkey = CompressedPublicKey::from_private_key(&secp, &private_key)
            .map_err(|e| format!("Failed to derive public key for input {i}: {e}"))?;

        let ecdsa_sig = EcdsaSignature { signature: sig, sighash_type };

        let mut witness = Witness::new();
        witness.push(ecdsa_sig.serialize());
        witness.push(compressed_pubkey.to_bytes());

        unsigned_tx.input[i].witness = witness;
    }

    Ok(unsigned_tx)
}

pub fn describe_transaction(tx: &Transaction, amount_sats: u64, fee_sats: u64) -> String {
    let mut out = String::new();
    out.push_str(&format!("Txid (will be, once broadcast): {}\n", tx.compute_txid()));
    out.push_str(&format!("Inputs: {}\n", tx.input.len()));
    for (i, input) in tx.input.iter().enumerate() {
        out.push_str(&format!(
            "  [{i}] spending {}:{}\n",
            input.previous_output.txid, input.previous_output.vout
        ));
    }
    out.push_str(&format!("Outputs: {}\n", tx.output.len()));
    for (i, output) in tx.output.iter().enumerate() {
        out.push_str(&format!(
            "  [{i}] {} sats -> {}\n",
            output.value.to_sat(),
            output.script_pubkey
        ));
    }
    out.push_str(&format!("Amount sent (to destination): {amount_sats} sats\n"));
    out.push_str(&format!("Fee: {fee_sats} sats\n"));
    out.push_str(&format!("Raw tx hex:\n{}\n", serialize_hex(tx)));
    out
}