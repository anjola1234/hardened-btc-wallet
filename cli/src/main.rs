mod chain_net;

use wallet_core::{storage, keys, chain, tx, generate_mnemonic};
use bip39::Mnemonic;
use bitcoin::{Address, Network, Transaction};
use bitcoin::consensus::encode::deserialize_hex;
use std::env;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use zeroize::Zeroizing;

fn save_wallet_file(bytes: &[u8], path: &Path) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| format!("Failed to write wallet file: {e}"))
}

fn load_wallet_file(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("Failed to read wallet file: {e}"))
}

fn prompt_new_passphrase() -> Result<Zeroizing<String>, String> {
    let pass1 = Zeroizing::new(rpassword::prompt_password("Choose a wallet passphrase: ").map_err(|e| format!("Failed to read passphrase: {e}"))?);
    let pass2 = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ").map_err(|e| format!("Failed to read passphrase: {e}"))?);
    if *pass1 != *pass2 { return Err("Passphrases did not match.".to_string()); }
    if pass1.len() < 8 { return Err("Passphrase too short. Use at least 8 characters (longer is much better).".to_string()); }
    Ok(pass1)
}

fn prompt_existing_passphrase() -> Result<Zeroizing<String>, String> {
    Ok(Zeroizing::new(rpassword::prompt_password("Enter wallet passphrase: ").map_err(|e| format!("Failed to read passphrase: {e}"))?))
}

fn cmd_new(wallet_path: &Path, network: Network) {
    if wallet_path.exists() {
        eprintln!("FATAL: {} already exists. Refusing to overwrite an existing wallet.", wallet_path.display());
        std::process::exit(1);
    }
    let passphrase = match prompt_new_passphrase() { Ok(p) => p, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let mnemonic = match generate_mnemonic() { Ok(m) => m, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let mnemonic_string = mnemonic.to_string();
    let encrypted = match storage::encrypt_to_bytes(&mnemonic_string, &passphrase) { Ok(b) => b, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    if let Err(e) = save_wallet_file(&encrypted, wallet_path) { eprintln!("FATAL: {e}"); std::process::exit(1); }
    println!("New wallet created and encrypted at {}", wallet_path.display());
    match keys::derive_wallet(&mnemonic, network) {
        Ok(wallet) => {
            println!("Receiving address ({network}): {}", wallet.address);
            println!("(Derivation path: m/84'/0'/0'/0/0)");
        }
        Err(e) => { eprintln!("FATAL: key derivation failed: {e}"); std::process::exit(1); }
    }
}

fn cmd_load(wallet_path: &Path, network: Network) {
    if !wallet_path.exists() { eprintln!("FATAL: {} does not exist. Use 'new' to create a wallet first.", wallet_path.display()); std::process::exit(1); }
    let passphrase = match prompt_existing_passphrase() { Ok(p) => p, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let bytes = match load_wallet_file(wallet_path) { Ok(b) => b, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let decrypted = match storage::decrypt_from_bytes(&bytes, &passphrase) { Ok(m) => m, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let mnemonic = match Mnemonic::parse_in_normalized(bip39::Language::English, &decrypted) { Ok(m) => m, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    match keys::derive_wallet(&mnemonic, network) {
        Ok(wallet) => { println!("Wallet loaded successfully."); println!("Receiving address ({network}): {}", wallet.address); }
        Err(e) => { eprintln!("FATAL: key derivation failed: {e}"); std::process::exit(1); }
    }
}

fn cmd_balance(wallet_path: &Path, network: Network) {
    if !wallet_path.exists() { eprintln!("FATAL: {} does not exist. Use 'new' to create a wallet first.", wallet_path.display()); std::process::exit(1); }
    let passphrase = match prompt_existing_passphrase() { Ok(p) => p, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let bytes = match load_wallet_file(wallet_path) { Ok(b) => b, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let decrypted = match storage::decrypt_from_bytes(&bytes, &passphrase) { Ok(m) => m, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let mnemonic = match Mnemonic::parse_in_normalized(bip39::Language::English, &decrypted) { Ok(m) => m, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };

    println!("Scanning all wallet addresses for balance (this may take a moment)...");
    let sourced_utxos = match chain_net::gather_all_utxos(&mnemonic, network) {
        Ok(u) => u, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); }
    };
    let plain_utxos: Vec<chain::Utxo> = sourced_utxos.into_iter().map(|s| s.utxo).collect();
    let confirmed = chain::confirmed_balance_sats(&plain_utxos);
    println!("UTXOs found: {}", plain_utxos.len());
    println!("Confirmed balance (across all addresses): {confirmed} sats");
}

fn cmd_send(wallet_path: &Path, network: Network, destination_str: &str, amount_sats: u64) {
    use std::io::{self, Write};

    if !wallet_path.exists() { eprintln!("FATAL: {} does not exist. Use 'new' to create a wallet first.", wallet_path.display()); std::process::exit(1); }

    let destination = match Address::from_str(destination_str) {
        Ok(addr) => match addr.require_network(network) {
            Ok(addr) => addr,
            Err(e) => { eprintln!("FATAL: destination address is not valid for {network}: {e}"); std::process::exit(1); }
        },
        Err(e) => { eprintln!("FATAL: invalid destination address: {e}"); std::process::exit(1); }
    };

    let passphrase = match prompt_existing_passphrase() { Ok(p) => p, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let bytes = match load_wallet_file(wallet_path) { Ok(b) => b, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let decrypted = match storage::decrypt_from_bytes(&bytes, &passphrase) { Ok(m) => m, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let mnemonic = match Mnemonic::parse_in_normalized(bip39::Language::English, &decrypted) { Ok(m) => m, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };

    println!("Scanning all wallet addresses for spendable funds...");
    let sourced_utxos = match chain_net::gather_all_utxos(&mnemonic, network) {
        Ok(u) => u, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); }
    };
    let confirmed_sourced: Vec<tx::SourcedUtxo> = sourced_utxos.into_iter().filter(|s| s.utxo.status.confirmed).collect();
    if confirmed_sourced.is_empty() {
        eprintln!("FATAL: no confirmed UTXOs available to spend, across any address.");
        std::process::exit(1);
    }

    println!("Finding a fresh, unused change address...");
    let (change_index, change_address) = match chain_net::find_unused_address(&mnemonic, network, 1) {
        Ok(r) => r, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); }
    };

    println!();
    println!("=== TRANSACTION REVIEW ===");
    println!("Sending:      {amount_sats} sats");
    println!("Destination:  {destination}");
    println!("Spending from {} input(s) across this wallet's addresses:", confirmed_sourced.len());
    for s in &confirmed_sourced {
        println!("  - chain {} index {}: {} sats", s.chain, s.index, s.utxo.value);
    }
    println!("Change to:    {change_address} (chain 1, index {change_index}, fresh)");
    println!();
    println!("Please verify the destination address character-by-character.");
    print!("Type 'yes' to build and sign this transaction: ");
    io::stdout().flush().ok();
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation).ok();
    if confirmation.trim() != "yes" { println!("Aborted. No transaction was built."); return; }

    let signed_tx: Transaction = match tx::build_and_sign_transaction(
        &mnemonic, network, &confirmed_sourced, &destination, amount_sats, &change_address,
    ) {
        Ok(t) => t, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); }
    };

    println!();
    println!("=== SIGNED TRANSACTION (not yet broadcast) ===");
    println!("{}", tx::describe_transaction(&signed_tx, amount_sats, 500));
    println!("This is your LAST chance to review before this is sent to the network.");
    println!("Once broadcast, this transaction cannot be undone.");
    print!("Type 'BROADCAST' (all caps) to send this transaction now: ");
    io::stdout().flush().ok();
    let mut broadcast_confirmation = String::new();
    io::stdin().read_line(&mut broadcast_confirmation).ok();
    if broadcast_confirmation.trim() != "BROADCAST" { println!("Not broadcast. Transaction was signed but not sent -- nothing was changed on-chain."); return; }

    match chain_net::broadcast_transaction(&signed_tx) {
        Ok(txid) => {
            println!();
            println!("Broadcast successful. Txid: {txid}");
            println!("You can track it at: https://mempool.space/tx/{txid}");
        }
        Err(e) => { eprintln!("FATAL: broadcast failed: {e}"); std::process::exit(1); }
    }
}

fn cmd_reveal(wallet_path: &Path) {
    if !wallet_path.exists() { eprintln!("FATAL: {} does not exist. Use 'new' to create a wallet first.", wallet_path.display()); std::process::exit(1); }
    println!("=== REVEAL RECOVERY PHRASE ===");
    println!("WARNING: This will display your wallet's 24-word recovery phrase.");
    println!("Anyone who sees these words can steal all funds in this wallet.");
    println!("Make sure no one is watching your screen, and that you are not");
    println!("screen-sharing, recording, or being screenshotted right now.");
    println!();
    let passphrase = match prompt_existing_passphrase() { Ok(p) => p, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let bytes = match load_wallet_file(wallet_path) { Ok(b) => b, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    let decrypted = match storage::decrypt_from_bytes(&bytes, &passphrase) { Ok(m) => m, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    println!();
    println!("Your recovery phrase (write this down somewhere safe and offline):");
    println!();
    println!("{decrypted}");
    println!();
    println!("Never type these words into any website, or share them with anyone.");
}

fn cmd_decode(hex_str: &str) {
    let tx: Transaction = match deserialize_hex(hex_str) { Ok(t) => t, Err(e) => { eprintln!("FATAL: {e}"); std::process::exit(1); } };
    println!("=== DECODED TRANSACTION (independent parse) ===");
    println!("Txid: {}", tx.compute_txid());
    println!("Version: {}", tx.version);
    println!("Inputs: {}", tx.input.len());
    for (i, input) in tx.input.iter().enumerate() {
        println!("  [{i}] spending {}:{}", input.previous_output.txid, input.previous_output.vout);
        println!("       witness items: {}", input.witness.len());
    }
    println!("Outputs: {}", tx.output.len());
    for (i, output) in tx.output.iter().enumerate() {
        let addr = Address::from_script(&output.script_pubkey, Network::Bitcoin).map(|a| a.to_string()).unwrap_or_else(|_| "(could not decode address)".to_string());
        println!("  [{i}] {} sats -> {}", output.value.to_sat(), addr);
    }
    let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    println!("Total output value: {total_out} sats");
}

fn main() {
    let wallet_path = Path::new("wallet_mainnet.dat");
    let network = Network::Bitcoin;

    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(String::as_str);

    match command {
        Some("new") => cmd_new(wallet_path, network),
        Some("load") => cmd_load(wallet_path, network),
        Some("balance") => cmd_balance(wallet_path, network),
        Some("send") => {
            let destination = args.get(2);
            let amount = args.get(3).and_then(|s| s.parse::<u64>().ok());
            match (destination, amount) {
                (Some(dest), Some(amt)) => cmd_send(wallet_path, network, dest, amt),
                _ => { eprintln!("Usage: {} send <destination_address> <amount_sats>", args.get(0).map(String::as_str).unwrap_or("hardened-btc-wallet")); std::process::exit(1); }
            }
        }
        Some("reveal") => cmd_reveal(wallet_path),
        Some("decode") => match args.get(2) {
            Some(hex_str) => cmd_decode(hex_str),
            None => { eprintln!("Usage: {} decode <raw_tx_hex>", args.get(0).map(String::as_str).unwrap_or("hardened-btc-wallet")); std::process::exit(1); }
        },
        _ => { eprintln!("Usage: {} <new|load|balance|send|reveal|decode>", args.get(0).map(String::as_str).unwrap_or("hardened-btc-wallet")); std::process::exit(1); }
    }
}