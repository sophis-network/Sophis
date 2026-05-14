/// dilithium-wallet — CLI PQC Wallet para Devnet/Testnet Sophis
use std::path::PathBuf;
use std::time::Duration;

use clap::{Arg, Command, value_parser};
use faster_hex::hex_encode;
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, ml_dsa_44};
use serde::{Deserialize, Serialize};
use sophis_addresses::{Address, Prefix};
use sophis_bip39::{Language, Mnemonic, WordCount};
use sophis_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use sophis_consensus_core::{
    config::params::DEVNET_PARAMS,
    constants::{SCRIPT_VERSION_CARRIER, SOMPI_PER_SOPHIS, TX_VERSION},
    da::{CarrierDomain, encode_bundle},
    hashing::sighash_type::SIG_HASH_ALL,
    sign::sign_input_dilithium,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        MutableTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
        UtxoEntry,
    },
};
use sophis_core::sophisd_env::version;
use sophis_grpc_client::GrpcClient;
use sophis_notify::subscription::context::SubscriptionContext;
use sophis_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};
use sophis_txscript::standard::{
    dilithium_address, dilithium_redeem_script, pay_to_address_script, pay_to_script_hash_signature_script,
};
use sophis_wallet_pskt::bundle::Bundle;
use sophis_wallet_pskt::crypto::{DILITHIUM44_SIG_SIZE, DilithiumPubKey, Signature as PsbsSignature};
use sophis_wallet_pskt::prelude::{Creator, Finalizer, InputBuilder, OutputBuilder, PSKT, SignInputOk, Signer};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const VK_SIZE: usize = 1312;
const SK_SIZE: usize = 2560;
const COINBASE_MATURITY_DEVNET: u64 = DEVNET_PARAMS.blockrate.coinbase_maturity;
const RPC_TIMEOUT: Duration = Duration::from_secs(15);

// ─── Fee calculation (integer arithmetic) ────────────────────────────────────

const STORAGE_MASS_PARAMETER: u64 = SOMPI_PER_SOPHIS * 10_000;
const MASS_PER_TX_BYTE: u64 = 1;
const MASS_PER_SCRIPT_PUB_KEY_BYTE: u64 = 10;
const MASS_PER_SIG_OP: u64 = 1000;
const P2SH_SCRIPT_PUB_KEY_SIZE: u64 = 36;
const DILITHIUM_SIG_SCRIPT_SIZE: u64 = 3744;
const FEE_RATE_PER_GRAM: u64 = 1;
const MINIMUM_FEE: u64 = 1_000;

fn calc_storage_mass_integer(inputs: &[(TransactionOutpoint, UtxoEntry)], send: u64, change: u64) -> u64 {
    let out_send = STORAGE_MASS_PARAMETER.div_ceil(send);
    let out_change = if change > 0 { STORAGE_MASS_PARAMETER.div_ceil(change) } else { 0 };
    let sum_out = out_send + out_change;
    let sum_in: u64 = inputs.iter().map(|(_, e)| STORAGE_MASS_PARAMETER / e.amount).sum();
    sum_out.saturating_sub(sum_in)
}

fn estimate_tx_mass(selected: &[(TransactionOutpoint, UtxoEntry)], send_amount: u64, fee: u64) -> (u64, u64) {
    let n_in = selected.len() as u64;
    let total_in: u64 = selected.iter().map(|(_, e)| e.amount).sum();
    let change = total_in.saturating_sub(send_amount + fee);
    let n_out = if change > 0 { 2u64 } else { 1u64 };
    let tx_size = 20 + n_in * (8 + 8 + 4 + 2 + DILITHIUM_SIG_SCRIPT_SIZE) + n_out * (8 + 2 + 34);
    let compute_mass =
        tx_size * MASS_PER_TX_BYTE + n_out * P2SH_SCRIPT_PUB_KEY_SIZE * MASS_PER_SCRIPT_PUB_KEY_BYTE + n_in * MASS_PER_SIG_OP;
    let storage_mass = calc_storage_mass_integer(selected, send_amount, change);
    (compute_mass, storage_mass)
}

fn calc_fee(selected: &[(TransactionOutpoint, UtxoEntry)], send_amount: u64) -> (u64, u64, u64) {
    let mut fee = MINIMUM_FEE;
    let mut compute_mass = 0u64;
    let mut storage_mass = 0u64;
    for _ in 0..8 {
        let (cm, sm) = estimate_tx_mass(selected, send_amount, fee);
        let new_fee = (cm.max(sm) * FEE_RATE_PER_GRAM * 105 / 100).max(MINIMUM_FEE);
        compute_mass = cm;
        storage_mass = sm;
        if new_fee == fee {
            break;
        }
        if new_fee > 0 && new_fee.abs_diff(fee) * 1000 < new_fee {
            fee = new_fee;
            break;
        }
        fee = new_fee;
    }
    (fee, compute_mass, storage_mass)
}

// ─── Key derivation ──────────────────────────────────────────────────────────

/// Derives a deterministic Dilithium-2 keypair from a BIP39 mnemonic phrase.
/// Derivation: BIP39-PBKDF2(mnemonic, "") → 64-byte seed → first 32 bytes as ML-DSA-44 randomness.
fn derive_dilithium_from_mnemonic(phrase: &str) -> Result<([u8; VK_SIZE], [u8; SK_SIZE])> {
    let mnemonic = Mnemonic::new(phrase.trim(), Language::English).map_err(|e| format!("Mnemônico inválido: {}", e))?;
    let seed = mnemonic.to_seed(""); // BIP39 PBKDF2, sem passphrase
    let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    randomness.copy_from_slice(&seed.as_bytes()[..KEY_GENERATION_RANDOMNESS_SIZE]);
    let keypair = ml_dsa_44::generate_key_pair(randomness);
    randomness.iter_mut().for_each(|b| *b = 0); // zeroize
    let vk: [u8; VK_SIZE] = *keypair.verification_key.as_ref();
    let sk: [u8; SK_SIZE] = *keypair.signing_key.as_ref();
    Ok((vk, sk))
}

fn build_hex(bytes: &[u8]) -> String {
    let mut buf = vec![0u8; bytes.len() * 2];
    hex_encode(bytes, &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

fn build_wallet_from_keys(
    vk: &[u8; VK_SIZE],
    sk: &[u8; SK_SIZE],
    mnemonic_phrase: &str,
    network: &str,
    prefix: Prefix,
) -> Result<Wallet> {
    let address = dilithium_address(vk, prefix)?;
    Ok(Wallet {
        version: 2,
        network: network.to_string(),
        address: String::from(&address),
        verification_key_hex: build_hex(vk),
        signing_key_hex: build_hex(sk),
        mnemonic: Some(mnemonic_phrase.to_string()),
    })
}

// ─── Wallet ──────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Wallet {
    /// Format version: 1 = chave aleatória sem mnemônico, 2 = derivação BIP39
    #[serde(default = "Wallet::default_version")]
    version: u32,
    network: String,
    address: String,
    verification_key_hex: String,
    signing_key_hex: String,
    /// BIP39 24-word recovery phrase (presente apenas na versão 2+)
    #[serde(skip_serializing_if = "Option::is_none")]
    mnemonic: Option<String>,
}

impl Wallet {
    fn default_version() -> u32 {
        1
    }

    fn load(path: &PathBuf) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&s)?)
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    fn address(&self) -> Result<Address> {
        Address::try_from(self.address.clone()).map_err(|e| format!("{e}").into())
    }

    fn verification_key(&self) -> Result<[u8; VK_SIZE]> {
        hex::decode(&self.verification_key_hex)?.try_into().map_err(|_| "VK size mismatch".into())
    }

    fn signing_key(&self) -> Result<[u8; SK_SIZE]> {
        hex::decode(&self.signing_key_hex)?.try_into().map_err(|_| "SK size mismatch".into())
    }
}

// ─── RPC ─────────────────────────────────────────────────────────────────────

async fn connect(rpc_server: &str) -> GrpcClient {
    let ctx = SubscriptionContext::new();
    GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{}", rpc_server),
        Some(ctx),
        true,
        None,
        false,
        Some(15_000),
        Default::default(),
    )
    .await
    .expect("Falha ao conectar ao gRPC")
}

async fn spendable_utxos(rpc: &GrpcClient, address: &Address) -> Vec<(TransactionOutpoint, UtxoEntry)> {
    let dag_info = tokio::time::timeout(RPC_TIMEOUT, rpc.get_block_dag_info())
        .await
        .unwrap_or_else(|_| {
            log::warn!("RPC get_block_dag_info timeout");
            Err("timeout".into())
        })
        .unwrap();
    let daa = dag_info.virtual_daa_score;
    let entries = tokio::time::timeout(RPC_TIMEOUT, rpc.get_utxos_by_addresses(vec![address.clone()]))
        .await
        .unwrap_or_else(|_| {
            log::warn!("RPC get_utxos_by_addresses timeout");
            Err("timeout".into())
        })
        .unwrap_or_default();
    let mut utxos: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            let needed = if e.utxo_entry.is_coinbase { COINBASE_MATURITY_DEVNET } else { 10 };
            e.utxo_entry.block_daa_score + needed < daa
        })
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .collect();
    utxos.sort_by(|a, b| b.1.amount.cmp(&a.1.amount));
    utxos
}

// ─── TX ──────────────────────────────────────────────────────────────────────

fn build_and_sign_dilithium_tx(
    utxos: &[(TransactionOutpoint, UtxoEntry)],
    send_amount: u64,
    fee: u64,
    to_address: &Address,
    change_address: &Address,
    vk_bytes: &[u8; VK_SIZE],
    sk_bytes: &[u8; SK_SIZE],
    tamper: bool,
) -> Result<Transaction> {
    let total: u64 = utxos.iter().map(|(_, e)| e.amount).sum();
    let change = total.saturating_sub(send_amount + fee);
    let mut outputs = vec![TransactionOutput { value: send_amount, script_public_key: pay_to_address_script(to_address) }];
    if change > 0 {
        outputs.push(TransactionOutput { value: change, script_public_key: pay_to_address_script(change_address) });
    }
    let inputs: Vec<TransactionInput> = utxos
        .iter()
        .map(|(op, _)| TransactionInput { previous_outpoint: *op, signature_script: vec![], sequence: 0, sig_op_count: 1 })
        .collect();
    let unsigned_tx = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let utxo_entries: Vec<UtxoEntry> = utxos.iter().map(|(_, e)| e.clone()).collect();
    let mut mutable_tx = MutableTransaction::with_entries(unsigned_tx, utxo_entries);
    let redeem_script = dilithium_redeem_script(vk_bytes)?;
    for i in 0..mutable_tx.tx.inputs.len() {
        let sig_script = sign_input_dilithium(&mutable_tx.as_verifiable(), i, sk_bytes, SIG_HASH_ALL)?;
        let mut final_sig = sig_script;
        if tamper && final_sig.len() > 10 {
            final_sig[5] ^= 0xff;
        }
        mutable_tx.tx.inputs[i].signature_script = pay_to_script_hash_signature_script(redeem_script.clone(), final_sig)?;
    }
    Ok(mutable_tx.tx)
}

// ─── Comandos ────────────────────────────────────────────────────────────────

fn prefix_for(network: &str) -> Prefix {
    match network {
        "testnet" => Prefix::Testnet,
        "mainnet" => Prefix::Mainnet,
        _ => Prefix::Devnet,
    }
}

/// Audit/F-13 (P1 mainnet blocker, fixed 2026-05-14):
///
/// The CLI wallet writes `signing_key_hex` + mnemonic to a plaintext JSON
/// file. That is **safe for devnet/testnet** (throwaway value) but
/// catastrophic for mainnet, where the canonical workflow is the
/// air-gapped procedure documented in
/// `mainnet-mining/WALLET-PROCEDURE.md` (Mnemonic on paper, JSON destroyed
/// after install). The original `cmd_keygen` happily accepted
/// `--network mainnet` and wrote the JSON anyway, with an on-screen
/// warning that only mentioned the mnemonic — not the JSON itself.
///
/// This helper rejects mainnet keygen/restore with a clear message
/// pointing the operator at the canonical procedure. It is called from
/// `cmd_keygen` and `cmd_restore` because both produce the same plaintext
/// JSON via `wallet.save(...)`.
fn reject_mainnet_plaintext(network: &str, op: &str) {
    if network == "mainnet" {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
        eprintln!("║  ERRO — `dilithium-wallet {op}` recusa --network mainnet            ║");
        eprintln!("║                                                                      ║");
        eprintln!("║  Este CLI escreve um JSON em texto-claro contendo:                   ║");
        eprintln!("║    - signing_key_hex (chave privada de 2560 bytes)                   ║");
        eprintln!("║    - mnemonic (24 palavras BIP-39)                                   ║");
        eprintln!("║                                                                      ║");
        eprintln!("║  Para mainnet, o procedimento canonico e air-gapped:                 ║");
        eprintln!("║    mainnet-mining/WALLET-PROCEDURE.md (9 passos, papel + offline)    ║");
        eprintln!("║                                                                      ║");
        eprintln!("║  Para uso testnet/devnet (throwaway), use --network testnet ou       ║");
        eprintln!("║  --network devnet.                                                   ║");
        eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
        eprintln!();
        std::process::exit(2);
    }
}

fn cmd_keygen(wallet_path: &PathBuf, network: &str) {
    reject_mainnet_plaintext(network, "keygen");
    let prefix = prefix_for(network);

    let mnemonic = Mnemonic::random(WordCount::Words24, Language::English).expect("Falha ao gerar mnemônico BIP39");
    let phrase = mnemonic.phrase_string();

    let (vk, sk) = derive_dilithium_from_mnemonic(&phrase).expect("Falha ao derivar chaves do mnemônico");

    let wallet = build_wallet_from_keys(&vk, &sk, &phrase, network, prefix).expect("Falha ao construir wallet");
    wallet.save(wallet_path).expect("Falha ao salvar wallet");

    println!("Keypair Dilithium-2 (ML-DSA-44) gerado com sucesso.");
    println!();
    println!("  Rede      : {}", network);
    println!("  Endereco  : {}", wallet.address);
    println!("  VK size   : {} bytes", VK_SIZE);
    println!("  SK size   : {} bytes", SK_SIZE);
    println!("  Wallet    : {}", wallet_path.display());
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║   GUARDE ESTAS 24 PALAVRAS COM SEGURANCA — papel, offline           ║");
    println!("║   Sao a unica forma de recuperar a wallet.                          ║");
    println!("║                                                                      ║");
    println!("║   ATENCAO: o arquivo JSON em '{}' tambem contem", wallet_path.display());
    println!("║   a sua signing_key em texto-claro. NAO sincronizar com cloud,       ║");
    println!("║   NAO fazer git commit, NAO deixar em maquinas conectadas para uso  ║");
    println!("║   alem de devnet/testnet (valor descartavel).                       ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  {}", phrase);
    println!();
    println!("Proximo passo — minere para este endereco:");
    println!("  sophis-miner.exe --mining-address {}", wallet.address);
}

fn cmd_restore(wallet_path: &PathBuf, phrase: &str, network: &str) {
    reject_mainnet_plaintext(network, "restore");
    let prefix = prefix_for(network);

    let (vk, sk) = match derive_dilithium_from_mnemonic(phrase) {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("Erro: {}", e);
            std::process::exit(1);
        }
    };

    let wallet = build_wallet_from_keys(&vk, &sk, phrase.trim(), network, prefix).expect("Falha ao construir wallet");
    wallet.save(wallet_path).expect("Falha ao salvar wallet");

    println!("Wallet restaurada com sucesso.");
    println!("  Rede      : {}", network);
    println!("  Endereco  : {}", wallet.address);
    println!("  Wallet    : {}", wallet_path.display());
}

fn cmd_mnemonic(wallet_path: &PathBuf) {
    let wallet = Wallet::load(wallet_path).expect("Wallet não encontrada");
    match wallet.mnemonic {
        Some(ref phrase) => {
            println!("╔══════════════════════════════════════════════════════════════╗");
            println!("║                  FRASE DE RECUPERAÇÃO (24 palavras)         ║");
            println!("╚══════════════════════════════════════════════════════════════╝");
            println!();
            println!("  {}", phrase);
            println!();
            println!("  Rede     : {}", wallet.network);
            println!("  Endereco : {}", wallet.address);
        }
        None => {
            eprintln!("Esta wallet (v1) foi gerada sem mnemônico BIP39.");
            eprintln!("Use 'keygen' para criar uma nova wallet com frase de recuperação.");
            std::process::exit(1);
        }
    }
}

async fn cmd_info(wallet_path: &PathBuf, rpc_server: &str) {
    let wallet = Wallet::load(wallet_path).expect("Wallet não encontrada");
    let address = wallet.address().unwrap();
    let rpc = connect(rpc_server).await;

    let dag_info = tokio::time::timeout(RPC_TIMEOUT, rpc.get_block_dag_info()).await.expect("Timeout").unwrap();
    let all_utxos =
        tokio::time::timeout(RPC_TIMEOUT, rpc.get_utxos_by_addresses(vec![address.clone()])).await.expect("Timeout").unwrap();
    let spendable = spendable_utxos(&rpc, &address).await;

    let total: u64 = all_utxos.iter().map(|e| e.utxo_entry.amount).sum();
    let spendable_total: u64 = spendable.iter().map(|(_, e)| e.amount).sum();

    println!("=== Dilithium Wallet Info ===");
    println!("  Versao    : v{}", wallet.version);
    println!("  Rede      : {}", wallet.network);
    println!("  Endereco  : {}", wallet.address);
    println!("  DAA Score : {}", dag_info.virtual_daa_score);
    println!("  UTXOs     : {} total ({} spendable)", all_utxos.len(), spendable.len());
    println!("  Saldo     : {:.8} SPHS total", total as f64 / SOMPI_PER_SOPHIS as f64);
    println!("  Spendable : {:.8} SPHS", spendable_total as f64 / SOMPI_PER_SOPHIS as f64);

    if spendable.is_empty() {
        println!();
        println!("  Nenhum UTXO maduro. {} UTXO(s) aguardando maturidade ({} blocos).", all_utxos.len(), COINBASE_MATURITY_DEVNET);
    }
}

async fn cmd_send(wallet_path: &PathBuf, rpc_server: &str, to_addr_str: &str, amount_sompi: u64, tamper: bool) {
    let wallet = Wallet::load(wallet_path).expect("Wallet não encontrada");
    let address = wallet.address().unwrap();
    let vk_bytes = wallet.verification_key().unwrap();
    let sk_bytes = wallet.signing_key().unwrap();
    let to_address = Address::try_from(to_addr_str.to_string()).expect("Endereço destino inválido");

    let rpc = connect(rpc_server).await;
    let utxos = spendable_utxos(&rpc, &address).await;

    if utxos.is_empty() {
        println!("Nenhum UTXO maduro disponível.");
        return;
    }

    let (est_fee, _, _) = calc_fee(&utxos[..1], amount_sompi);
    let needed = amount_sompi + est_fee;
    let total: u64 = utxos.iter().map(|(_, e)| e.amount).sum();
    if total < needed {
        println!("Saldo insuficiente: {} sompi disponível, {} necessário.", total, needed);
        return;
    }

    let mut selected = vec![];
    let mut acc = 0u64;
    for (op, entry) in &utxos {
        selected.push((*op, entry.clone()));
        acc += entry.amount;
        if acc >= needed {
            break;
        }
    }

    let (fee, compute_mass, storage_mass) = calc_fee(&selected, amount_sompi);
    let total_mass = compute_mass.max(storage_mass);

    println!("Construindo TX Dilithium{}...", if tamper { " (ADULTERADA)" } else { "" });
    println!("  Inputs    : {} UTXOs ({} sompi)", selected.len(), acc);
    println!("  Destino   : {}", to_addr_str);
    println!("  Valor     : {} sompi  ({:.8} SPHS)", amount_sompi, amount_sompi as f64 / SOMPI_PER_SOPHIS as f64);
    println!("  Fee       : {} sompi  (mass={}: compute={}, storage={})", fee, total_mass, compute_mass, storage_mass);
    println!("  Sig size  : ~2420 bytes (Dilithium-2 / ML-DSA-44)");

    let tx = build_and_sign_dilithium_tx(&selected, amount_sompi, fee, &to_address, &address, &vk_bytes, &sk_bytes, tamper)
        .expect("Falha ao construir TX");

    let tx_id = {
        let mut t = tx.clone();
        t.finalize();
        t.id()
    };

    let submit_result = tokio::time::timeout(RPC_TIMEOUT, rpc.submit_transaction((&tx).into(), false)).await;
    match submit_result {
        Err(_) => println!("\nTX rejeitada: timeout ao submeter ({}s)", RPC_TIMEOUT.as_secs()),
        Ok(Ok(_)) => {
            println!();
            if tamper {
                println!("ATENCAO: TX adulterada foi ACEITA — isto é um erro!");
            } else {
                println!("TX submetida com sucesso!");
            }
            println!("  TX ID : {}", tx_id);
        }
        Ok(Err(e)) => {
            println!();
            if tamper {
                println!("TX adulterada REJEITADA conforme esperado!");
                println!("  Erro : {}", e);
            } else {
                println!("TX rejeitada: {}", e);
            }
        }
    }
}

// ─── DA publish + queries (Phase 6) ──────────────────────────────────────────

/// Parse the user-friendly domain name into the `CarrierDomain` enum.
/// Returns `None` for the literal string `"none"` (= no domain flag set).
fn parse_domain(s: &str) -> Result<Option<CarrierDomain>> {
    match s.to_ascii_lowercase().as_str() {
        "none" | "" => Ok(None),
        "rollup" => Ok(Some(CarrierDomain::Rollup)),
        "oracle" => Ok(Some(CarrierDomain::Oracle)),
        "user" => Ok(Some(CarrierDomain::User)),
        other => Err(format!("domain inválido '{}': use Rollup|Oracle|User|None", other).into()),
    }
}

/// Build a transaction whose outputs are V5 carrier outputs (value=0)
/// plus a change-back output. Inputs are spent from the wallet's UTXO
/// set, using just enough to cover the flat fee.
///
/// Fee strategy: a flat fee bound to compensate for the carrier outputs'
/// non-trivial size (each fragment is ~970 bytes script). For a typical
/// 1–4-fragment publish this is well under 1 SPHS even at 50 sompi/byte
/// which is generous.
fn build_signed_da_tx(
    utxos: &[(TransactionOutpoint, UtxoEntry)],
    carrier_scripts: &[Vec<u8>],
    fee: u64,
    change_address: &Address,
    vk_bytes: &[u8; VK_SIZE],
    sk_bytes: &[u8; SK_SIZE],
) -> Result<Transaction> {
    let total_in: u64 = utxos.iter().map(|(_, e)| e.amount).sum();
    if total_in < fee {
        return Err(format!("UTXOs insuficientes para cobrir fee ({} < {})", total_in, fee).into());
    }
    let change = total_in - fee;

    let mut outputs: Vec<TransactionOutput> = Vec::with_capacity(carrier_scripts.len() + 1);
    for script in carrier_scripts {
        outputs.push(TransactionOutput {
            value: 0,
            script_public_key: ScriptPublicKey::new(SCRIPT_VERSION_CARRIER, ScriptVec::from_slice(script)),
        });
    }
    if change > 0 {
        outputs.push(TransactionOutput { value: change, script_public_key: pay_to_address_script(change_address) });
    }

    let inputs: Vec<TransactionInput> = utxos
        .iter()
        .map(|(op, _)| TransactionInput { previous_outpoint: *op, signature_script: vec![], sequence: 0, sig_op_count: 1 })
        .collect();
    let unsigned_tx = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let utxo_entries: Vec<UtxoEntry> = utxos.iter().map(|(_, e)| e.clone()).collect();
    let mut mutable_tx = MutableTransaction::with_entries(unsigned_tx, utxo_entries);
    let redeem_script = dilithium_redeem_script(vk_bytes)?;
    for i in 0..mutable_tx.tx.inputs.len() {
        let sig_script = sign_input_dilithium(&mutable_tx.as_verifiable(), i, sk_bytes, SIG_HASH_ALL)?;
        mutable_tx.tx.inputs[i].signature_script = pay_to_script_hash_signature_script(redeem_script.clone(), sig_script)?;
    }
    Ok(mutable_tx.tx)
}

async fn cmd_da_publish(wallet_path: &PathBuf, rpc_server: &str, payload_file: &str, domain_str: &str) {
    let wallet = Wallet::load(wallet_path).expect("Wallet não encontrada");
    let address = wallet.address().expect("endereço inválido na wallet");
    let vk = wallet.verification_key().expect("VK inválida na wallet");
    let sk = wallet.signing_key().expect("SK inválida na wallet");

    let domain = match parse_domain(domain_str) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Erro: {}", e);
            std::process::exit(2);
        }
    };

    let payload = std::fs::read(payload_file).unwrap_or_else(|e| {
        eprintln!("Erro lendo {}: {}", payload_file, e);
        std::process::exit(2);
    });
    let scripts = match encode_bundle(&payload, domain) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Erro empacotando bundle: {:?}", e);
            std::process::exit(2);
        }
    };
    println!("Payload: {} bytes -> {} fragment(s)", payload.len(), scripts.len());
    if let Some(d) = domain {
        println!("Domain : {:?}", d);
    } else {
        println!("Domain : (none)");
    }

    let rpc = connect(rpc_server).await;
    let utxos = spendable_utxos(&rpc, &address).await;
    if utxos.is_empty() {
        eprintln!("Nenhum UTXO maduro disponível em {}", address);
        std::process::exit(1);
    }

    // Generous flat fee that covers ~10 fragments worth of carrier
    // outputs comfortably. A future sub-fase can tighten this with the
    // existing mass-based calc_fee once carrier-aware mass rules are
    // wired (today carrier outputs are exempt from storage mass).
    let fee: u64 = 100_000 * (1 + scripts.len() as u64);
    let tx = match build_signed_da_tx(&utxos, &scripts, fee, &address, &vk, &sk) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Erro construindo TX: {}", e);
            std::process::exit(1);
        }
    };

    // Compute payload_id and bundle_id locally so the user can pipe to
    // `dilithium-wallet da inspect` without parsing the relayer's logs.
    use sophis_consensus_core::da::{bundle_id_of, payload_id};
    let bundle_id = bundle_id_of(&payload);
    println!("bundle_id : {}", fmt_hex_48(&bundle_id));
    for (i, script) in scripts.iter().enumerate() {
        let pid = payload_id(script);
        println!("  fragment {:02}: payload_id = {}", i, fmt_hex_48(&pid));
    }

    println!("\nSubmetendo TX (fee={} sompi)...", fee);
    match tokio::time::timeout(RPC_TIMEOUT, rpc.submit_transaction((&tx).into(), false)).await {
        Ok(Ok(tx_id)) => {
            println!("TX submetida — tx_id: {}", tx_id);
            println!("Aguarde a inclusão num bloco e use 'da inspect' para verificar.");
        }
        Ok(Err(e)) => {
            eprintln!("Submit rejeitado: {}", e);
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("RPC timeout em submit_transaction");
            std::process::exit(1);
        }
    }
}

// ─── DA queries (Phase 6) ────────────────────────────────────────────────────

/// Decode a hex string into a 48-byte payload/bundle id. Accepts the
/// canonical `0x`-prefixed form as well as bare hex.
fn parse_id_48(s: &str) -> Result<[u8; 48]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 96 {
        return Err(format!("ID hex deve ter 96 chars (48 bytes); recebido {}", s.len()).into());
    }
    let mut out = [0u8; 48];
    let bytes = s.as_bytes();
    for i in 0..48 {
        let hi = match bytes[i * 2] {
            b'0'..=b'9' => bytes[i * 2] - b'0',
            b'a'..=b'f' => bytes[i * 2] - b'a' + 10,
            b'A'..=b'F' => bytes[i * 2] - b'A' + 10,
            _ => return Err("ID contém caractere não-hex".into()),
        };
        let lo = match bytes[i * 2 + 1] {
            b'0'..=b'9' => bytes[i * 2 + 1] - b'0',
            b'a'..=b'f' => bytes[i * 2 + 1] - b'a' + 10,
            b'A'..=b'F' => bytes[i * 2 + 1] - b'A' + 10,
            _ => return Err("ID contém caractere não-hex".into()),
        };
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn fmt_hex_48(bytes: &[u8]) -> String {
    let mut buf = vec![0u8; bytes.len() * 2];
    hex_encode(bytes, &mut buf).expect("hex encode");
    String::from_utf8(buf).expect("ascii hex")
}

fn fmt_domain_byte(b: u8) -> &'static str {
    match b {
        // Mirror chips/da: 0=None, 1=Rollup, 2=Oracle, 3=User
        // (matching CARRIER_FLAG_DOMAIN_* constants)
        0 => "(none)",
        1 => "Rollup",
        2 => "Oracle",
        3 => "User",
        _ => "(unknown)",
    }
}

async fn cmd_da_inspect(rpc_server: &str, payload_id_hex: &str) {
    let payload_id = match parse_id_48(payload_id_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Erro: {}", e);
            std::process::exit(2);
        }
    };
    let rpc = connect(rpc_server).await;
    let entry = match tokio::time::timeout(RPC_TIMEOUT, rpc.get_da_payload(payload_id.to_vec())).await {
        Ok(Ok(Some(p))) => p,
        Ok(Ok(None)) => {
            println!("payload_id {} não encontrado no DA store.", payload_id_hex);
            std::process::exit(1);
        }
        Ok(Err(e)) => {
            eprintln!("RPC error: {}", e);
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("RPC timeout em get_da_payload");
            std::process::exit(1);
        }
    };
    println!("DA payload {}", fmt_hex_48(&entry.payload_id));
    println!("  bundle_id           : {}", fmt_hex_48(&entry.bundle_id));
    println!("  fragment            : {}/{}", entry.fragment_index + 1, entry.fragment_count);
    println!("  domain              : {} (byte {})", fmt_domain_byte(entry.domain_byte), entry.domain_byte);
    println!("  accepting_block     : {}", entry.accepting_block_hash);
    println!("  blue_score          : {}", entry.blue_score);
    println!("  script bytes        : {} bytes", entry.script.len());
    // Print first 64 hex bytes of script for sanity
    let preview_n = entry.script.len().min(64);
    if preview_n > 0 {
        let mut buf = vec![0u8; preview_n * 2];
        hex_encode(&entry.script[..preview_n], &mut buf).expect("hex");
        let preview = String::from_utf8(buf).expect("ascii");
        let suffix = if entry.script.len() > preview_n { "..." } else { "" };
        println!("  script preview      : {}{}", preview, suffix);
    }
}

async fn cmd_da_bundle(rpc_server: &str, bundle_id_hex: &str) {
    let bundle_id = match parse_id_48(bundle_id_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Erro: {}", e);
            std::process::exit(2);
        }
    };
    let rpc = connect(rpc_server).await;
    let bundle = match tokio::time::timeout(RPC_TIMEOUT, rpc.get_da_bundle(bundle_id.to_vec())).await {
        Ok(Ok(Some(b))) => b,
        Ok(Ok(None)) => {
            println!("bundle_id {} não encontrado no DA store.", bundle_id_hex);
            std::process::exit(1);
        }
        Ok(Err(e)) => {
            eprintln!("RPC error: {}", e);
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("RPC timeout em get_da_bundle");
            std::process::exit(1);
        }
    };
    println!("DA bundle {}", fmt_hex_48(&bundle.bundle_id));
    println!("  fragment_count : {}", bundle.fragment_count);
    println!("  fragments seen : {}", bundle.payload_ids.len());
    for (i, pid) in bundle.payload_ids.iter().enumerate() {
        println!("    [{:02}] {}", i, fmt_hex_48(pid));
    }
    match &bundle.data {
        Some(data) => {
            println!("  reassembled    : {} bytes", data.len());
            let preview_n = data.len().min(64);
            if preview_n > 0 {
                let mut buf = vec![0u8; preview_n * 2];
                hex_encode(&data[..preview_n], &mut buf).expect("hex");
                let preview = String::from_utf8(buf).expect("ascii");
                let suffix = if data.len() > preview_n { "..." } else { "" };
                println!("  data preview   : {}{}", preview, suffix);
            }
        }
        None => println!("  reassembled    : (incomplete — fragments missing)"),
    }
}

// ─── PSBS — Partially Signed Sophis Transactions (K1.4) ──────────────────────
//
// Cold-storage workflow:
//   1. (online machine)  pskt create  — build PSBS w/ UTXOs+outputs, NO sigs
//   2. (offline machine) pskt sign    — load wallet keys, sign each input
//   3. (online machine)  pskt extract — finalize + serialize tx for broadcast
//
// Combine is a stub: trivial in single-sig (1 bundle == output bundle).
// Real multisig path requires J1 (Account Abstraction) — see wallet/aa-spec/.

/// Build an unsigned PSBS bundle and write it to `output_path`.
async fn cmd_pskt_create(wallet_path: &PathBuf, rpc_server: &str, to_addr_str: &str, amount_sompi: u64, output_path: &PathBuf) {
    let wallet = Wallet::load(wallet_path).expect("Wallet não encontrada");
    let address = wallet.address().unwrap();
    let vk_bytes = wallet.verification_key().unwrap();
    let to_address = Address::try_from(to_addr_str.to_string()).expect("Endereço destino inválido");
    let redeem_script = dilithium_redeem_script(&vk_bytes).expect("redeem script");

    let rpc = connect(rpc_server).await;
    let utxos = spendable_utxos(&rpc, &address).await;
    if utxos.is_empty() {
        println!("Nenhum UTXO maduro disponível.");
        return;
    }

    let (est_fee, _, _) = calc_fee(&utxos[..1], amount_sompi);
    let needed = amount_sompi + est_fee;
    let total: u64 = utxos.iter().map(|(_, e)| e.amount).sum();
    if total < needed {
        println!("Saldo insuficiente: {} sompi disponível, {} necessário.", total, needed);
        return;
    }

    let mut selected = vec![];
    let mut acc = 0u64;
    for (op, entry) in &utxos {
        selected.push((*op, entry.clone()));
        acc += entry.amount;
        if acc >= needed {
            break;
        }
    }
    let (fee, ..) = calc_fee(&selected, amount_sompi);
    let change = acc.saturating_sub(amount_sompi + fee);

    // Build PSKT<Creator> → Constructor with inputs + outputs populated, no sigs.
    let pskt = PSKT::<Creator>::default().inputs_modifiable().outputs_modifiable();
    let mut constructor = pskt.constructor();

    for (outpoint, entry) in &selected {
        let input = InputBuilder::default()
            .utxo_entry(entry.clone())
            .previous_outpoint(*outpoint)
            .sig_op_count(1)
            .redeem_script(redeem_script.clone())
            .build()
            .expect("input builder");
        constructor = constructor.input(input);
    }

    let payment_output = OutputBuilder::default()
        .amount(amount_sompi)
        .script_public_key(pay_to_address_script(&to_address))
        .build()
        .expect("output builder");
    constructor = constructor.output(payment_output);

    if change > 0 {
        let change_output =
            OutputBuilder::default().amount(change).script_public_key(pay_to_address_script(&address)).build().expect("change output");
        constructor = constructor.output(change_output);
    }

    let bundle = Bundle::from(constructor);
    let serialized = bundle.serialize().expect("bundle serialize");
    std::fs::write(output_path, &serialized).expect("write file");

    println!("PSBS criado.");
    println!("  Inputs    : {} UTXOs ({} sompi)", selected.len(), acc);
    println!("  Destino   : {}", to_addr_str);
    println!("  Valor     : {} sompi  ({:.8} SPHS)", amount_sompi, amount_sompi as f64 / SOMPI_PER_SOPHIS as f64);
    println!("  Fee       : {} sompi", fee);
    if change > 0 {
        println!("  Change    : {} sompi → {}", change, address);
    }
    println!("  Arquivo   : {}", output_path.display());
    println!();
    println!("Próximo passo (em máquina offline com chave):");
    println!("  dilithium-wallet pskt sign --wallet <wallet> --input {} --output <signed.psbs>", output_path.display());
}

/// Load a PSBS bundle, sign each input with the wallet's Dilithium key,
/// and write the signed bundle to `output_path`.
fn cmd_pskt_sign(wallet_path: &PathBuf, input_path: &PathBuf, output_path: &PathBuf) {
    use libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE;
    use sophis_consensus_core::hashing::sighash::calc_signature_hash;

    let wallet = Wallet::load(wallet_path).expect("Wallet não encontrada");
    let vk_bytes = wallet.verification_key().unwrap();
    let sk_bytes = wallet.signing_key().unwrap();

    let serialized = std::fs::read_to_string(input_path).expect("read PSBS file");
    let bundle = Bundle::deserialize(&serialized).expect("deserialize bundle");
    if bundle.0.is_empty() {
        eprintln!("Erro: bundle PSBS vazio.");
        return;
    }

    let mut signed_bundle = Bundle::new();
    let mut total_inputs_signed = 0usize;

    for inner in bundle.0.iter().cloned() {
        let pskt: PSKT<Signer> = PSKT::from(inner);
        let signed = pskt
            .pass_signature_sync(|tx, sighashes| -> std::result::Result<Vec<SignInputOk>, String> {
                let reused = SigHashReusedValuesUnsync::new();
                tx.tx
                    .inputs
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        let sighash_type = sighashes[i];
                        let sig_hash = calc_signature_hash(&tx.as_verifiable(), i, sighash_type, &reused);
                        let signing_key = ml_dsa_44::MLDSA44SigningKey::new(sk_bytes);
                        let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
                        getrandom::getrandom(&mut randomness).map_err(|e| format!("rand: {}", e))?;
                        let sig = ml_dsa_44::sign(&signing_key, &sig_hash.as_bytes()[..], b"", randomness)
                            .map_err(|_| "Dilithium sign failed".to_string())?;
                        randomness.iter_mut().for_each(|b| *b = 0);
                        let sig_array: [u8; DILITHIUM44_SIG_SIZE] = *sig.as_ref();
                        Ok(SignInputOk {
                            signature: PsbsSignature::dilithium_ml44_from_bytes(sig_array),
                            pub_key: DilithiumPubKey::from_bytes(vk_bytes),
                            key_source: None,
                        })
                    })
                    .collect()
            })
            .expect("pass_signature");

        total_inputs_signed += signed.inputs.len();
        signed_bundle.add_inner((*signed).clone());
    }

    let serialized_out = signed_bundle.serialize().expect("serialize signed bundle");
    std::fs::write(output_path, &serialized_out).expect("write signed bundle");

    println!("PSBS assinado.");
    println!("  Inputs assinados : {}", total_inputs_signed);
    println!("  Arquivo          : {}", output_path.display());
    println!();
    println!("Próximo passo (em máquina online):");
    println!("  dilithium-wallet pskt extract --input {} --output <tx.json>", output_path.display());
}

/// Combine multiple PSBS files into one. Useful for multisig coordination.
/// Single-sig case: trivial pass-through (only one input file).
fn cmd_pskt_combine(input_paths: &[PathBuf], output_path: &PathBuf) {
    if input_paths.is_empty() {
        eprintln!("Erro: nenhum arquivo de entrada fornecido.");
        return;
    }

    let mut accumulator: Option<Bundle> = None;
    for (i, path) in input_paths.iter().enumerate() {
        let serialized = std::fs::read_to_string(path).expect("read PSBS file");
        let bundle = Bundle::deserialize(&serialized).expect("deserialize bundle");
        match accumulator.take() {
            None => accumulator = Some(bundle),
            Some(mut acc) => {
                // For single-sig case (input_paths.len() == 1) this branch never runs.
                // Real multisig combine requires Combiner role logic per-PSKT (J1 work).
                acc.merge(bundle);
                accumulator = Some(acc);
            }
        }
        println!("  ✓ carregado: {}", path.display());
        if i == 0 && input_paths.len() == 1 {
            println!("    (single input — combine é pass-through)");
        }
    }

    let result = accumulator.expect("at least one input");
    let serialized = result.serialize().expect("serialize");
    std::fs::write(output_path, &serialized).expect("write");

    println!();
    println!("PSBS combinado.");
    println!("  Inputs    : {} arquivos", input_paths.len());
    println!("  Arquivo   : {}", output_path.display());
    if input_paths.len() == 1 {
        println!();
        println!("Nota: combine real (multisig N-of-M) requer Account Abstraction (J1) —");
        println!("      ver wallet/aa-spec/SPEC.md e wallet/aa-spec/templates/Recovery.template.rs.");
    }
}

/// Finalize and extract the underlying Transaction from a signed PSBS,
/// writing it as JSON to `output_path` for downstream broadcast.
fn cmd_pskt_extract(input_path: &PathBuf, output_path: &PathBuf) {
    let serialized = std::fs::read_to_string(input_path).expect("read PSBS file");
    let bundle = Bundle::deserialize(&serialized).expect("deserialize bundle");
    if bundle.0.is_empty() {
        eprintln!("Erro: bundle vazio.");
        return;
    }

    // Single-sig path: take the first PSKT in the bundle, finalize, extract.
    let inner = bundle.0[0].clone();
    let pskt_finalizer: PSKT<Finalizer> = PSKT::from(inner);

    let finalized = pskt_finalizer
        .finalize_sync(|inner: &sophis_wallet_pskt::pskt::Inner| -> std::result::Result<Vec<Vec<u8>>, String> {
            inner
                .inputs
                .iter()
                .enumerate()
                .map(|(idx, input)| -> std::result::Result<Vec<u8>, String> {
                    let partial_sig = input.partial_sigs.first().ok_or_else(|| format!("Input {} has no partial signature", idx))?;
                    let sig_bytes = partial_sig.1.raw_bytes();
                    if sig_bytes.len() != DILITHIUM44_SIG_SIZE {
                        return Err(format!(
                            "Input {}: signature is {} bytes, expected {}",
                            idx,
                            sig_bytes.len(),
                            DILITHIUM44_SIG_SIZE
                        ));
                    }
                    let mut sig_with_sighash: Vec<u8> = Vec::with_capacity(DILITHIUM44_SIG_SIZE + 1);
                    sig_with_sighash.extend_from_slice(sig_bytes);
                    sig_with_sighash.push(input.sighash_type.to_u8());

                    let redeem_script = input.redeem_script.clone().ok_or_else(|| format!("Input {} missing redeem_script", idx))?;
                    pay_to_script_hash_signature_script(redeem_script, sig_with_sighash).map_err(|e| format!("Input {}: {}", idx, e))
                })
                .collect()
        })
        .expect("finalize");

    let extractor = finalized.extractor().expect("extractor");
    let mutable_tx = extractor.extract_tx(&DEVNET_PARAMS).expect("extract_tx");
    let tx = mutable_tx.tx;
    let tx_id = {
        let mut t = tx.clone();
        t.finalize();
        t.id()
    };

    let json = serde_json::to_string_pretty(&tx).expect("serialize tx");
    std::fs::write(output_path, &json).expect("write tx file");

    println!("Tx extraída.");
    println!("  Tx ID     : {}", tx_id);
    println!("  Inputs    : {}", tx.inputs.len());
    println!("  Outputs   : {}", tx.outputs.len());
    println!("  Arquivo   : {}", output_path.display());
    println!();
    println!("Próximo passo: broadcast da tx via RPC submit_transaction (manual ou ferramenta dedicada).");
}

// ─── J2 Typed-data signing ──────────────────────────────────────────────────

/// J2 — sign a typed-data message with the wallet's Dilithium key.
/// Reads schema (TypedStruct) and values (Vec<TypedValue>) from JSON
/// files, computes the typed digest, signs with Dilithium, prints
/// hex-encoded digest + signature + verification key.
fn cmd_typed_sign(wallet_path: &PathBuf, domain_name: &str, domain_version: &str, schema_path: &PathBuf, values_path: &PathBuf) {
    use libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE;
    use sophis_typed_data::{TypedDataDomain, TypedStruct, TypedValue, compute_typed_digest};

    let wallet = Wallet::load(wallet_path).expect("Wallet não encontrada");
    let vk_bytes = wallet.verification_key().unwrap();
    let sk_bytes = wallet.signing_key().unwrap();

    let network = match wallet.network.as_str() {
        "mainnet" => sophis_typed_data::NETWORK_MAINNET,
        "testnet" => sophis_typed_data::NETWORK_TESTNET,
        "devnet" => sophis_typed_data::NETWORK_DEVNET,
        "simnet" => sophis_typed_data::NETWORK_SIMNET,
        other => panic!("network desconhecido: {other}"),
    };

    let schema_str = std::fs::read_to_string(schema_path).expect("read schema");
    let schema: TypedStruct = serde_json::from_str(&schema_str).expect("parse schema JSON");
    let values_str = std::fs::read_to_string(values_path).expect("read values");
    let values: Vec<TypedValue> = serde_json::from_str(&values_str).expect("parse values JSON");

    let domain = TypedDataDomain::new(domain_name, domain_version, network);
    let digest = compute_typed_digest(&domain, &schema, &values, &[]).expect("compute digest");

    let signing_key = ml_dsa_44::MLDSA44SigningKey::new(sk_bytes);
    let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
    getrandom::getrandom(&mut randomness).expect("rand");
    let sig = ml_dsa_44::sign(&signing_key, &digest, b"", randomness).expect("Dilithium sign failed");
    randomness.iter_mut().for_each(|b| *b = 0);
    let sig_array: [u8; DILITHIUM44_SIG_SIZE] = *sig.as_ref();

    println!("Typed-data assinatura.");
    println!("  Domain    : {} v{} (network={})", domain_name, domain_version, wallet.network);
    println!("  Schema    : {}", schema.name);
    println!("  Digest    : {}", hex::encode(digest));
    println!("  Signature : {}", hex::encode(sig_array));
    println!("  PubKey    : {}", hex::encode(vk_bytes));
    println!();
    println!("Próximo passo: distribuir Domain + Schema + Values + Signature + PubKey ao verificador.");
}

/// J2 — verify a typed-data signature.
fn cmd_typed_verify(
    domain_name: &str,
    domain_version: &str,
    network: &str,
    schema_path: &PathBuf,
    values_path: &PathBuf,
    pubkey_hex: &str,
    signature_hex: &str,
) {
    use libcrux_ml_dsa::ml_dsa_44::{MLDSA44Signature, MLDSA44VerificationKey};
    use sophis_typed_data::{TypedDataDomain, TypedStruct, TypedValue, compute_typed_digest};

    let network_byte = match network {
        "mainnet" => sophis_typed_data::NETWORK_MAINNET,
        "testnet" => sophis_typed_data::NETWORK_TESTNET,
        "devnet" => sophis_typed_data::NETWORK_DEVNET,
        "simnet" => sophis_typed_data::NETWORK_SIMNET,
        other => panic!("network desconhecido: {other}"),
    };

    let schema_str = std::fs::read_to_string(schema_path).expect("read schema");
    let schema: TypedStruct = serde_json::from_str(&schema_str).expect("parse schema JSON");
    let values_str = std::fs::read_to_string(values_path).expect("read values");
    let values: Vec<TypedValue> = serde_json::from_str(&values_str).expect("parse values JSON");

    let domain = TypedDataDomain::new(domain_name, domain_version, network_byte);
    let digest = compute_typed_digest(&domain, &schema, &values, &[]).expect("compute digest");

    let vk_bytes_vec = hex::decode(pubkey_hex).expect("invalid pubkey hex");
    let vk_bytes: [u8; VK_SIZE] = vk_bytes_vec.try_into().expect("pubkey wrong length");
    let sig_bytes_vec = hex::decode(signature_hex).expect("invalid signature hex");
    let sig_bytes: [u8; DILITHIUM44_SIG_SIZE] = sig_bytes_vec.try_into().expect("sig wrong length");

    let vk = MLDSA44VerificationKey::new(vk_bytes);
    let signature = MLDSA44Signature::new(sig_bytes);

    match ml_dsa_44::verify(&vk, &digest, b"", &signature) {
        Ok(()) => {
            println!("VALID");
            println!("  Domain    : {} v{} (network={})", domain_name, domain_version, network);
            println!("  Schema    : {}", schema.name);
            println!("  Digest    : {}", hex::encode(digest));
        }
        Err(_) => {
            println!("INVALID");
            std::process::exit(1);
        }
    }
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    sophis_core::log::init_logger(None, "warn");

    let wallet_arg = || Arg::new("wallet").long("wallet").short('w').default_value("dilithium_wallet.json");
    let network_arg =
        || Arg::new("network").long("network").short('n').default_value("devnet").value_parser(["devnet", "testnet", "mainnet"]);
    let rpc_arg = || Arg::new("rpcserver").long("rpcserver").short('s').default_value("localhost:46610");

    let m = Command::new("dilithium-wallet")
        .about(format!("Sophis Dilithium-2 PQC Wallet v{}", version()))
        .subcommand_required(true)
        .subcommand(
            Command::new("keygen")
                .about("Gera keypair Dilithium-2 a partir de mnemônico BIP39 (24 palavras)")
                .arg(wallet_arg())
                .arg(network_arg()),
        )
        .subcommand(
            Command::new("restore")
                .about("Restaura wallet a partir de mnemônico BIP39 de 24 palavras")
                .arg(wallet_arg())
                .arg(network_arg())
                .arg(Arg::new("mnemonic").long("mnemonic").short('m').required(true).help("As 24 palavras separadas por espaço")),
        )
        .subcommand(Command::new("mnemonic").about("Exibe a frase de recuperação de 24 palavras da wallet").arg(wallet_arg()))
        .subcommand(Command::new("info").about("Exibe saldo e UTXOs do endereço Dilithium").arg(wallet_arg()).arg(rpc_arg()))
        .subcommand(
            Command::new("send")
                .about("Constrói, assina com Dilithium-2 e submete uma TX")
                .arg(wallet_arg())
                .arg(rpc_arg())
                .arg(Arg::new("to").long("to").short('t').required(true))
                .arg(Arg::new("amount").long("amount").short('a').required(true).value_parser(value_parser!(u64))),
        )
        .subcommand(
            Command::new("tampered")
                .about("Submete TX com assinatura ADULTERADA — espera rejeição do nó")
                .arg(wallet_arg())
                .arg(rpc_arg())
                .arg(Arg::new("to").long("to").short('t').required(true))
                .arg(Arg::new("amount").long("amount").short('a').required(true).value_parser(value_parser!(u64))),
        )
        .subcommand(
            // Phase 6 — Data Availability layer queries + publishing.
            Command::new("da")
                .about("Comandos do Data Availability layer (Phase 6)")
                .subcommand_required(true)
                .subcommand(
                    Command::new("publish")
                        .about("Publica um payload arbitrário no DA layer (V5 carrier outputs)")
                        .arg(wallet_arg())
                        .arg(rpc_arg())
                        .arg(
                            Arg::new("payload-file")
                                .long("payload-file")
                                .short('f')
                                .required(true)
                                .help("Arquivo com bytes do payload"),
                        )
                        .arg(Arg::new("domain").long("domain").short('d').default_value("none").help("Rollup|Oracle|User|None")),
                )
                .subcommand(
                    Command::new("inspect")
                        .about("Exibe um payload DA pelo seu payload_id (hex 96 chars / 48 bytes)")
                        .arg(rpc_arg())
                        .arg(
                            Arg::new("payload-id")
                                .long("payload-id")
                                .short('p')
                                .required(true)
                                .help("payload_id em hex (com ou sem 0x)"),
                        ),
                )
                .subcommand(
                    Command::new("bundle")
                        .about("Exibe um bundle DA pelo seu bundle_id (hex 96 chars / 48 bytes)")
                        .arg(rpc_arg())
                        .arg(
                            Arg::new("bundle-id").long("bundle-id").short('b').required(true).help("bundle_id em hex (com ou sem 0x)"),
                        ),
                ),
        )
        .subcommand(
            // K1.4 — Partially Signed Sophis Transactions (PSBS) cold-storage workflow.
            // See wallet/pskt/DESIGN.md and wallet/pskt/SPEC (forthcoming).
            Command::new("pskt")
                .about("Cold-storage workflow PSBS — create / sign / combine / extract")
                .subcommand_required(true)
                .subcommand(
                    Command::new("create")
                        .about("Constrói PSBS unsigned (online: precisa RPC pra UTXOs)")
                        .arg(wallet_arg())
                        .arg(rpc_arg())
                        .arg(Arg::new("to").long("to").short('t').required(true))
                        .arg(Arg::new("amount").long("amount").short('a').required(true).value_parser(value_parser!(u64)))
                        .arg(Arg::new("output").long("output").short('o').required(true).help("Arquivo .psbs de saída")),
                )
                .subcommand(
                    Command::new("sign")
                        .about("Assina PSBS com chave Dilithium da wallet (offline: não precisa RPC)")
                        .arg(wallet_arg())
                        .arg(Arg::new("input").long("input").short('i').required(true).help("Arquivo .psbs de entrada"))
                        .arg(Arg::new("output").long("output").short('o').required(true).help("Arquivo .psbs assinado de saída")),
                )
                .subcommand(
                    Command::new("combine")
                        .about("Combina N PSBS num único bundle (multisig coord; trivial em single-sig)")
                        .arg(
                            Arg::new("inputs")
                                .long("inputs")
                                .short('i')
                                .required(true)
                                .num_args(1..)
                                .help("Arquivos .psbs separados por espaço"),
                        )
                        .arg(Arg::new("output").long("output").short('o').required(true).help("Arquivo .psbs combinado de saída")),
                )
                .subcommand(
                    Command::new("extract")
                        .about("Finaliza + extrai Transaction de PSBS assinado (single-sig path)")
                        .arg(Arg::new("input").long("input").short('i').required(true).help("Arquivo .psbs assinado de entrada"))
                        .arg(Arg::new("output").long("output").short('o').required(true).help("Arquivo .json de tx de saída")),
                ),
        )
        .subcommand(
            // J2 — Typed-data signing (EIP-712-equivalent for Dilithium).
            // See docs/J2_TYPED_SIGNING_DESIGN.md and SIPS/SIP-2-TYPED-SIGNING.md.
            Command::new("typed")
                .about("Typed-data signing (EIP-712 equivalent) — sign / verify")
                .subcommand_required(true)
                .subcommand(
                    Command::new("sign")
                        .about("Assina mensagem typed-data com chave Dilithium da wallet")
                        .arg(wallet_arg())
                        .arg(Arg::new("domain-name").long("domain-name").required(true).help("Nome da dApp (e.g. MyDApp)"))
                        .arg(Arg::new("domain-version").long("domain-version").required(true).help("Versão da dApp (e.g. 1.0.0)"))
                        .arg(Arg::new("schema").long("schema").required(true).help("Arquivo JSON com TypedStruct"))
                        .arg(Arg::new("values").long("values").required(true).help("Arquivo JSON com Vec<TypedValue>")),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verifica assinatura typed-data (offline)")
                        .arg(Arg::new("domain-name").long("domain-name").required(true))
                        .arg(Arg::new("domain-version").long("domain-version").required(true))
                        .arg(network_arg())
                        .arg(Arg::new("schema").long("schema").required(true))
                        .arg(Arg::new("values").long("values").required(true))
                        .arg(Arg::new("pubkey").long("pubkey").required(true).help("VK em hex (1312 bytes = 2624 hex chars)"))
                        .arg(Arg::new("signature").long("signature").required(true).help("Sig em hex (2420 bytes = 4840 hex chars)")),
                ),
        )
        .get_matches();

    match m.subcommand() {
        Some(("keygen", sub)) => {
            let w = PathBuf::from(sub.get_one::<String>("wallet").unwrap());
            let n = sub.get_one::<String>("network").unwrap();
            cmd_keygen(&w, n);
        }
        Some(("restore", sub)) => {
            let w = PathBuf::from(sub.get_one::<String>("wallet").unwrap());
            let n = sub.get_one::<String>("network").unwrap();
            let phrase = sub.get_one::<String>("mnemonic").unwrap();
            cmd_restore(&w, phrase, n);
        }
        Some(("mnemonic", sub)) => {
            let w = PathBuf::from(sub.get_one::<String>("wallet").unwrap());
            cmd_mnemonic(&w);
        }
        Some(("info", sub)) => {
            let w = PathBuf::from(sub.get_one::<String>("wallet").unwrap());
            let s = sub.get_one::<String>("rpcserver").unwrap();
            cmd_info(&w, s).await;
        }
        Some(("send", sub)) => {
            let w = PathBuf::from(sub.get_one::<String>("wallet").unwrap());
            let s = sub.get_one::<String>("rpcserver").unwrap();
            let t = sub.get_one::<String>("to").unwrap();
            let a = *sub.get_one::<u64>("amount").unwrap();
            cmd_send(&w, s, t, a, false).await;
        }
        Some(("tampered", sub)) => {
            let w = PathBuf::from(sub.get_one::<String>("wallet").unwrap());
            let s = sub.get_one::<String>("rpcserver").unwrap();
            let t = sub.get_one::<String>("to").unwrap();
            let a = *sub.get_one::<u64>("amount").unwrap();
            cmd_send(&w, s, t, a, true).await;
        }
        Some(("da", sub)) => match sub.subcommand() {
            Some(("publish", ssub)) => {
                let w = PathBuf::from(ssub.get_one::<String>("wallet").unwrap());
                let s = ssub.get_one::<String>("rpcserver").unwrap();
                let f = ssub.get_one::<String>("payload-file").unwrap();
                let d = ssub.get_one::<String>("domain").unwrap();
                cmd_da_publish(&w, s, f, d).await;
            }
            Some(("inspect", ssub)) => {
                let s = ssub.get_one::<String>("rpcserver").unwrap();
                let pid = ssub.get_one::<String>("payload-id").unwrap();
                cmd_da_inspect(s, pid).await;
            }
            Some(("bundle", ssub)) => {
                let s = ssub.get_one::<String>("rpcserver").unwrap();
                let bid = ssub.get_one::<String>("bundle-id").unwrap();
                cmd_da_bundle(s, bid).await;
            }
            _ => unreachable!(),
        },
        Some(("pskt", sub)) => match sub.subcommand() {
            Some(("create", ssub)) => {
                let w = PathBuf::from(ssub.get_one::<String>("wallet").unwrap());
                let s = ssub.get_one::<String>("rpcserver").unwrap();
                let t = ssub.get_one::<String>("to").unwrap();
                let a = *ssub.get_one::<u64>("amount").unwrap();
                let o = PathBuf::from(ssub.get_one::<String>("output").unwrap());
                cmd_pskt_create(&w, s, t, a, &o).await;
            }
            Some(("sign", ssub)) => {
                let w = PathBuf::from(ssub.get_one::<String>("wallet").unwrap());
                let i = PathBuf::from(ssub.get_one::<String>("input").unwrap());
                let o = PathBuf::from(ssub.get_one::<String>("output").unwrap());
                cmd_pskt_sign(&w, &i, &o);
            }
            Some(("combine", ssub)) => {
                let inputs: Vec<PathBuf> = ssub.get_many::<String>("inputs").unwrap().map(PathBuf::from).collect();
                let o = PathBuf::from(ssub.get_one::<String>("output").unwrap());
                cmd_pskt_combine(&inputs, &o);
            }
            Some(("extract", ssub)) => {
                let i = PathBuf::from(ssub.get_one::<String>("input").unwrap());
                let o = PathBuf::from(ssub.get_one::<String>("output").unwrap());
                cmd_pskt_extract(&i, &o);
            }
            _ => unreachable!(),
        },
        Some(("typed", sub)) => match sub.subcommand() {
            Some(("sign", ssub)) => {
                let w = PathBuf::from(ssub.get_one::<String>("wallet").unwrap());
                let dn = ssub.get_one::<String>("domain-name").unwrap();
                let dv = ssub.get_one::<String>("domain-version").unwrap();
                let sc = PathBuf::from(ssub.get_one::<String>("schema").unwrap());
                let vl = PathBuf::from(ssub.get_one::<String>("values").unwrap());
                cmd_typed_sign(&w, dn, dv, &sc, &vl);
            }
            Some(("verify", ssub)) => {
                let dn = ssub.get_one::<String>("domain-name").unwrap();
                let dv = ssub.get_one::<String>("domain-version").unwrap();
                let net = ssub.get_one::<String>("network").unwrap();
                let sc = PathBuf::from(ssub.get_one::<String>("schema").unwrap());
                let vl = PathBuf::from(ssub.get_one::<String>("values").unwrap());
                let pk = ssub.get_one::<String>("pubkey").unwrap();
                let sg = ssub.get_one::<String>("signature").unwrap();
                cmd_typed_verify(dn, dv, net, &sc, &vl, pk, sg);
            }
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}
