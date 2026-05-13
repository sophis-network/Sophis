mod donate;

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Arg, Command};
use rayon::prelude::*;
use sophis_addresses::Address;
use sophis_consensus_core::{header::Header, merkle::calc_hash_merkle_root, tx::Transaction};
use sophis_core::{info, warn};
use sophis_grpc_client::GrpcClient;
use sophis_notify::subscription::context::SubscriptionContext;
use sophis_pow::{EPOCH_LENGTH, SharedDataset, State, build_epoch_dataset};
use sophis_rpc_core::{
    api::rpc::RpcApi,
    model::message::{GetBlockTemplateRequest, SubmitBlockRequest},
    notify::mode::NotificationMode,
};
use tokio::time::sleep;

// Nonces verificados por batch rayon (ajuste conforme velocidade da CPU)
const BATCH_SIZE: u64 = 5_000_000;

// Intervalo máximo antes de buscar novo template (ms)
const TEMPLATE_REFRESH_MS: u64 = 500;

// ---------------------------------------------------------------------------
// Mining
// ---------------------------------------------------------------------------

fn mine_template(state: &State, template_refresh_ms: u64) -> Option<u64> {
    let mut nonce_start: u64 = rand::random::<u64>();
    let deadline = Instant::now() + Duration::from_millis(template_refresh_ms);

    loop {
        let end = nonce_start.wrapping_add(BATCH_SIZE);
        let range: Vec<u64> = if end >= nonce_start {
            (nonce_start..end).collect()
        } else {
            // wrap-around
            (nonce_start..u64::MAX).chain(0..end).collect()
        };

        let found = range.into_par_iter().find_any(|&nonce| state.check_pow(nonce).0);

        if let Some(nonce) = found {
            return Some(nonce);
        }

        nonce_start = nonce_start.wrapping_add(BATCH_SIZE);

        if Instant::now() >= deadline {
            return None; // tempo esgotado, buscar novo template
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    sophis_core::log::init_logger(None, "");

    let m =
        Command::new("sophis-miner")
            .about("Sophis CPU Miner — devnet/testnet")
            .arg(
                Arg::new("rpcserver")
                    .long("rpcserver")
                    .short('s')
                    .default_value("localhost:46610")
                    .help("Endereco gRPC do no (host:porta). Devnet node-0 = localhost:46610"),
            )
            .arg(
                Arg::new("threads")
                    .long("threads")
                    .short('t')
                    .default_value("0")
                    .value_parser(clap::value_parser!(usize))
                    .help("Threads de mineracao (0 = todos os nucleos)"),
            )
            .arg(
                Arg::new("mining-address").long("mining-address").short('a').required(true).help(
                    "Endereco Sophis Dilithium que recebe a recompensa coinbase (obrigatorio — gere com `dilithium-wallet new`)",
                ),
            )
            .arg(
                Arg::new("fast-mode")
                    .long("fast-mode")
                    .action(clap::ArgAction::SetTrue)
                    .help("Ativa RandomX Fast Mode (~2 GB RAM, ~10x hashrate). Requer ~2 min de inicializacao por epoch."),
            )
            .arg(Arg::new("donate-to").long("donate-to").value_name("ADDRESS").action(clap::ArgAction::Append).help(
                "Endereco Sophis que recebe parte da recompensa coinbase (cliente-side, opt-in). \
                     Pode ser repetido para split entre varias causas. Requer --donate-percent na mesma ordem. \
                     Sem lista oficial: o operador escolhe livremente.",
            ))
            .arg(
                Arg::new("donate-percent")
                    .long("donate-percent")
                    .value_name("N")
                    .value_parser(clap::value_parser!(u8))
                    .action(clap::ArgAction::Append)
                    .help(
                        "Percentual da recompensa que vai para a entrada --donate-to correspondente (0-100, inteiro). \
                     A soma deve ser <= 100. Default: nenhum (100% pro minerador).",
                    ),
            )
            .get_matches();

    let rpc_server = m.get_one::<String>("rpcserver").unwrap().clone();
    let threads = *m.get_one::<usize>("threads").unwrap();
    let fast_mode = m.get_flag("fast-mode");

    if threads > 0 {
        rayon::ThreadPoolBuilder::new().num_threads(threads).build_global().unwrap();
    }

    // Endereço de mineração — `--mining-address` é obrigatório (clap enforces).
    let addr_str = m.get_one::<String>("mining-address").expect("clap garante --mining-address obrigatorio");
    let pay_address = Address::try_from(addr_str.clone()).expect("Endereco de mineracao invalido");

    // Donations (cliente-side, opt-in). Default: nenhuma → 100% pro minerador.
    let donate_addrs: Vec<String> = m.get_many::<String>("donate-to").map(|v| v.cloned().collect()).unwrap_or_default();
    let donate_pcts: Vec<u8> = m.get_many::<u8>("donate-percent").map(|v| v.copied().collect()).unwrap_or_default();
    let donations = match donate::parse_donations(&donate_addrs, &donate_pcts, pay_address.prefix) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Erro ao processar flags --donate-*: {}", e);
            std::process::exit(1);
        }
    };
    if !donations.is_empty() {
        let total_pct: u32 = donations.iter().map(|d| d.percent as u32).sum();
        info!("Donations cliente-side ATIVAS — {}% do bloco pra {} endereco(s):", total_pct, donations.len());
        for d in &donations {
            info!("  {}% -> {}", d.percent, String::from(&d.address));
        }
        info!("(Convencao: split aplicado por bloco; arredondamento acumula no minerador. Sem lista oficial.)");
    }

    if fast_mode {
        info!("Fast Mode ativado. Dataset sera construido (~2 GB RAM, ~2 min) no primeiro bloco recebido.");
    }

    // Conecta ao gRPC
    let sub_ctx = SubscriptionContext::new();
    let rpc = GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{}", rpc_server),
        Some(sub_ctx),
        true,
        None,
        false,
        Some(500_000),
        Default::default(),
    )
    .await
    .expect("Falha ao conectar ao gRPC");

    info!("Conectado a grpc://{}. Iniciando mineracao...", rpc_server);

    let mut blocks_found: u64 = 0;
    let mut total_hashes: u64 = 0;
    let start_time = Instant::now();
    let mut last_log = Instant::now();

    // Fast mode: dataset compartilhado entre threads, reconstruido por epoch.
    let mut current_epoch: u64 = u64::MAX;
    let mut shared_dataset: Option<Arc<SharedDataset>> = None;

    loop {
        // Obtém template
        let mut template =
            match rpc.get_block_template_call(None, GetBlockTemplateRequest::new(pay_address.clone(), b"sophis-miner".to_vec())).await
            {
                Ok(t) => t,
                Err(e) => {
                    warn!("get_block_template falhou: {}. Retry em 2s...", e);
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

        // Aplica donation split na coinbase (cliente-side, antes de minerar).
        // O nó devolve a coinbase como transactions[0]. Reescrevemos seus
        // outputs para incluir as doações configuradas e recomputamos o
        // hash_merkle_root do header — caso contrário o bloco fica
        // inválido após submit_block.
        if !donations.is_empty() && !template.block.transactions.is_empty() {
            donate::rewrite_coinbase_outputs(&mut template.block.transactions[0], &donations);
            // Recompute merkle root: convert each RpcTransaction → Transaction.
            let txs: Result<Vec<Transaction>, _> = template.block.transactions.iter().cloned().map(Transaction::try_from).collect();
            match txs {
                Ok(txs_internal) => {
                    let new_root = calc_hash_merkle_root(txs_internal.iter());
                    template.block.header.hash_merkle_root = new_root;
                }
                Err(e) => {
                    warn!("Conversao de tx para recomputar merkle root falhou: {}. Skipping bloco.", e);
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }
        }

        // Converte header para tipo interno
        let header = match Header::try_from(&template.block.header) {
            Ok(h) => h,
            Err(e) => {
                warn!("Conversao de header falhou: {}. Retry...", e);
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let daa_score = header.daa_score;
        let epoch = daa_score / EPOCH_LENGTH;

        // Reconstroi dataset ao entrar em novo epoch (fast mode)
        if fast_mode && epoch != current_epoch {
            info!("Novo epoch RandomX ({}) — construindo dataset (~2 GB RAM). Aguarde ~2 minutos...", epoch);
            let ds = tokio::task::spawn_blocking(move || build_epoch_dataset(daa_score)).await.expect("build_epoch_dataset falhou");
            shared_dataset = Some(Arc::new(ds));
            current_epoch = epoch;
            info!("Dataset RandomX pronto. Minerando em Fast Mode.");
        }

        // Cria State para este template
        let state = if fast_mode { State::new_fast(&header, shared_dataset.as_ref().unwrap().clone()) } else { State::new(&header) };

        // Minera até encontrar nonce ou expirar o template
        let found = mine_template(&state, TEMPLATE_REFRESH_MS);
        total_hashes += BATCH_SIZE; // aproximação para log

        // Log de hash rate a cada 10s
        if last_log.elapsed().as_secs() >= 10 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let mhs = total_hashes as f64 / elapsed / 1_000_000.0;
            info!("Hash rate: {:.2} MH/s | Blocos: {} | DAA: {} | Epoch: {}", mhs, blocks_found, daa_score, epoch);
            last_log = Instant::now();
        }

        if let Some(nonce) = found {
            let mut block = template.block;
            block.header.nonce = nonce;

            match rpc.submit_block_call(None, SubmitBlockRequest::new(block, false)).await {
                Ok(resp) => {
                    if resp.report.is_success() {
                        blocks_found += 1;
                        let elapsed = start_time.elapsed().as_secs_f64();
                        let mhs = total_hashes as f64 / elapsed / 1_000_000.0;
                        info!("*** BLOCO ENCONTRADO! #{} | nonce={} | DAA={} | {:.2} MH/s ***", blocks_found, nonce, daa_score, mhs);
                    } else {
                        warn!("Bloco rejeitado: {:?}", resp.report);
                    }
                }
                Err(e) => warn!("submit_block falhou: {}", e),
            }
        }
    }
}
