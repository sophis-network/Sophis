/// sophis-explorer — Sophis block explorer HTTP server
use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, response::Html, routing::get};
use clap::{Arg, Command, value_parser};
use sophis_core::sophisd_env::version;
use sophis_grpc_client::GrpcClient;
use sophis_notify::subscription::context::SubscriptionContext;
use sophis_rpc_core::notify::mode::NotificationMode;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

mod api;
mod rpc;

pub const BLOCKS_CACHE_TTL: Duration = Duration::from_secs(5);

pub struct BlocksCache {
    pub blocks: Vec<rpc::BlockSummary>,
    pub expires: std::time::Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub rpc: Arc<GrpcClient>,
    pub blocks_cache: Arc<Mutex<Option<BlocksCache>>>,
}

static INDEX_HTML: &str = include_str!("../html/index.html");
static BLOCK_HTML: &str = include_str!("../html/block.html");
static TX_HTML: &str = include_str!("../html/tx.html");
static ADDRESS_HTML: &str = include_str!("../html/address.html");

async fn connect_rpc(server: &str) -> GrpcClient {
    let ctx = SubscriptionContext::new();
    GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{}", server),
        Some(ctx),
        true,
        None,
        false,
        Some(15_000),
        Default::default(),
    )
    .await
    .expect("Failed to connect to sophisd gRPC")
}

#[tokio::main]
async fn main() {
    sophis_core::log::init_logger(None, "info");

    let m = Command::new("sophis-explorer")
        .about(format!("Sophis Block Explorer v{}", version()))
        .subcommand_required(true)
        .subcommand(
            Command::new("start")
                .about("Start the block explorer HTTP server")
                .arg(Arg::new("rpcserver").long("rpcserver").short('s').default_value("localhost:46610"))
                .arg(Arg::new("port").long("port").short('p').default_value("8091").value_parser(value_parser!(u16)))
                .arg(
                    Arg::new("network")
                        .long("network")
                        .short('n')
                        .default_value("devnet")
                        .value_parser(["devnet", "testnet", "simnet", "mainnet"]),
                ),
        )
        .get_matches();

    let Some(("start", sub)) = m.subcommand() else { return };

    let rpc_server = sub.get_one::<String>("rpcserver").unwrap().clone();
    let port = *sub.get_one::<u16>("port").unwrap();
    let network = sub.get_one::<String>("network").unwrap().clone();

    let rpc = Arc::new(connect_rpc(&rpc_server).await);
    let state = AppState { rpc, blocks_cache: Arc::new(Mutex::new(None)) };

    let cors = CorsLayer::new().allow_methods([axum::http::Method::GET]).allow_origin(tower_http::cors::Any);

    let app = Router::new()
        .route("/", get(|| async { Html(INDEX_HTML) }))
        .route("/block", get(|| async { Html(BLOCK_HTML) }))
        .route("/tx", get(|| async { Html(TX_HTML) }))
        .route("/address", get(|| async { Html(ADDRESS_HTML) }))
        .route("/api/info", get(api::handle_info))
        .route("/api/blocks", get(api::handle_blocks))
        .route("/api/blocks/:hash", get(api::handle_block))
        .route("/api/transactions/:txid", get(api::handle_tx))
        .route("/api/address/:address", get(api::handle_address))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("Failed to bind");

    println!("=== Sophis Block Explorer v{} ===", version());
    println!("  Network  : {}", network);
    println!("  RPC      : {}", rpc_server);
    println!("  URL      : http://0.0.0.0:{}", port);
    println!();

    axum::serve(listener, app).await.expect("Server error");
}
