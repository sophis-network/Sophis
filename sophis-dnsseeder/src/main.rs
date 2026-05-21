use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

mod crawler;
mod dns;

#[derive(Parser)]
#[command(name = "sophis-dnsseeder", about = "DNS seeder for the Sophis network")]
struct Args {
    /// Network to seed: mainnet or testnet-10
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// UDP address to listen for DNS queries
    #[arg(long, default_value = "0.0.0.0:53")]
    listen_dns: SocketAddr,

    /// wRPC Borsh URLs of seed nodes used for initial peer discovery (ws://IP:PORT)
    /// Example: --seeds ws://1.2.3.4:47110,ws://5.6.7.8:47110
    #[arg(long, value_delimiter = ',', required = true)]
    seeds: Vec<String>,

    /// How often to re-crawl the network (seconds)
    #[arg(long, default_value = "1800")]
    crawl_interval: u64,

    /// DNS TTL for returned A records (seconds)
    #[arg(long, default_value = "30")]
    dns_ttl: u32,

    /// Zone we are authoritative for. Queries for any other name receive RCODE=REFUSED.
    /// Case-insensitive. Default targets the testnet seed.
    #[arg(long, default_value = "testnet-seed.sophis.org")]
    zone: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let p2p_port = match args.network.as_str() {
        "mainnet" => 46111u16,
        "testnet" | "testnet-10" => 46211,
        other => {
            eprintln!("Unknown network '{other}'. Use mainnet or testnet-10.");
            std::process::exit(1);
        }
    };

    let zone = args.zone.trim().trim_end_matches('.').to_ascii_lowercase();
    if zone.is_empty() {
        eprintln!("--zone cannot be empty");
        std::process::exit(1);
    }

    eprintln!("sophis-dnsseeder starting | network={} p2p_port={} dns={} zone={}", args.network, p2p_port, args.listen_dns, zone);

    let good_nodes: Arc<RwLock<Vec<Ipv4Addr>>> = Arc::new(RwLock::new(Vec::new()));

    // DNS server task
    let dns_nodes = good_nodes.clone();
    let listen_dns = args.listen_dns;
    let ttl = args.dns_ttl;
    let zone_for_dns = zone.clone();
    tokio::spawn(async move {
        dns::serve(listen_dns, dns_nodes, ttl, zone_for_dns).await;
    });

    // Crawl loop
    let seeds = args.seeds.clone();
    let interval = Duration::from_secs(args.crawl_interval);
    loop {
        eprintln!("Starting crawl from {} seed(s)...", seeds.len());
        let reachable = crawler::crawl(&seeds, p2p_port).await;
        eprintln!("Crawl done: {} reachable IPv4 nodes", reachable.len());
        *good_nodes.write().await = reachable;
        tokio::time::sleep(interval).await;
    }
}
