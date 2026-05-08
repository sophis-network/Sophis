use sophis_rpc_core::api::rpc::RpcApi;
use sophis_wrpc_client::{
    SophisRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Crawl the Sophis network:
/// 1. Query each seed node via wRPC Borsh for its known peer addresses.
/// 2. TCP-check every discovered address on the P2P port.
/// 3. Return IPs that passed the TCP check (IPv4 only — used for DNS A records).
pub async fn crawl(seeds: &[String], p2p_port: u16) -> Vec<Ipv4Addr> {
    let mut discovered: HashSet<IpAddr> = HashSet::new();

    for seed in seeds {
        match query_peers(seed).await {
            Ok(ips) => {
                let new = ips.len();
                discovered.extend(ips);
                eprintln!("  seed {seed}: {new} addresses");
            }
            Err(e) => eprintln!("  seed {seed}: error — {e}"),
        }
    }

    eprintln!("  discovered {} unique IPs, health-checking...", discovered.len());

    // TCP health-check all discovered IPs concurrently
    let tasks: Vec<_> = discovered
        .into_iter()
        .filter_map(|ip| {
            // DNS A records are IPv4 only
            if let IpAddr::V4(v4) = ip {
                let addr = SocketAddr::new(IpAddr::V4(v4), p2p_port);
                Some(tokio::spawn(async move { if tcp_check(addr).await { Some(v4) } else { None } }))
            } else {
                None
            }
        })
        .collect();

    let mut reachable = Vec::new();
    for task in tasks {
        if let Ok(Some(ip)) = task.await {
            reachable.push(ip);
        }
    }
    reachable
}

/// Connect to a seed node via wRPC Borsh and call get_peer_addresses.
async fn query_peers(wrpc_url: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let url = if wrpc_url.starts_with("ws://") || wrpc_url.starts_with("wss://") {
        wrpc_url.to_string()
    } else {
        format!("ws://{wrpc_url}")
    };

    let client = SophisRpcClient::new(WrpcEncoding::Borsh, Some(url.as_str()), None, None, None)?;
    let options = ConnectOptions {
        block_async_connect: true,
        connect_timeout: Some(Duration::from_secs(10)),
        strategy: ConnectStrategy::Fallback,
        ..Default::default()
    };
    client.connect(Some(options)).await?;

    let resp = client.get_peer_addresses().await?;
    client.disconnect().await?;

    let ips = resp.known_addresses.iter().map(|a| a.ip.0).collect();
    Ok(ips)
}

/// TCP-connect to addr with a 5-second timeout to verify the node is reachable.
async fn tcp_check(addr: SocketAddr) -> bool {
    tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await.is_ok_and(|r| r.is_ok())
}
