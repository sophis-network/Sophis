use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

const MAX_ADDRS_PER_RESPONSE: usize = 16;

/// Minimal UDP DNS server. Handles A queries only; all other query types are ignored.
///
/// DNS response format (RFC 1035):
///   Header (12 bytes) + echo question + A record answers
pub async fn serve(listen: SocketAddr, nodes: Arc<RwLock<Vec<Ipv4Addr>>>, ttl: u32) {
    let sock = UdpSocket::bind(listen).await.expect("DNS: failed to bind UDP socket");
    eprintln!("DNS server listening on {listen}");

    let mut buf = [0u8; 512];
    loop {
        let (len, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("DNS recv error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let good = nodes.read().await.clone();
        if let Some(response) = build_response(&buf[..len], &good, ttl)
            && let Err(e) = sock.send_to(&response, peer).await
        {
            eprintln!("DNS send error: {e}");
        }
    }
}

/// Parse a DNS query and build an A-record response.
/// Returns None for malformed packets or non-A queries.
fn build_response(query: &[u8], nodes: &[Ipv4Addr], ttl: u32) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let id = &query[0..2];
    // RD bit is bit 0 of query byte 2 (flags high byte)
    let rd_flag = query[2] & 0x01;
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse QNAME (labels ending with 0x00, or compression pointer 0xC0xx)
    let mut pos = 12usize;
    loop {
        if pos >= query.len() {
            return None;
        }
        let label_len = query[pos] as usize;
        if label_len == 0 {
            pos += 1;
            break;
        }
        if label_len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + label_len;
    }
    if pos + 4 > query.len() {
        return None;
    }

    // QTYPE must be A (1) to respond
    let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
    if qtype != 1 {
        return None;
    }

    // The full question section: QNAME + QTYPE(2) + QCLASS(2)
    let question = &query[12..pos + 4];

    let selected = select_nodes(nodes);
    let ancount = selected.len() as u16;

    let mut resp = Vec::with_capacity(12 + question.len() + ancount as usize * 16);

    // Header
    resp.extend_from_slice(id);
    // Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=rd_flag | RA=0, Z=0, RCODE=0
    resp.push(0x84 | rd_flag);
    resp.push(0x00);
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question (echoed)
    resp.extend_from_slice(question);

    // A record answers
    for ip in &selected {
        resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer → offset 12 (QNAME start)
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&ttl.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&ip.octets()); // RDATA
    }

    Some(resp)
}

/// Return up to MAX_ADDRS_PER_RESPONSE nodes, rotating the starting offset each second
/// so successive queries get different subsets.
fn select_nodes(nodes: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    if nodes.is_empty() {
        return Vec::new();
    }
    if nodes.len() <= MAX_ADDRS_PER_RESPONSE {
        return nodes.to_vec();
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as usize;
    let offset = now % nodes.len();
    nodes.iter().cycle().skip(offset).take(MAX_ADDRS_PER_RESPONSE).copied().collect()
}
