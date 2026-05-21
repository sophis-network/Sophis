use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

const MAX_ADDRS_PER_RESPONSE: usize = 16;

// DNS RCODE values (RFC 1035 §4.1.1)
const RCODE_NOERROR: u8 = 0;
const RCODE_REFUSED: u8 = 5;

// DNS QTYPE values
const QTYPE_A: u16 = 1;

/// Minimal UDP DNS server. Authoritative for a single zone passed in `zone`.
///
/// - Queries for the zone with QTYPE=A → respond with A records of currently
///   reachable Sophis peers, AA=1.
/// - Every other query (different name, non-A type, malformed-but-parsable) →
///   respond with RCODE=REFUSED, AA=0, no answer. This is what keeps the
///   server out of "open resolver" classifications: scanners only flag servers
///   that return NOERROR+ANCOUNT>0 for names the server isn't authoritative for.
/// - Unparsable packets are silently dropped.
pub async fn serve(listen: SocketAddr, nodes: Arc<RwLock<Vec<Ipv4Addr>>>, ttl: u32, zone: String) {
    let sock = UdpSocket::bind(listen).await.expect("DNS: failed to bind UDP socket");
    eprintln!("DNS server listening on {listen} (zone={zone})");

    let zone = normalize_name(&zone);
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
        if let Some(response) = build_response(&buf[..len], &good, ttl, &zone)
            && let Err(e) = sock.send_to(&response, peer).await
        {
            eprintln!("DNS send error: {e}");
        }
    }
}

/// Lowercase, strip trailing dot. Used to normalize both the configured zone
/// and the QNAME extracted from the query for case-insensitive comparison.
fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Parse a DNS query and build the appropriate response.
/// Returns None for unparsable packets (silent drop).
fn build_response(query: &[u8], nodes: &[Ipv4Addr], ttl: u32, zone: &str) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let id = [query[0], query[1]];
    // RD bit is bit 0 of query byte 2 (flags high byte) — echoed back per convention
    let rd_flag = query[2] & 0x01;
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse QNAME into a normalized string. Compression pointers in the
    // question section are RFC-1035 illegal, but we tolerate them by ending
    // the name early and falling through to REFUSED (the partial name won't
    // match the zone).
    let mut pos = 12usize;
    let mut qname = String::new();
    let mut compressed = false;
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
            // Compression pointer — uncommon in the question section. End QNAME.
            if pos + 2 > query.len() {
                return None;
            }
            pos += 2;
            compressed = true;
            break;
        }
        if label_len > 63 {
            return None; // RFC 1035 §2.3.4 — labels are at most 63 octets
        }
        if pos + 1 + label_len > query.len() {
            return None;
        }
        let label = &query[pos + 1..pos + 1 + label_len];
        if !qname.is_empty() {
            qname.push('.');
        }
        for &b in label {
            qname.push(b.to_ascii_lowercase() as char);
        }
        pos += 1 + label_len;
    }
    if pos + 4 > query.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
    // QNAME + QTYPE(2) + QCLASS(2) — echoed back verbatim in the response
    let question = &query[12..pos + 4];

    let is_zone_match = !compressed && qname == zone;
    let answer_a = is_zone_match && qtype == QTYPE_A;

    if answer_a {
        Some(build_answer_response(id, rd_flag, question, &select_nodes(nodes), ttl))
    } else {
        Some(build_refused_response(id, rd_flag, question))
    }
}

/// Authoritative positive response: AA=1, RCODE=NOERROR, A records in the answer section.
fn build_answer_response(id: [u8; 2], rd_flag: u8, question: &[u8], nodes: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
    let ancount = nodes.len() as u16;
    let mut resp = Vec::with_capacity(12 + question.len() + nodes.len() * 16);

    // Header: id, flags, counts
    resp.extend_from_slice(&id);
    // Flags byte 2: QR=1 | Opcode=0 | AA=1 | TC=0 | RD=echo
    resp.push(0x84 | rd_flag);
    // Flags byte 3: RA=0 | Z=0 | RCODE=NOERROR
    resp.push(RCODE_NOERROR);
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question (echoed)
    resp.extend_from_slice(question);

    // A record answers — name pointer to question's QNAME offset (12)
    for ip in nodes {
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&QTYPE_A.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&ttl.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&ip.octets());
    }

    resp
}

/// Negative response: AA=0, RCODE=REFUSED, no answer. ~17 bytes + question
/// echo — no amplification, can't be classified as open resolver.
fn build_refused_response(id: [u8; 2], rd_flag: u8, question: &[u8]) -> Vec<u8> {
    let mut resp = Vec::with_capacity(12 + question.len());

    resp.extend_from_slice(&id);
    // Flags byte 2: QR=1 | Opcode=0 | AA=0 | TC=0 | RD=echo
    resp.push(0x80 | rd_flag);
    // Flags byte 3: RA=0 | Z=0 | RCODE=REFUSED
    resp.push(RCODE_REFUSED);
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question echoed back per convention (RFC 1035 §4.1.2)
    resp.extend_from_slice(question);

    resp
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for testing.
    fn make_query(qname: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        // Header: id=0x1234, flags=0x0100 (RD=1, standard query), QDCOUNT=1
        q.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in qname.split('.') {
            assert!(label.len() <= 63);
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0x00);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        q
    }

    fn parse_flags(resp: &[u8]) -> (bool, bool, u8) {
        let qr = (resp[2] & 0x80) != 0;
        let aa = (resp[2] & 0x04) != 0;
        let rcode = resp[3] & 0x0F;
        (qr, aa, rcode)
    }

    fn parse_counts(resp: &[u8]) -> (u16, u16) {
        let qd = u16::from_be_bytes([resp[4], resp[5]]);
        let an = u16::from_be_bytes([resp[6], resp[7]]);
        (qd, an)
    }

    const ZONE: &str = "testnet-seed.sophis.org";

    #[test]
    fn zone_match_returns_a_records_with_aa() {
        let nodes = vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)];
        let query = make_query(ZONE, QTYPE_A);
        let resp = build_response(&query, &nodes, 30, ZONE).expect("response");

        let (qr, aa, rcode) = parse_flags(&resp);
        let (qd, an) = parse_counts(&resp);

        assert!(qr);
        assert!(aa, "AA bit must be set for authoritative answer");
        assert_eq!(rcode, RCODE_NOERROR);
        assert_eq!(qd, 1);
        assert_eq!(an, 2);
        assert_eq!(&resp[0..2], &[0x12, 0x34], "ID echoed");
    }

    #[test]
    fn non_zone_name_returns_refused() {
        let nodes = vec![Ipv4Addr::new(1, 2, 3, 4)];
        let query = make_query("google.com", QTYPE_A);
        let resp = build_response(&query, &nodes, 30, ZONE).expect("response");

        let (qr, aa, rcode) = parse_flags(&resp);
        let (_qd, an) = parse_counts(&resp);

        assert!(qr);
        assert!(!aa, "AA must NOT be set for refused query");
        assert_eq!(rcode, RCODE_REFUSED);
        assert_eq!(an, 0);
    }

    #[test]
    fn zone_match_is_case_insensitive() {
        let nodes = vec![Ipv4Addr::new(9, 9, 9, 9)];
        let query = make_query("TESTNET-SEED.SOPHIS.ORG", QTYPE_A);
        let resp = build_response(&query, &nodes, 30, ZONE).expect("response");

        let (_qr, aa, rcode) = parse_flags(&resp);
        let (_qd, an) = parse_counts(&resp);

        assert!(aa);
        assert_eq!(rcode, RCODE_NOERROR);
        assert_eq!(an, 1);
    }

    #[test]
    fn non_a_qtype_returns_refused_even_for_zone() {
        let nodes = vec![Ipv4Addr::new(1, 2, 3, 4)];
        let mut query = make_query(ZONE, 16); // TXT
        query[2] = 0x00; // also exercise rd_flag=0 path
        let resp = build_response(&query, &nodes, 30, ZONE).expect("response");

        let (_qr, aa, rcode) = parse_flags(&resp);
        assert!(!aa);
        assert_eq!(rcode, RCODE_REFUSED);
    }

    #[test]
    fn malformed_short_query_returns_none() {
        let short = vec![0u8; 10];
        assert!(build_response(&short, &[], 30, ZONE).is_none());
    }

    #[test]
    fn qdcount_zero_returns_none() {
        let mut query = make_query(ZONE, QTYPE_A);
        query[4] = 0;
        query[5] = 0;
        assert!(build_response(&query, &[], 30, ZONE).is_none());
    }

    #[test]
    fn truncated_label_returns_none() {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        q.push(0x0A);
        q.extend_from_slice(b"ab");
        assert!(build_response(&q, &[], 30, ZONE).is_none());
    }

    #[test]
    fn oversized_label_returns_none() {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        q.push(64);
        q.extend(std::iter::repeat_n(b'a', 64));
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        assert!(build_response(&q, &[], 30, ZONE).is_none());
    }

    #[test]
    fn compression_pointer_in_question_falls_through_to_refused() {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        q.push(0xC0);
        q.push(0x0C);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let resp = build_response(&q, &[], 30, ZONE).expect("response");
        let (_qr, aa, rcode) = parse_flags(&resp);
        assert!(!aa);
        assert_eq!(rcode, RCODE_REFUSED);
    }

    #[test]
    fn zone_arg_normalization_strips_trailing_dot() {
        let z1 = normalize_name("Testnet-Seed.Sophis.Org.");
        let z2 = normalize_name("testnet-seed.sophis.org");
        assert_eq!(z1, z2);
        assert_eq!(z1, "testnet-seed.sophis.org");
    }

    #[test]
    fn empty_node_list_returns_zero_answers_for_zone_query() {
        let query = make_query(ZONE, QTYPE_A);
        let resp = build_response(&query, &[], 30, ZONE).expect("response");
        let (_qr, aa, rcode) = parse_flags(&resp);
        let (_qd, an) = parse_counts(&resp);
        assert!(aa);
        assert_eq!(rcode, RCODE_NOERROR);
        assert_eq!(an, 0);
    }
}
