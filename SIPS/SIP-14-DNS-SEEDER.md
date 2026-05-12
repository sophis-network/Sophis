```
SIP: 14
Title: DNS Seeder Protocol for Sophis Peer Discovery
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-12
```

# SIP-14: DNS Seeder Protocol for Sophis Peer Discovery

## 1. Abstract

This SIP defines a **DNS-based peer-discovery protocol** for Sophis nodes. A DNS seeder is an independent operator that crawls the Sophis P2P network, validates which peers are responsive and serving the correct network/protocol version, and exposes a deterministically-formatted DNS zone (A, AAAA, and TXT records) that fresh nodes query at bootstrap. The protocol is **off-chain and decentralizable**: multiple seeders may operate in parallel, each producing compatible records under their own domains; clients sample across seeders to avoid trust in any single operator. The protocol is the same shape Bitcoin Core has used since 2010, formalized here so that independent Sophis seeders can interoperate without coordination.

## 2. Motivation

A freshly installed Sophis node has no peers in its local address book. The bootstrap problem is "how does this node find any other node?". Three solutions exist:

1. **Hard-coded seed IPs in the client binary.** Fragile (IPs change), centralizing (the binary author chooses), and a censorship vector (one operator blocked = whole bootstrap path blocked for clients that only know that one).
2. **Out-of-band discovery** (Telegram, IRC, peer-shared address books). Works but does not scale and requires the user to already know someone in the network.
3. **DNS-based seeding.** The client queries `seed.<some-domain>` and receives a list of A/AAAA records of currently-active peers. Multiple independent domains may serve this role; the client samples across them.

Bitcoin Core has used DNS seeding since 2010, with five independent seeders (`seed.bitcoin.sipa.be`, `dnsseed.bluematt.me`, `dnsseed.bitcoin.dashjr.org`, etc.) maintained by different operators. The protocol is documented informally; no formal BIP exists. This SIP formalizes the equivalent for Sophis so that anyone wishing to run a Sophis DNS seeder can produce records compatible with anyone wishing to consume them.

Concretely, the protocol must address:

- **Format of the served records.** A client must know what `A`, `AAAA`, and `TXT` records mean in the Sophis context.
- **Refresh cadence.** Stale records cause repeated bootstrap failures.
- **Validation contract** — what the seeder operator must guarantee about the peers it serves.
- **Operational expectations** — what the operator must NOT do (e.g., return their own node as the only peer, return offline peers as a denial-of-service).
- **Client behavior** — how clients sample across multiple seeders and detect a hostile or broken seeder.

This SIP defines all five.

## 3. Specification

### 3.1 Canonical names

The Sophis reference convention reserves the following subdomains under any seeder operator's domain:

| Name | Network |
|---|---|
| `seed.<operator-domain>` | Mainnet |
| `seed-testnet.<operator-domain>` | Testnet |
| `seed-devnet.<operator-domain>` | Devnet (local-only; rarely served publicly) |

Operators MAY publish under additional subdomains for testing or staging (e.g., `seed-staging.<domain>`), but clients MUST NOT consume those by default.

The reference Sophis operator (`sophis-network`) is expected to publish `seed.sophis.org`, `seed-testnet.sophis.org`. Independent operators publish under their own domains (`seed.<their-domain>`).

### 3.2 A and AAAA records

The seeder serves A (IPv4) and AAAA (IPv6) records pointing to the IP addresses of currently-active Sophis peers on the operator's curated list. Each record:

- MUST point to a peer that the seeder has verified within the last 6 hours (see §3.5).
- MUST be a peer running the canonical P2P protocol on the **default port** for the network (mainnet: 46111, testnet: 46211).
- MUST be served with a TTL ≤ 300 seconds. Lower TTLs reduce stale-record exposure; higher TTLs increase cache churn at recursive resolvers.

Multiple A/AAAA records SHOULD be returned per query. The recommended cardinality is 10–25 records per query (large enough that clients have diversity; small enough to fit in a typical DNS response without truncation).

Operators MAY use DNS-level randomization (different subset returned on each query) to spread load across the peer list. Clients MUST handle the case where consecutive queries return non-overlapping IP sets.

### 3.3 TXT records

The seeder MUST publish a single TXT record at the same name as the A/AAAA records, containing metadata about the seeder operator. The format is `key1=value1;key2=value2;...`, ASCII-only, max 255 chars (DNS TXT-record limit):

```
v=sophis-seed-1;network=mainnet;ops=sophis-network;contact=email:sophis-network@proton.me;refresh=6h
```

| Key | Required | Value semantics |
|---|---|---|
| `v` | yes | Protocol version. v1 of this SIP is `sophis-seed-1` |
| `network` | yes | `mainnet`, `testnet`, `devnet`, or `simnet` |
| `ops` | yes | Operator identifier (free-form short string; should match the publishing entity's known identity) |
| `contact` | no | One contact method, prefixed by scheme (`email:`, `https:`, `xmpp:`, etc.). Used for abuse reports and coordination |
| `refresh` | no | Author-claimed refresh cadence (e.g., `1h`, `6h`, `24h`). Advisory; clients SHOULD NOT enforce |

If a TXT record is missing, malformed, or has `v` not equal to `sophis-seed-1`, clients MUST treat the seeder as unrecognized and skip it.

### 3.4 Peer validation by the seeder

Before serving a peer's IP in the next zone refresh, the seeder MUST have, within the last 6 hours:

1. Successfully established a P2P connection to that peer on the default port.
2. Received the peer's `Version` handshake message.
3. Validated that the peer's reported network ID matches the seeder's served network (a mainnet seeder MUST NOT serve testnet peers and vice versa).
4. Optionally: validated that the peer reports a recent virtual selected tip (within the last 30 minutes of the seeder's own tip). This reduces serving forked-out or stalled nodes.

Peers that fail any of these checks MUST be removed from the served set on the next refresh.

### 3.5 Refresh cadence

The seeder MUST refresh its peer list at least every 6 hours. Faster refresh (1–2 hours) is encouraged for high-traffic operators. The published TXT `refresh` value should match the actual cadence.

If the seeder's crawl is broken or its node is desynchronized, the operator MUST stop serving A/AAAA records (return NXDOMAIN or an empty response) rather than serve stale data. Returning known-stale records harms clients more than returning none.

### 3.6 Client behavior

A Sophis client implementing this SIP performs bootstrap as follows:

1. Resolve `seed.<domain>` for each configured seeder domain. The reference client SHOULD ship with a default list of seeder domains; users MAY override.
2. For each seeder, fetch the TXT record and verify `v=sophis-seed-1` and `network` matches the client's configured network.
3. Fetch A and AAAA records; collect the union across all seeders.
4. Randomize the order; do not prefer any seeder's records (defeats sampling).
5. Connect to peers in the randomized order, opening up to N parallel connections (reference default N=8).
6. As soon as a quorum of peers (e.g., 4 of 8) successfully complete the P2P handshake and report consistent virtual selected tips, exit bootstrap and begin normal P2P operation.

The client MUST track per-seeder reliability over time. A seeder that consistently returns offline or invalid peers SHOULD be deprioritized; one that fails completely (no DNS response or NXDOMAIN) SHOULD be marked degraded but not permanently removed (it may recover).

### 3.7 Multi-seeder sampling

Clients SHOULD use **at least 3 distinct seeders** for bootstrap. Reasons:

- **Censorship resistance.** A single seeder operator could (deliberately or by compromise) return only peers under the operator's control, eclipsing the new node. Sampling across 3+ independent operators makes this attack impractical.
- **Availability.** Any single seeder may be temporarily down (operator hosting issue, DNS provider outage).
- **Diversity.** Different seeders may emphasize different geographic regions of the peer set; sampling gives the client a more uniform view.

The reference client ships a default seeder list (`seed.sophis.org` and any community-operated additions documented in a future revision of this SIP); operators of independent seeders SHOULD submit a PR to that default list once they have been running stably for ≥ 30 days.

### 3.8 No on-chain registry of seeders

There is intentionally no on-chain or core-team-curated authoritative list of valid seeders. The default-list in the reference client is a starting point, not an authoritative whitelist. Any operator MAY run a seeder under their own domain and inform users via off-chain channels (community forums, blog posts, social media). Clients MUST allow users to configure additional seeder domains via configuration.

This avoids reintroducing the curation surface that `HARD_FORK_POLICY.md` anti-rug invariants and the broader `OPERATIONAL_BOUNDARIES.md` posture reject.

## 4. Rationale

### 4.1 Why DNS, not hard-coded IPs

Hard-coded seed IPs in the client binary are the simplest possible bootstrap. They fail when:

- The IP is reassigned to a different host (the operator changes hosting).
- The IP is blocked at a network or ISP level (state-level censorship).
- The operator goes offline (a single binary-level IP is a single point of failure).

DNS adds one layer of indirection. The seeder operator updates their DNS records as needed; clients always get the current list. The DNS resolver itself is a more robust, more distributed system than any single IP.

### 4.2 Why TXT for metadata

The TXT record is the standard DNS mechanism for arbitrary metadata. It is preferable to inventing a custom record type (which would require client-side custom resolver code) or stuffing metadata into reverse DNS (which most operators cannot control).

The format `key=value;key=value;...` is the same shape SPF, DKIM, security.txt-via-DNS, and several other DNS-published-text-records use. It is well-understood by tooling.

### 4.3 Why 6 hours as the maximum staleness

Bitcoin DNS seeders typically refresh every 1–6 hours; 6 hours is the conservative upper bound. A peer that was alive 6 hours ago is highly likely to still be alive (most Sophis nodes are intended to run continuously). Faster refresh produces fresher data but more crawler load on the network.

### 4.4 Why multiple seeders, not one canonical

A single canonical seeder is a single point of trust and a single point of failure. Bitcoin learned this in 2010 (Satoshi-only `bitseed.xf2.org`) and migrated to multiple independent seeders by 2011. Sophis adopts the same posture from the start, with a default list that grows by community PR as new operators emerge.

### 4.5 Why the client must sample randomly

If a client always tries the first seeder's records first, that seeder becomes a censorship choke point: the seeder operator can engineer which peers the client tries first. Random sampling defeats this — the client equally likely tries any peer from any seeder.

## 5. Backwards Compatibility

**Fully backwards compatible.** This SIP does not modify the Sophis protocol, consensus rules, P2P wire format, RPC schema, or any on-chain semantics. It defines an off-chain bootstrap convention.

Nodes that do not implement DNS seeder consumption can still bootstrap via hard-coded peer lists or out-of-band discovery; their experience is unchanged.

Seeder operators today (the reference `sophis-network/sophis-dns` Cloudflare worker) MAY continue to serve their current records; the only change required by this SIP is publishing the TXT metadata record (which they may already do informally). Adoption is opt-in.

## 6. Reference Implementation

The reference seeder implementation is staged in [`sophis-network/sophis-dns`](https://github.com/sophis-network/sophis-dns). A Cloudflare worker reads from a curated peer list and serves A/AAAA + TXT records under `seed.sophis.org`.

The reference client implementation is part of `sophisd` itself. Bootstrap configuration lives in `sophisd/src/network.rs`; SIP-14 alignment may require adjusting the default seeder list and adding TXT record validation. This is implementation work for a follow-up PR, not blocking SIP-14 Draft acceptance.

This SIP is **spec-only** at the time of submission. Per SIP-0 §5, the SIP remains in Draft until at least two independent seeder operators are publishing SIP-14-compliant records and the reference client validates against the spec.

## 7. Security Considerations

### 7.1 Threat model

- **Hostile single seeder.** Operator returns only peers under their control, attempting to eclipse the new node. **Defense:** clients sample across ≥3 distinct seeders (§3.6, §3.7). Eclipse requires compromising the majority of the seeder pool, not just one.
- **Stale records.** Operator's crawler is broken; published records point to offline peers. **Defense:** operators MUST stop serving rather than serve stale data (§3.5). Clients detect via failed handshakes and try the next address.
- **DNS hijacking.** Attacker compromises the operator's DNS provider and serves arbitrary IPs. **Defense:** standard DNS hygiene (DNSSEC where available, CAA records, monitoring). Not specific to this SIP; same threat as any DNS-published service.
- **DDoS via DNS amplification.** Attacker uses the seeder's DNS as an amplifier. **Defense:** operator-side rate limiting and standard DNS hardening. Not a Sophis-specific concern.
- **Network ID mismatch.** Mainnet client receives testnet peer IPs and attempts to handshake. **Defense:** P2P version handshake check by the client; the misrouted handshake fails loudly. Also, the TXT `network` field allows the client to reject a mismatched seeder before even querying A records.
- **Sybil at the peer layer.** Many seeded peers are controlled by the same entity. **Defense:** out of scope for DNS seeding alone; this is a general P2P concern addressed elsewhere (geographic peer diversity, manual peer banning, etc.).

### 7.2 Privacy implications

DNS queries are observable to the recursive resolver. A user bootstrapping a Sophis node via this protocol discloses to their DNS resolver that they are running Sophis. This is similar to (and no worse than) the privacy posture of any chain that uses DNS seeding. Users wanting greater privacy SHOULD route DNS queries through DoH/DoT (DNS-over-HTTPS / DNS-over-TLS) or use Tor for bootstrap.

### 7.3 Cryptographic assumptions

None added by this SIP. DNS queries are not cryptographically signed in v1 (DNSSEC where deployed is helpful but optional). The Sophis P2P handshake itself authenticates peer identity at a layer above DNS, so a tampered DNS response only succeeds in directing the client to the wrong IPs — it does not let the attacker impersonate a Sophis node.

### 7.4 Impact on Sophis subsystems

- **Long-range attack resistance:** none — DNS seeding is bootstrap-time only, before any chain state is consumed. The client's `min_chain_work` check (post-handshake) still applies.
- **Reorg behaviour:** none.
- **Mempool policy:** none.
- **Light-client / SPV verifiability:** SPV clients use the same DNS seeding mechanism for bootstrap; their post-bootstrap validation is identical to full-node validation.
- **ZK-Rollup (Phase 3):** unaffected.
- **ZK-Oracle (Phase 5 / Phase 9):** unaffected. Oracle publishers connect to peers via the same bootstrap mechanism.
- **Data Availability (Phase 6):** unaffected.

## 8. Test Vectors

Test vectors for DNS record format and client validation:

- A reference TXT record string: `v=sophis-seed-1;network=mainnet;ops=sophis-network;contact=email:sophis-network@proton.me;refresh=6h` (must parse to the field map specified in §3.3).
- An invalid TXT record string (wrong `v`): `v=kaspa-seed-1;network=mainnet` — clients MUST reject.
- A boundary A record set: 25 IPs in a single response. Must fit in a 512-byte UDP DNS response or be served via TCP fallback (RFC 5966).

Concrete vectors will accompany the reference client implementation.

## 9. References

- Bitcoin Core DNS seed list (`https://github.com/bitcoin/bitcoin/blob/master/contrib/seeds/`) — prior art, informal
- IETF RFC 1035 — Domain Names: Implementation and Specification
- IETF RFC 5936 — DNS Zone Transfer Protocol (AXFR), relevant for seeders who serve large peer lists
- IETF RFC 5966 — DNS Transport over TCP
- IETF RFC 8484 — DNS Queries over HTTPS (DoH), for privacy-preserving bootstrap
- DNSSEC RFCs (4033, 4034, 4035) — optional cryptographic authentication of DNS responses
- [`sophis-network/sophis-dns`](https://github.com/sophis-network/sophis-dns) — reference seeder implementation
- SIP-7: Light Client SPV — SPV clients use this bootstrap mechanism

## 10. Copyright

This SIP is released into the public domain (CC0).
