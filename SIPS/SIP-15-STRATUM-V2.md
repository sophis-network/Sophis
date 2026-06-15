```
SIP: 15
Title: Stratum V2 Adaptation for Sophis (RandomX + Dilithium Coinbase)
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-12
```

# SIP-15: Stratum V2 Adaptation for Sophis (RandomX + Dilithium Coinbase)

## 1. Abstract

This SIP defines a **Stratum V2-compatible mining-coordination protocol** for Sophis, adapting the Bitcoin Stratum V2 specification (initiated by Braiins in 2019; IETF-track since 2021) to Sophis's RandomX proof-of-work and Dilithium coinbase signing. Stratum V2 governs the message exchange between miners (hashers) and pool operators (block-template producers / share validators / payout administrators); SIP-15 specifies the Sophis-specific deviations from the canonical V2 spec, principally around job description, share format, and coinbase handling. **This SIP is forward-looking and gated on community demand**: the Sophis core team does not operate any mining pool (see `OPERATIONAL_BOUNDARIES.md` §6 Decision 6), and SIP-15 is published so that independent pool operators who emerge in the Sophis ecosystem have a single specification to implement instead of inventing one-off protocols.

## 2. Motivation

Solo mining is the cleanest mining mode — a miner runs `sophisd` + `sophis-miner` directly, finds a block, and the reward goes to the address they configured. No pool, no protocol, no coordination. The Sophis reference miner supports this fully.

Pool mining exists as a practical answer to one problem: variance. A solo miner with 0.1% of network hashrate, even at perfect efficiency, finds a block on average once every ~1000 blocks. At 10 BPS, that is ~16 minutes of expected variance, but the actual distribution has a heavy tail (~50% of solo miners at this hashrate go > 1 hour between blocks; 5% go > 4 hours). For miners who depend on mining income for operational cost coverage, this variance is operationally unworkable.

Pool mining smooths variance: many miners contribute shares (partial proofs of work) to a pool; the pool finds blocks at the aggregate hashrate and distributes the reward proportionally. Variance drops by orders of magnitude.

Three pool-protocol choices exist:

| Protocol | Status | Pros | Cons |
|---|---|---|---|
| **Stratum V1** (Bitcoin, 2012) | Universal in mining today | Simple, battle-tested | No transport encryption, miner cannot validate template, attack-prone |
| **Stratum V2** (Braiins, 2019; IETF-track 2024) | Adopted by Braiins Pool, Foundry, others | Noise protocol encryption, header coverage (miner can validate templates), reduced trust in pool | More complex to implement, not yet universal |
| **P2Pool** (decentralized, ~2011) | Niche; ~0.1% of Bitcoin hashrate | Pool is itself a P2P sidechain — no central operator | High complexity, share-chain reorgs, niche |

For Sophis the choice is Stratum V2:

- Mining is CPU-friendly (RandomX), so the miner pool of potential participants is larger than Bitcoin's ASIC-dominated pool. More small miners = greater attack surface for hostile pool operators. V2's encryption and template validation matter.
- Sophis is post-quantum at consensus. The coinbase is signed with Dilithium ML-DSA-44, not secp256k1 / Schnorr. V1's coinbase format does not accommodate Dilithium's 2.4 KB signatures cleanly; V2 already supports variable-length coinbase, requiring only field-format adjustments.

This SIP specifies the Sophis-specific deviations from Stratum V2. **It does not duplicate the canonical V2 spec.** Implementers should read Braiins's V2 documentation first; SIP-15 is the diff.

## 3. Specification

### 3.1 Inherited from canonical Stratum V2

The following Stratum V2 mechanisms apply to Sophis unchanged:

- **Transport encryption** via Noise Protocol (NX handshake).
- **Connection types**: Mining Connection, Job Negotiation Connection, Template Distribution Connection, Job Distribution Connection.
- **Message framing** and binary message encoding.
- **Channel management** (extended/standard channels, group channels).
- **Difficulty management** (`SetNewPrevHash`, `SetTarget`).
- **Share validation** semantics (a "share" is a partial proof of work below pool difficulty but possibly above network difficulty).
- **Negotiation**: clients and servers negotiate version, supported flags, and channel parameters at handshake time.

### 3.2 Sophis-specific deviations

#### 3.2.1 PoW algorithm — RandomX (not SHA-256d)

Stratum V2 was specified for Bitcoin's SHA-256d. Sophis uses **RandomX** (memory-hard, CPU-friendly, anti-ASIC). The implications:

- **Pool difficulty unit** is the RandomX target, encoded as a 32-byte big-endian integer.
- **Header-hashing path** uses the standard RandomX program: dataset key = first 8 bytes of the seed hash (epoch-derived); input = serialized block header.
- **Verification by the pool** of a submitted share requires running the RandomX verifier on the share's full header. The pool MAY operate in light-mode RandomX (slower, ~256 MB dataset) for verification; miners typically use fast-mode (faster, ~2 GB dataset).
- The Stratum V2 message `SubmitShares` carries the full block header (or the deviation from the assigned template, depending on channel type) so the pool can reconstruct the input to the RandomX verification.

#### 3.2.2 Coinbase format — Dilithium signature

Sophis coinbases include a `ScriptPublicKey` with version `2` (Dilithium P2SH). The coinbase outputs 100% of the block reward to a single Dilithium-derived address. For pool mining:

- The **pool** configures the coinbase output to the pool's payout address; per-miner accounting is the pool's internal concern.
- The **miner** is informed of the coinbase structure via the Stratum V2 template message and verifies that the coinbase encodes a fair-share output to their configured payout address.

#### 3.2.3 Block template construction

In Stratum V2, the miner (in some channel types) can construct or modify the block template. For Sophis:

- The block header layout is Sophis's (RandomX nonce, blue-score-derived fields, GHOSTDAG parents, Dilithium-friendly merkle root).
- The merkle root construction follows Sophis's BlockHasher rules (see consensus/core).
- The miner constructing or validating a template MUST be aware that GHOSTDAG parent selection is the chain's job, not the miner's. Templates received from the pool include the pool's chosen parent set; the miner SHOULD validate the parent set against their own sophisd if running a node, but is not required to.

### 3.3 Operational boundaries

The Sophis core team operates **no pool**. This SIP is published so that independent operators have a specification to implement; the specification itself does not constitute, nor imply, operation.

Pool operators implementing SIP-15 are independent third parties. The Sophis Project:

- Does **not** maintain a list of "approved" pools.
- Does **not** offer Stratum V2 endpoint hosting.
- Does **not** endorse any specific pool implementation.
- Does **not** mediate disputes between miners and pool operators.

Per `OPERATIONAL_BOUNDARIES.md` §6 (Decision 6 of the 2026-05-04 regulatory pivot), running a custodial mining pool would constitute money transmission under FATF / MiCA / FinCEN / BCB rules and is permanently outside the team's posture.

## 4. Rationale

### 4.1 Why Stratum V2 over V1

Stratum V1 has three structural weaknesses for Sophis specifically:

1. **No transport encryption.** ISP-level adversaries can read pool↔miner traffic, learning miner hashrate and pool affiliation. V2's Noise protocol fixes this.
2. **No template validation.** V1 miners receive job parameters but cannot verify that the resulting block, if found, pays them correctly. V2 provides header-coverage messages letting the miner reconstruct and verify the entire block.
3. **Variable-length coinbase is awkward.** V1 was designed around Bitcoin's small coinbase scripts. Dilithium's 2.4 KB signatures sit better in V2's binary message format.

V2 has been in production at Braiins Pool, Foundry, and others since 2021. Adopting V2 lets Sophis pool operators reuse existing Stratum V2 libraries instead of writing wire protocols from scratch.

### 4.2 Why not P2Pool

P2Pool is a decentralized pool (a P2P network of miners that itself forms a sidechain of share commitments). It eliminates the central operator entirely. The downsides:

- High implementation complexity (each pool node is a full sidechain client).
- Share-chain reorgs introduce variance back into miner income.
- Niche: ~0.1% of Bitcoin hashrate after a decade.

P2Pool is not rejected by this SIP — an independent operator could publish a Sophis-P2Pool spec as a future SIP. SIP-15 covers Stratum V2 because it is the dominant non-custodial pool protocol in active development and has clear upgrade paths from existing V1 deployments.

### 4.3 Why "forward-looking" status

As of this SIP's submission, no Sophis pool operates yet. Pool emergence depends on Sophis hashrate growing to a level where solo-mining variance is operationally painful for a meaningful fraction of miners. At 10 BPS and small-network early-mainnet hashrate, this threshold may be months or years away.

Publishing SIP-15 now lets future pool operators (whenever they emerge) implement a single spec rather than inventing one-offs. The cost of premature publication is zero; the cost of delayed publication is fragmented protocols when pools eventually launch.

Per SIP-0 §5, SIP-15 remains in **Draft** until at least one production pool implementation exists.

## 5. Backwards Compatibility

**Fully backwards compatible.** This SIP does not modify the Sophis protocol, consensus rules, RPC schema, or block format. It defines an off-chain coordination protocol between miners and pool operators.

Solo miners (using `sophis-miner` directly, no pool) are unaffected. Existing Sophis tooling continues to function unchanged.

Pool operators implementing SIP-15 produce blocks that look identical on-chain to solo-mined blocks; consensus validation is unchanged.

## 6. Reference Implementation

**No reference implementation exists.** Per SIP-0 §5, SIP-15 cannot enter Review until a reference Stratum V2 implementation exists for Sophis. The reference implementation would adapt an existing V2 codebase (the Braiins V2 reference implementation in Rust is a candidate) to Sophis's RandomX + Dilithium specifics.

Implementation effort is estimated at 4–8 weeks for one experienced developer, plus security review. It is **not** on the Sophis core team's roadmap; the team's `OPERATIONAL_BOUNDARIES.md` posture excludes operating mining infrastructure.

## 7. Security Considerations

### 7.1 Threat model

- **Hostile pool operator.** Pool changes the coinbase to pay only itself, ignoring the miner's declared payout address. **Defense:** V2's header-coverage messages let the miner reconstruct the block and validate the coinbase. If the coinbase disagrees with the negotiated payout address, the miner refuses to submit valid shares and disconnects. This shifts the trust model from "miner trusts pool" to "miner verifies pool's templates".
- **Pool steals shares.** Pool credits the miner less than their fair contribution. **Defense:** out of scope for the protocol — this is a payout-accounting issue that requires either trust in the pool or a P2Pool-style sidechain. SIP-15 does not solve it; miners SHOULD choose pools with reputational track records.
- **Pool runs invalid templates.** Pool serves templates that, if mined, would produce blocks rejected by Sophis consensus (e.g., wrong difficulty target, invalid Dilithium signature on coinbase). **Defense:** miners running a local `sophisd` node SHOULD validate templates against the node before mining; this is the highest-trust mode.
- **Eavesdropping.** Network-level adversary observes pool↔miner traffic. **Defense:** V2's Noise protocol encryption.
- **MITM at handshake.** Adversary intercepts the initial Noise handshake. **Defense:** miners SHOULD pin pool public keys on first observation (TOFU) or use out-of-band key distribution.
### 7.2 Cryptographic assumptions

- Noise NX is secure for transport encryption (standard cryptographic assumption).
- Dilithium ML-DSA-44 is unforgeable (same assumption as the consensus layer).
- RandomX produces unforgeable proofs of work (same assumption as the consensus layer).
- This SIP introduces no new cryptographic assumptions beyond what Stratum V2 and Sophis consensus already rely on.

### 7.3 Privacy implications

Joining a pool reveals the miner's hashrate and IP to the pool operator. This is intrinsic to pool mining and not specific to SIP-15. Privacy-sensitive miners SHOULD use solo mining or anonymizing transports (Tor) for the pool connection.

### 7.4 Impact on Sophis subsystems

- **Long-range attack resistance:** none — pool mining produces blocks indistinguishable on-chain from solo-mined blocks.
- **Reorg behaviour:** unaffected. A pool's blocks compete in GHOSTDAG identically to any other miner's.
- **Mempool policy:** unaffected.
- **Coinbase maturity:** unaffected. Pool-mined coinbase outputs are subject to the same 100-block maturity (mainnet) as solo-mined.
- **Light-client / SPV verifiability:** unaffected.
- **Long-range / 5%-cap commitment:** if the founder mines via a pool (allowed per `FOUNDER_SELF_RESTRICTION.md`, which prohibits operating a pool but not participating in one), the cap-monitoring script reads the founder's pool-paid address and behaves identically to solo mining. The cap is on the on-chain balance, not on the mining mode.

## 8. Test Vectors

Test vectors will accompany the reference implementation. The initial set MUST include:

- A reference `SophisPayoutPolicy` message round-tripped through binary encoding.
- A canonical RandomX share-submission message and the corresponding pool-side verification.
- A coinbase reconstruction test: given a template and a miner's payout policy, the miner reconstructs the exact coinbase bytes and verifies the resulting block-hash chain.

Concrete vectors are out of scope for SIP-15 Draft status; they accompany the reference implementation when one materializes.

## 9. References

- Stratum V2 specification (Braiins, https://stratumprotocol.org/) — canonical Stratum V2 documentation
- Stratum V1 specification (informal, Bitcoin Wiki) — predecessor protocol
- Noise Protocol Framework (https://noiseprotocol.org/) — transport encryption
- RandomX specification (https://github.com/tevador/RandomX) — Sophis's proof-of-work
- NIST FIPS 204 — Dilithium ML-DSA (signature for coinbase)
- P2Pool (https://github.com/p2pool/p2pool) — alternative decentralized pool architecture; out of scope here but referenced as prior art
- `OPERATIONAL_BOUNDARIES.md` §6 — binding constraint that the core team does not operate any pool
- `FOUNDER_SELF_RESTRICTION.md` §2 — founder may mine solo or via a third-party pool, but never via a team-operated pool
- Whitepaper §5.6 — coinbase allocation policy (100% to miner; voluntary redirection removed pre-launch)

## 10. Copyright

This SIP is released into the public domain (CC0).
