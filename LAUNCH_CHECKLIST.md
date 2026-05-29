# Sophis — Mainnet Launch Checklist (T-72h to T+24h)

**Status:** v1, drafted 2026-05-06. Operational checklist binding the
5 defensive actions enumerated below to the public timeline of the
Sophis mainnet launch.

This checklist transforms the **24-hour founder restraint window** (the
gap between genesis and the founder's first hash, decided 2026-05-04)
from a passive symbolic gesture into a **contemporaneously auditable**
defensive posture. Each action lays down evidence in a different medium
(Git commit, on-chain dashboard, social posts, third-party witnesses)
so that adversarial regulatory analysis cannot dismiss the wait period
as "founder narrative".

The five actions are **orthogonal** to the 5% lifetime cap and to the
content of `FOUNDER_SELF_RESTRICTION.md`. The cap defends numerically;
this checklist defends **temporally** and **publicly**.

---

## Timeline overview

```
T-90d  ─── outreach to independent miners begins (Action 3 prep)
T-72h  ─── public mainnet announcement     (Actions 1, 5 publish)
T-0    ─── genesis block                   (Actions 2, 4 begin)
T+24h  ─── founder mining starts           (Actions 2, 4 continue)
T+30d  ─── checklist debriefing post       (lessons learned, if any)
```

---

## Action 1 — Mining address published with announcement (T-72h)

**What:** include the founder's single mining address in the public
T-72h mainnet announcement, with a Git commit hash + tag that pins
the publication to a verifiable timestamp.

**Address:** `sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r`

(Already declared in § 1 of `FOUNDER_SELF_RESTRICTION.md` and § 4 of
`MONETARY_POLICY.md`.)

**Evidence produced:** the announcement commit hash + tag, both
publicly verifiable on `sophis-network/Sophis` and reproducible by anyone.
Once T-0 happens, the address-to-coinbase mapping is on-chain — any
deviation from this declaration (e.g., founder mining to a different
address) is automatically falsified.

**Owner:** founder
**Status:** ⏳ pending (will execute at T-72h)

### 1.1 Pre-flight checks (do at T-90d)

- [ ] Confirm founder address private key is recoverable (test
      restore from paper backup in a tempdir using
      `dilithium-wallet restore`)
- [ ] Confirm `FOUNDER_SELF_RESTRICTION.md` § 1 still names the same
      address
- [ ] Confirm `MONETARY_POLICY.md` § 4 still names the same address
- [ ] Confirm SUCCESSION.md package contains the recovery info

### 1.2 Execution (at T-72h)

- [ ] Push final commit to `main` with mainnet announcement notes
- [ ] Tag with `v1.0.0-mainnet` (or whichever version stamp ships)
- [ ] Post the announcement (Twitter/X, GitHub Discussions, any
      relevant communities) with the commit hash + tag
- [ ] Compute and publish SHA-256 hashes of the **four canonical
      commitment docs**: `MONETARY_POLICY.md`,
      `FOUNDER_SELF_RESTRICTION.md`, `OPERATIONAL_BOUNDARIES.md`,
      `HARD_FORK_POLICY.md`. This file (`LAUNCH_CHECKLIST.md`) is
      intentionally **excluded** from the anchor: it is a mutable
      operational runbook whose content changes during the T-72h→T+24h
      window (items get checked off), so anchoring its hash would
      produce false drift and no governance value. Anchor only the
      binding commitment statements.

---

## Action 2 — Public dashboard live at T=0

**What:** stand up a public dashboard that, in real time during the
T-0 → T+24h window, shows:

- Network total hashrate
- Count of unique coinbase recipient addresses observed
- Founder share of recent hashrate (visibly **0%** during the
  restraint window)
- A persistent banner declaring "founder share = 0% during restraint
  window"

**Evidence produced:** on-chain auditable record of the founder's
zero participation during the window. Survives independent of the
dashboard host: anyone running their own full node sees the same
truth.

**Owner:** founder, or a community volunteer if identified pre-launch
**Status:** ⏳ pending (spec + deploy)

### 2.1 Implementation hints

- May reuse the block explorer view-only infrastructure
  (`OPERATIONAL_BOUNDARIES.md` § 3 permits this)
- Does NOT require the gRPC DA bindings (`6.4.b`) to function — the
  needed data is `getBlockDagInfo` + `getBlocks` + coinbase scanning
- A static HTML page that polls a public Sophis RPC endpoint via
  WASM-compiled wRPC is sufficient for v1; sophistication can grow
  later
- The dashboard should be **redundant**: ideally hosted on at least
  two providers (e.g., GitHub Pages + a self-hosted VPS), so a
  single take-down does not erase the evidence

### 2.2 Pre-flight (T-30d)

- [ ] Domain / subdomain reserved (`launch.sophis.org` or similar)
- [ ] Static page draft committed to `sophis-network/Sophis` for review
- [ ] Independent observer (e.g., one of the Action 3 miners) has
      tested the page against a devnet or testnet

### 2.3 Execution

- [ ] Dashboard goes live within 5 minutes of T-0
- [ ] Banner stays in place until T+24h
- [ ] Continues to be reachable post-window so the historical
      evidence does not disappear

---

## Action 3 — 3–5 independent miners invited (T-30 to T-7)

**What:** identify and invite 3 to 5 miners outside the founder's
direct circle to participate in the network from T-0. The invitation
is **not** a payment; payment would create a contractual relationship
and undermine "independent". The invitation may include:

- Technical assistance (helping them get `sophis-miner` running)
- Documentation tailored to their existing setup (e.g., XMRig
  operators have specific RandomX tuning experience)
- Mention in a launch acknowledgments post (after the fact)

**Evidence produced:** if even 3 independent miners show up at T-0,
the network is demonstrably "not solo founder". If the recruiting
fails, the **documented attempt** (e-mails, public posts, Discord
messages) itself becomes evidence of intent.

**Owner:** founder
**Status:** ⏳ pending (target list + outreach)

### 3.1 Target communities

- Monero / RandomX miner forums (e.g. `monero.stackexchange`, XMR
  subreddit, `getmonero.org` IRC)
- Brazilian crypto communities (Telegram, Discord, regional forums)
  — same time zone, lower communication friction
- General PoW enthusiasts (Bitcoin mining channels, although their
  RandomX experience is limited)
- Academic groups working on memory-hard PoW

### 3.2 Pre-flight (T-90 to T-30)

- [ ] Compile a list of 5–10 candidate miners
- [ ] Draft a standard invitation text (template)
- [ ] Send invitations
- [ ] Track responses (accept, decline, no-reply)

### 3.3 Documentation if recruiting falls short

If fewer than 3 confirmed independent miners agree:

- [ ] Save the outreach record (invitations sent, response counts,
      reasons for decline if any)
- [ ] Make the record public (or at least accessible to a
      regulatory audit) post-launch

The documented attempt is itself defensive evidence.

---

## Action 4 — Live-stream / chronograph thread (T-0 → T+24h)

**What:** a **contemporaneous public performance** of the 24-hour
restraint window. Options:

- Twitter/X thread with a visible 24h timer + hourly status updates
  (commits, node hashrate, dashboard screenshots)
- Brief live-stream (Twitch, YouTube, OBS to local recording) of
  the founder's terminal during the window — proves the founder
  is not running a hidden mining setup
- Screenshot snapshots posted hourly to `sophis-network/Sophis`
  Discussions

The format is the founder's choice; the constraint is that it be
**performed live** and **timestamped publicly** as it happens, not
narrated retroactively. Retroactive evidence is regulatorily weak.

**Evidence produced:** continuous public timeline that an adversarial
analyst would have to allege the founder "faked in real time on
multiple platforms simultaneously" — implausible.

**Owner:** founder
**Status:** ⏳ pending (decide format)

### 4.1 Pre-flight

- [ ] Pick the format: Twitter thread + screenshots, or live-stream,
      or both
- [ ] Decide what the hourly update contains (template)
- [ ] Test the streaming setup against a devnet (rehearsal at T-7d)

### 4.2 Execution

- [ ] Start at T=0 (genesis block)
- [ ] Maintain through T+24h continuously, no extended interruptions
      (>1h gap is a red flag)
- [ ] Capture and archive the entire stream / thread for the
      historical record

---

## Action 5 — Founder Self-Restriction Statement, hashed and pre-published (T-72h)

**What:** publish `FOUNDER_SELF_RESTRICTION.md` (already drafted in
this repository) and announce its **SHA-256 hash** in the T-72h
mainnet announcement. The hash binds the document content to the
announcement timestamp; any modification later changes the hash and
therefore breaks the link to that timestamp.

**Evidence produced:** the founder's commitments are pinned to a
moment that **precedes the chain itself**. They cannot be retroactively
softened to fit later behavior — any softening is publicly visible as
a hash mismatch.

**Owner:** founder
**Status:** ⏳ pending (SHA-256 to be computed on the final v1
commit, included in the T-72h announcement)

### 5.1 Pre-flight

- [ ] `FOUNDER_SELF_RESTRICTION.md` v1 frozen (no further edits
      pre-launch)
- [ ] Compute `sha256sum FOUNDER_SELF_RESTRICTION.md`
      (and similarly for `MONETARY_POLICY.md`,
      `OPERATIONAL_BOUNDARIES.md`, and `HARD_FORK_POLICY.md`).
      `LAUNCH_CHECKLIST.md` is intentionally excluded — see § 1.2.
- [ ] Commit a copy of the hashes to a separate file
      (`HASHES_T_72H.txt` or similar) to make the fingerprint
      publicly archive-friendly

### 5.2 Execution

- [ ] Hashes posted in the T-72h announcement, alongside the address
      (Action 1)
- [ ] Hashes mirrored to any third-party archive (e.g.,
      archive.org snapshot of the GitHub page)

---

## Why these 5 actions are sufficient

A typical adversarial argument against the 24-hour founder restraint
takes one of these forms:

| Argument | Defended by |
|---|---|
| "Founder changed the address afterward" | Action 1 (address is in the T-72h announcement, before T-0) + Action 5 (hash of the statement is older than the chain) |
| "Founder mined and lied about it" | Action 2 (on-chain dashboard) + Action 4 (live performance) |
| "Founder was the only miner so it didn't matter" | Action 3 (independent participants, or documented attempt) |
| "Founder invented the restraint narrative retrospectively" | Action 4 (contemporaneous public record) + Action 5 (hash anchored before T-0) |

Each action produces a **different kind of evidence**: cryptographic
(1, 5), on-chain auditable (2), socially independent (3), and
publicly contemporaneous (4). To dismantle the defense, an adversary
would need to dismantle all four media simultaneously — which is the
intended difficulty.

## Cost

The actions are nearly free in money (a domain, a VPS for the
dashboard, all under R$ 100 / month) but do require **disciplined
execution** during the T-90 → T+24h window. The biggest risk is
**under-execution under stress**: forgetting to publish hashes,
letting the dashboard lag, missing the live-stream window. The
checklist exists so the discipline is mechanical rather than
inspirational.

## Reference

- 5-action specification: this document itself (§§ 1-5 above)
- Founder address: declared in `FOUNDER_SELF_RESTRICTION.md` § 1
- Founder restrictions: `FOUNDER_SELF_RESTRICTION.md`
- Operational boundaries: `OPERATIONAL_BOUNDARIES.md`
- Monetary policy: `MONETARY_POLICY.md`
- Hard-fork policy: `HARD_FORK_POLICY.md`
- Cap-monitoring watchdog: `tools/sophis-cap-monitor/` (Rust binary)

---

**Document version:** v1, 2026-05-06
**Next scheduled review:** T-30d before mainnet (to confirm pre-flight
checkpoints) and T+30d post-launch (debrief)
