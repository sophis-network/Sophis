# Sophis ZK-Oracle relayer — operator runbook (sub-fase 5.5.c)

This document is the **operational source of truth** for someone running
a `sophis-oracle-relayer` instance on testnet or mainnet. Read it
end-to-end before deploying for the first time.

> **Pre-mainnet status (2026-05-05):** the relayer ships `MockSubmit` by
> default and falls back to it when built without `--features grpc-submit`.
> This runbook covers the full production path (`--features grpc-submit`).

---

## 1. Preflight checklist

Before installing, confirm:

- [ ] You have a Sophis L1 node (`sophisd`) reachable on a stable host:port.
- [ ] You have a Pythnet RPC endpoint with sufficient quota
      (recommended: dedicated paid endpoint, not a public one).
- [ ] You know the Pyth `PriceAccountV2` pubkey for the feed you want to
      relay AND the publisher pubkey you trust.
- [ ] You have at least 1 SPHS at the relayer's L1 address (each
      submission costs `INVOCATION_UTXO_VALUE + SUBMIT_TX_FEE = 51_000`
      sompi = 0.0051 SPHS; budget ≥1 month of operation).
- [ ] You know which Sophis network you're targeting (`mainnet` |
      `testnet` | `devnet` | `simnet`).

## 2. Installing

### 2.1 From source (recommended for v1)

```bash
git clone https://github.com/sophis-network/Sophis
cd Sophis
git checkout phase5-zk-oracle    # or a tagged release
cargo build --release -p sophis-oracle-relayer --features grpc-submit
# Binary at: target/release/sophis-oracle-relayer
```

> Build environment: see `CLAUDE.md` (Rust 1.94+, MSVC tools on Windows,
> LIBCLANG_PATH, protoc, cmake). Linux/Docker builds are simpler.

### 2.2 From a release artifact

(Future: `gh release` artifact, GPG-signed binary. Not available yet.)

## 3. Generating the relayer's Dilithium key

The relayer needs an ML-DSA-44 keypair (2560-byte SK + 1312-byte VK).
The same key signs both:

- The bundle commitment hash (cryptographic proof of relayer authorship)
- L1 fee tx inputs (covers the invocation tx fee)

### 3.1 Quick generation (dev/test)

```bash
# 1. Generate via dilithium-wallet (separate Sophis wallet binary).
target/release/dilithium-wallet keygen --out ./relayer.sk --vk-out ./relayer.sk.vk
# 2. Confirm the file sizes:
wc -c relayer.sk relayer.sk.vk
# Expected: 2560 relayer.sk, 1312 relayer.sk.vk
```

### 3.2 Air-gapped generation (mainnet recommended)

For mainnet, generate the keypair on an offline machine, transfer only
the `relayer.sk` + `relayer.sk.vk` files to the relayer host via
removable media, and **destroy the offline machine's RAM** (poweroff
before resuming network). The same `dilithium-wallet keygen` command
above works offline.

Backup `relayer.sk` and `relayer.sk.vk` to **at least two physical
locations** (paper backup of seed phrase if `dilithium-wallet` exposes
one — not yet documented for the relayer keypair specifically; for v1
treat the raw 2560 bytes as the canonical secret).

### 3.3 Permissions

```bash
chmod 0400 relayer.sk relayer.sk.vk
chown relayer:relayer relayer.sk relayer.sk.vk
```

## 4. Funding the relayer's L1 address

Derive the relayer's bech32m address from `relayer.sk.vk` and the
network prefix:

```bash
# (Helper TBD — for now use dilithium-wallet:)
target/release/dilithium-wallet address \
    --vk ./relayer.sk.vk \
    --network mainnet     # or testnet / devnet
# Output example: sophis:qx<58 chars>
```

Send at least 1 SPHS to this address from your funding wallet. Wait
for `coinbase_maturity` blocks (100 on mainnet, 20 on devnet) before
the first relayer run.

## 5. Writing the config

Save as `relayer.toml`:

```toml
[pythnet]
rpc_endpoint  = "https://pythnet.rpcpool.com"
price_account = "GVXRSBjFk6e6J3NbVPXohDJetcTjaeeuykUpbQF8UoMU"   # BTC/USD price account
publisher     = "5j5xK4U7yeC1RVH4MM7yAHzkhdJYuBjFFyMvmaq2HBXM"   # the publisher you trust

[feed]
id            = "BTC/USD"      # 1-8 ASCII bytes
min_price     = 1_000_00       # i64; $10.00 floor (exponent -8)
max_price     = 1_000_000_00   # i64; $10,000.00 ceiling (exponent -8)
max_age_secs  = 60             # reject witnesses older than this

[proving]
verify_air_companion = true    # ed25519 STARK companion (default true; set false to skip slower proof)

[signing]
key_path      = "/etc/sophis-oracle/relayer.sk"   # 2560-byte ML-DSA-44 SK
                                                  # sibling .vk MUST also exist

[submit]
grpc_endpoint    = "127.0.0.1:46110"              # sophisd gRPC
contract_address = "sophis:qx<oracle contract>"   # bech32m
state_path       = "/var/lib/sophis-oracle/relayer.state"
network_prefix   = "mainnet"                      # mainnet | testnet | devnet | simnet

[daemon]
interval_secs = 30
```

Validate the config without touching I/O:

```bash
sophis-oracle-relayer --config relayer.toml inspect
```

## 6. First run

```bash
# Smoke test (one update + exit):
sophis-oracle-relayer --config relayer.toml --log-level info relay-once
```

Expected log output (production path with `--features grpc-submit`):

```text
loaded config from relayer.toml
submit: GrpcSubmit (endpoint=127.0.0.1:46110, contract=sophis:qx..., prefix=mainnet)
iteration: next_seq=1, last_seq=0, now=1730000000
bundle ready: journal.price=65000000, oracle_proof_len=12345, va_proof=true
oracle invocation seq=1 submitted to L1 (txid=abcdef..., daa=12345)
submitted seq 1 as txid abcdef00..00000000
relay-once done: submitted sequence 1
```

If you see `submit: MockSubmit` instead, you forgot `--features grpc-submit`
at build time.

## 7. Daemon mode

Once `relay-once` succeeds, switch to long-running daemon:

```bash
sophis-oracle-relayer --config relayer.toml --log-level info daemon
```

The daemon:

1. Loads `state_path` (or starts from sequence 0 if missing).
2. Pulls Pyth → builds bundle → signs → submits, every `interval_secs`.
3. Persists `last_sequence=N` after every successful submit.
4. Logs WARN on iteration errors and **continues** (next iteration retries).
5. Logs ERROR + exits on persistence failure (avoids replay after restart).
6. Handles SIGINT / Ctrl-C gracefully (finishes current iteration, then exits).

### 7.1 Running under systemd (recommended)

`/etc/systemd/system/sophis-oracle-relayer.service`:

```ini
[Unit]
Description=Sophis ZK-Oracle relayer
After=network.target sophisd.service
Requires=sophisd.service

[Service]
Type=simple
User=relayer
ExecStart=/usr/local/bin/sophis-oracle-relayer \
    --config /etc/sophis-oracle/relayer.toml \
    --log-level info daemon
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now sophis-oracle-relayer
journalctl -fu sophis-oracle-relayer
```

## 8. Monitoring

The relayer logs structured key=value pairs the operator should monitor:

| Pattern | Meaning | Severity |
|---|---|---|
| `submitted seq N as txid <hex>` | Successful update | INFO (expected) |
| `iteration failed: <error> — continuing after sleep` | Transient error | WARN (investigate if persistent) |
| `failed to persist state after seq N` | Disk full / permissions / FS bug | ERROR (daemon exits) |
| `iteration took Nms — no sleep before next round` | Proving slower than `interval_secs` | WARN (raise `interval_secs`) |
| `gRPC connect to <endpoint>: <e>` | sophisd unreachable | WARN (auto-retries) |

Future: Prometheus exporter (out of v1 scope). For v1, use `journalctl`
+ alerting on `WARN`/`ERROR` patterns.

## 9. Troubleshooting

### 9.1 `no spendable UTXOs at relayer address`

Funding hasn't matured or the previous tx consumed all UTXOs without
change. Wait for a confirmation block and check:

```bash
# Replace with your address.
sophis-cli get_balance --address sophis:qx...
```

### 9.2 `fee UTXO too small: have N sompi, need 51000`

The relayer's largest UTXO is below the per-tx requirement (1 SPHS
locked + 50_000 sompi fee = 1.05 SPHS minimum per tx). Send more SPHS
to the relayer address.

### 9.3 `gRPC connect to 127.0.0.1:46110: <e>`

`sophisd` is down or not listening on the expected port. Check:

```bash
systemctl status sophisd
ss -tlnp | grep 46110
```

If sophisd uses a non-default port, update `[submit].grpc_endpoint` in
`relayer.toml`.

### 9.4 `transaction rejected by node: <reason>`

The submitted invocation tx failed mempool/consensus checks. Common
causes:

- `mass too high`: invocation script exceeded mempool's standard mass.
  Reduce `verify_air_companion` to false to skip the larger proof.
- `bad-signature`: relayer key file mismatch. Verify `relayer.sk.vk`
  matches the L1 address you funded.
- `duplicate sequence`: previous tx with same seq is in the mempool.
  Wait one interval and retry.

### 9.5 Daemon exits with `failed to persist state`

Disk is full or the state file's directory lost write permission. Check:

```bash
df -h /var/lib/sophis-oracle
ls -ld /var/lib/sophis-oracle
```

After fixing, restart. The daemon resumes from the last persisted
sequence (no replay risk).

### 9.6 Pyth feed seems stale even though the relayer is running

The Pythnet publisher you configured may have stopped publishing
(e.g. trading halt). Check the publisher's last `pub_slot`:

```bash
# Use a Solana RPC tool to inspect the price account.
solana account GVXRSBjFk6e6J3NbVPXohDJetcTjaeeuykUpbQF8UoMU --url $PYTHNET_RPC
```

Switch to a different publisher (update `[pythnet].publisher`) if the
configured one is dormant.

## 10. Key rotation

To rotate the relayer's keypair (recommended every 6 months for
mainnet, or immediately on suspected compromise):

1. Generate the new keypair on an air-gapped machine (§3.2).
2. Send the new VK's L1 address some funding (≥1 SPHS).
3. Stop the old daemon: `systemctl stop sophis-oracle-relayer`.
4. Move the new key files into place: `mv new_relayer.sk* /etc/sophis-oracle/`.
5. Start the daemon: `systemctl start sophis-oracle-relayer`.
6. Confirm the new VK is allow-listed in the on-chain contract (this
   step depends on the contract's allowlist API; see
   `CONTRACT_DISPATCH.md`).
7. After 24h of clean operation, drain the OLD relayer's residual
   UTXOs back to your funding wallet, then **destroy the old keypair**
   (shred + remove backups).

## 11. Cap rotation (founder-cap monitoring)

The Sophis founder commits to a 5% lifetime cap on accumulated mining
proceeds (see `DECISOES_2026-05-04.md` decision #3). The oracle
relayer is **separate** from this cap — its operating costs are
unrelated to founder mining. No cap-related action is required for
relayer operation.

## 12. Disaster recovery

| Scenario | Action |
|---|---|
| Host died, key files survived | Restore from backup, copy `.sk + .sk.vk + .state`, restart daemon — resumes from last persisted sequence |
| Host died, key files lost | Generate new keypair (§3), bootstrap as new relayer (§4), apply for allowlist in contract |
| Suspected key compromise | Stop daemon immediately, drain UTXOs, generate new keypair, request contract allowlist update |
| sophisd corrupt / re-syncing | Daemon will log `gRPC connect ...` WARN every interval; no action needed, will resume on its own |
| `relayer.state` file corrupted | Stop daemon, edit file by hand to set `last_sequence=N` to a known-safe value (the contract will reject if N is too low). Restart |

## 13. Migrating to a future relayer version

When v2 lands (currently hypothetical), follow the migration doc
(`MIGRATION.md`, TBD) which will cover:

- Wire format diffs (v1 → v2)
- Contract upgrade timing
- Backwards-compatible window (if any)
- Forced cutover deadline

For v1 → v1 patches (bug fixes), drop-in replace the binary; no config
or state changes required.

## Appendix A — File layout convention

```text
/usr/local/bin/sophis-oracle-relayer       # binary
/etc/sophis-oracle/relayer.toml            # config (mode 0640, owner relayer:relayer)
/etc/sophis-oracle/relayer.sk              # SK (mode 0400)
/etc/sophis-oracle/relayer.sk.vk           # VK (mode 0400)
/var/lib/sophis-oracle/relayer.state       # sequence persistence (mode 0600, owner relayer:relayer)
/var/log/sophis-oracle/                    # if not using journald
```

## Appendix B — Hardening recommendations

- Run `sophis-oracle-relayer` as an unprivileged user (`relayer`).
- Use `CapabilityBoundingSet=` and `NoNewPrivileges=true` in systemd
  unit if available.
- Mount `/etc/sophis-oracle/` with `noexec`.
- Keep `relayer.sk` outside any repo — never commit it.
- Restrict outbound network: only `pythnet.rpcpool.com:443` (HTTPS) and
  `sophisd:46110` (gRPC) need to be reachable.
- Backup `relayer.state` daily — losing it doesn't break operation but
  avoids confusing log gaps after a restart.
