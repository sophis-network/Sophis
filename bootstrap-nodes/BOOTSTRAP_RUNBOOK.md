# Bootstrap Nodes Runbook

Day-to-day operations for the two Sophis bootstrap nodes deployed on OCI
Always Free. Read [`OCI_SETUP_GUIDE.md`](OCI_SETUP_GUIDE.md) first if the
nodes don't exist yet.

## Quick reference

| Host                    | Region            | Roles                                        | Public ports     |
|-------------------------|-------------------|----------------------------------------------|------------------|
| `bootstrap1.sophis.org` | São Paulo         | mainnet P2P + testnet P2P + faucet           | 22, 80, 443, 46111(t/u), 46211(t/u) |
| `bootstrap2.sophis.org` | Ashburn           | mainnet P2P + testnet P2P                    | 22, 46111(t/u), 46211(t/u) |

## Daily check (1 minute)

```bash
for h in bootstrap1 bootstrap2; do
    echo "=== $h ==="
    ssh ubuntu@$h.sophis.org "systemctl is-active sophisd-mainnet sophisd-testnet"
done
curl -fsS https://faucet.sophis.org/status | jq '{balance_sphs, total_drips}'
```

Expected: 2× `active` from each host, faucet balance > 0.

## Common operations

### View logs

```bash
# Last 100 lines of mainnet log
ssh ubuntu@bootstrap1.sophis.org "sudo tail -100 /var/lib/sophis/mainnet/logs/sophisd.log"

# Live tail (Ctrl-C to exit)
ssh ubuntu@bootstrap1.sophis.org "sudo tail -f /var/lib/sophis/mainnet/logs/sophisd.log"

# systemd journal (captures crashes)
ssh ubuntu@bootstrap1.sophis.org "sudo journalctl -u sophisd-mainnet -n 50 --no-pager"
```

### Restart a service

```bash
ssh ubuntu@bootstrap1.sophis.org "sudo systemctl restart sophisd-mainnet"
# Or, if you suspect data corruption (rare — only after unclean shutdown):
ssh ubuntu@bootstrap1.sophis.org "sudo systemctl stop sophisd-mainnet && sleep 5 && sudo systemctl start sophisd-mainnet"
```

### Update sophisd to latest main

```bash
ssh ubuntu@bootstrap1.sophis.org
sudo systemctl stop sophisd-mainnet sophisd-testnet faucet
sudo -u sophis bash -lc '
  cd /var/lib/sophis/src && \
  git fetch origin && git checkout main && git pull --ff-only && \
  export LIBCLANG_PATH=$(llvm-config --libdir 2>/dev/null || echo /usr/lib/llvm-18/lib) && \
  export CARGO_BUILD_JOBS=2 && \
  ~/.cargo/bin/cargo build --release -p sophisd -p testnet-faucet -p dilithium-wallet
'
sudo install -m 0755 /var/lib/sophis/src/target/release/sophisd          /usr/local/bin/sophisd
sudo install -m 0755 /var/lib/sophis/src/target/release/testnet-faucet   /usr/local/bin/testnet-faucet
sudo install -m 0755 /var/lib/sophis/src/target/release/dilithium-wallet /usr/local/bin/dilithium-wallet
sudo systemctl start sophisd-mainnet sophisd-testnet faucet
sudo systemctl is-active sophisd-mainnet sophisd-testnet faucet
```

Incremental rebuilds take 5–10 minutes on Ampere A1.

### Add a new peer with `--addpeer`

If you want bootstraps to deterministically peer with a specific node
(use case: pre-DNS-seeder rollout, or pinning a known-good peer for
debugging), use `--addpeer`:

```bash
ssh root@bootstrap1.sophis.org
sudo sed -i "s|--utxoindex|--utxoindex --addpeer=<peer-ip>:46111|" \
    /etc/systemd/system/sophisd-mainnet.service
sudo systemctl daemon-reload
sudo systemctl restart sophisd-mainnet
```

> ⚠️ **Do NOT use `--connect=` for this.** `--connect` (inherited from
> the Kaspa CLI) puts sophisd in **client-only mode**: outbound connection
> to the named peer only, no inbound listener, no peer discovery.
> `systemctl is-active` will report `active` but `ss -tlnp` will show no
> LISTEN on the P2P port — external monitors will see it as DOWN.
> `--addpeer` pins the peer to the contact list AND keeps the listener
> + discovery alive — that's what you want for a public bootstrap.

This was used at first launch (2026-05-14) to pin node 2 → node 1
because no DNS seeders were live yet. Once roadmap item #2 (DNS
seeders) deploys, the `--addpeer` lines can be removed and peer
discovery becomes automatic.

### Reset a node's data (nuclear — keep the SSH keys, lose the chain)

```bash
ssh ubuntu@bootstrap1.sophis.org
sudo systemctl stop sophisd-mainnet
sudo rm -rf /var/lib/sophis/mainnet/data /var/lib/sophis/mainnet/logs
sudo install -d -o sophis -g sophis -m 0750 /var/lib/sophis/mainnet /var/lib/sophis/mainnet/logs
sudo systemctl start sophisd-mainnet
# Node will re-sync from peers (instant pre-mainnet, slow post-mainnet)
```

## Troubleshooting

### "Two nodes aren't peering"

```bash
# Check peer count on each
for h in bootstrap1 bootstrap2; do
    ssh ubuntu@$h.sophis.org \
        "sudo grep -c 'Connected to peer' /var/lib/sophis/mainnet/logs/sophisd.log"
done
```

If 0 peers on either side:

1. Confirm OCI Security List has 46111 TCP+UDP open
2. Confirm `ufw status` shows 46111 allowed
3. Test connectivity from one to the other:
   ```bash
   ssh ubuntu@bootstrap2.sophis.org "nc -zv bootstrap1.sophis.org 46111"
   ```
4. If connection refused, sophisd isn't listening — check `ss -tlnp | grep 46111`
5. If timeout, OCI Security List blocks — re-verify the ingress rules

### "Faucet says 503 'no spendable funds'"

The faucet wallet ran out. To refill:

```bash
ssh ubuntu@bootstrap1.sophis.org "sudo jq -r .address /var/lib/sophis-faucet/wallet.json"
# Send testnet SPHS to that address from a wallet that has them.
# Wait coinbase_maturity (1000 blocks ≈ 100 min on testnet) if funding via mining.
```

### "Build OOM'd on the VM"

Ampere A1 with 12GB usually doesn't OOM but rust+cmake can spike. Fix:

```bash
ssh ubuntu@bootstrap1.sophis.org
echo 'export CARGO_BUILD_JOBS=1' | sudo -u sophis tee -a /var/lib/sophis/.bashrc
# Re-run the build step from "Update sophisd to latest main" above
```

`CARGO_BUILD_JOBS=1` ≈ 60 min build (vs 30 min at 2). Worth it for stability.

### "Cloud-init failed halfway"

The instance is still usable but in an incomplete state. To re-run from where
it failed, the easiest path is to terminate the instance, fix the cloud-init
YAML, and create a fresh one (cheap on Always Free — same reserved IP). For
in-place recovery:

```bash
ssh ubuntu@<vm-ip>
sudo tail -200 /var/log/cloud-init-output.log    # find the failure
# Manually re-run the failed step from the YAML's runcmd list
```

### "OCI says 'Auto-reclaim warning'"

Means CPU + memory + network all dropped below the idle threshold for 7 days.
This should never happen with a running `sophisd`, but if it does:

1. SSH in and verify both services are actually running
2. Check the daily healthcheck log: `/var/log/sophis/healthcheck.log`
3. Restart any dead service

Reclaimed instances can be re-launched from the OCI console, but the boot
volume is gone. Re-running cloud-init recreates everything in ~45 min.

## Backups

Bootstrap nodes are **stateless** from an operational standpoint:

- Chain data: re-syncs from peers
- Faucet wallet: backed up separately (see below)
- SSH keys: stored on your workstation

**The only thing worth backing up** is `/var/lib/sophis-faucet/wallet.json`:

```bash
# On your workstation
ssh ubuntu@bootstrap1.sophis.org "sudo cat /var/lib/sophis-faucet/wallet.json" \
    > ~/backups/sophis-faucet-wallet-$(date +%F).json
chmod 600 ~/backups/sophis-faucet-wallet-*.json
```

Or print the mnemonic and put it on paper offline (same protocol as the
founder mining wallet — see `WALLET-PROCEDURE.md` in mainnet-mining/).

## Cost monitoring

OCI Always Free should stay at **$0/mo** but check monthly:

1. Console → **Billing → Cost Analysis**
2. Filter by service: **Compute, Networking, Block Storage**
3. Expected: all $0

If anything shows a charge:

- **Block volume over 200 GB**: trim. 50 GB × 2 instances = 100 GB, well under.
- **Egress over 10 TB/mo**: investigate. Bootstrap traffic should be < 200 GB/mo.
- **A non-Free instance accidentally created**: terminate it immediately.

## Security incident response

### Suspected compromise

```bash
# 1. Lock SSH
ssh ubuntu@<host> "sudo passwd -l ubuntu"

# 2. Snapshot via OCI console (Compute → Instance → Create Boot Volume Backup)

# 3. Stop services
ssh ubuntu@<host> "sudo systemctl stop sophisd-mainnet sophisd-testnet faucet"

# 4. Rotate the faucet wallet (if compromise might have touched it)
#    See testnet-faucet/README.md → "Rotate the wallet"

# 5. Terminate and re-provision from cloud-init
```

### DDoS

OCI's network edge handles volumetric attacks. Cloudflare in front of the
faucet handles HTTP-layer attacks. If P2P ports (46111/46211) are flooded:

```bash
# Temporary block at iptables — replace <attacker-ip>
ssh ubuntu@<host> "sudo iptables -I INPUT -s <attacker-ip> -j DROP && sudo netfilter-persistent save"
```

Long-term: file an abuse report with the attacker's hosting provider via
`whois <attacker-ip>`.

## Adding a third bootstrap node

When organic adoption justifies it (or after first community-volunteered
node arrives):

1. Provision in a new region (same OCI account; 4th instance still fits
   under the 4-OCPU Always Free cap if you reduce the existing two to
   1 OCPU each — or use a different provider)
2. Run `bootstrap2-cloud-init.yaml` (node-only)
3. Add to Cloudflare DNS: `bootstrap3.sophis.org` → public IP, proxy OFF
4. Add the IP to the project's DNS seeder rotation (see `dnsseeder/` setup)
5. Update this runbook with the new host
