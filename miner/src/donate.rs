//! Client-side coinbase donation split.
//!
//! Pure-client convenience: the miner re-writes the coinbase transaction
//! it receives from `getBlockTemplate` so that part of the reward goes to
//! caller-chosen donation addresses instead of 100% to the miner. Then
//! recomputes the block's merkle root to keep the block valid before
//! submission. Default OFF (zero impact if not used).
//!
//! No consensus rule, no protocol change, no whitelist. Each operator
//! decides what (if anything) to donate and to whom. See
//! `Operational Boundaries Statement` for the policy framing.

use sophis_addresses::{Address, Prefix};
use sophis_rpc_core::model::tx::{RpcTransaction, RpcTransactionOutput};
use sophis_txscript::standard::pay_to_address_script;

/// Maximum number of donation outputs the miner is willing to attach.
///
/// Caps both the CLI `--donate-to` repetitions and the resulting coinbase
/// fan-out. Avoids dust-flood / DoS from absurd splits.
pub const MAX_DONATION_OUTPUTS: usize = 8;

/// One donation entry parsed from `--donate-to ADDR --donate-percent N` flags.
#[derive(Debug, Clone)]
pub struct Donation {
    pub address: Address,
    /// Percentage of the coinbase reward (0-100, integer).
    pub percent: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum DonateError {
    #[error("invalid donation address `{addr}`: {source}")]
    InvalidAddress { addr: String, source: sophis_addresses::AddressError },

    #[error(
        "address prefix mismatch: --donate-to address has prefix {actual:?}, expected {expected:?} \
         (must match the network the miner is mining)"
    )]
    PrefixMismatch { actual: Prefix, expected: Prefix },

    #[error("--donate-percent values must satisfy 0 <= sum <= 100, got total {total}")]
    PercentOverflow { total: u32 },

    #[error("number of --donate-to entries ({count}) exceeds MAX_DONATION_OUTPUTS ({max})")]
    TooManyDonations { count: usize, max: usize },

    #[error("number of --donate-percent values ({percents}) does not match --donate-to count ({addresses})")]
    LengthMismatch { percents: usize, addresses: usize },
}

/// Parse and validate the CLI flags into a list of `Donation` entries.
///
/// The `expected_prefix` is the prefix of the miner's primary
/// `--mining-address`. Donation addresses must use the same prefix.
pub fn parse_donations(
    addresses_str: &[String],
    percents: &[u8],
    expected_prefix: Prefix,
) -> Result<Vec<Donation>, DonateError> {
    if addresses_str.is_empty() && percents.is_empty() {
        return Ok(Vec::new());
    }
    if addresses_str.len() != percents.len() {
        return Err(DonateError::LengthMismatch {
            percents: percents.len(),
            addresses: addresses_str.len(),
        });
    }
    if addresses_str.len() > MAX_DONATION_OUTPUTS {
        return Err(DonateError::TooManyDonations {
            count: addresses_str.len(),
            max: MAX_DONATION_OUTPUTS,
        });
    }

    // Sum check (using u32 to safely catch overflow above 255).
    let total: u32 = percents.iter().map(|&p| p as u32).sum();
    if total > 100 {
        return Err(DonateError::PercentOverflow { total });
    }

    let mut donations = Vec::with_capacity(addresses_str.len());
    for (addr_str, &pct) in addresses_str.iter().zip(percents.iter()) {
        let addr = Address::try_from(addr_str.clone())
            .map_err(|e| DonateError::InvalidAddress { addr: addr_str.clone(), source: e })?;
        if addr.prefix != expected_prefix {
            return Err(DonateError::PrefixMismatch { actual: addr.prefix, expected: expected_prefix });
        }
        donations.push(Donation { address: addr, percent: pct });
    }
    Ok(donations)
}

/// Compute the integer split of `total_value` according to `donations`.
///
/// Returns `(miner_share, [donation_amounts])` such that
/// `miner_share + sum(donation_amounts) == total_value` exactly, with
/// each donation amount = `floor(total_value * pct / 100)`. Any rounding
/// remainder accrues to the miner, never lost or inflated.
pub fn compute_split(total_value: u64, donations: &[Donation]) -> (u64, Vec<u64>) {
    if donations.is_empty() {
        return (total_value, Vec::new());
    }
    let amounts: Vec<u64> = donations
        .iter()
        .map(|d| (total_value as u128 * d.percent as u128 / 100u128) as u64)
        .collect();
    let donated_total: u64 = amounts.iter().sum();
    let miner_share = total_value.saturating_sub(donated_total);
    (miner_share, amounts)
}

/// Re-write the coinbase transaction's outputs to apply the split.
///
/// The original coinbase from `getBlockTemplate` has exactly ONE output
/// (the miner's full reward). After this rewrite it has `1 + N` outputs:
/// the miner's reduced share + one output per donation entry. Order is
/// `[miner, donations...]` to keep the miner output at index 0
/// (matches existing tooling that may assume index 0 = miner).
///
/// **Caller responsibility**: after calling this, recompute the block's
/// `hash_merkle_root` because the coinbase tx body changed.
pub fn rewrite_coinbase_outputs(coinbase: &mut RpcTransaction, donations: &[Donation]) {
    if donations.is_empty() || coinbase.outputs.is_empty() {
        return;
    }
    // Sum of original outputs is the total reward.
    let total: u64 = coinbase.outputs.iter().map(|o| o.value).sum();
    let (miner_share, donation_amounts) = compute_split(total, donations);

    // Existing miner output keeps its script_public_key, gets reduced value.
    // Replace value of first output, drop any extras (defensive — coinbase
    // typically has exactly one output, but this handles edge cases).
    let miner_script = coinbase.outputs[0].script_public_key.clone();
    let mut new_outputs: Vec<RpcTransactionOutput> = Vec::with_capacity(1 + donations.len());
    new_outputs.push(RpcTransactionOutput {
        value: miner_share,
        script_public_key: miner_script,
        verbose_data: None,
    });
    for (donation, amount) in donations.iter().zip(donation_amounts.iter()) {
        if *amount == 0 {
            // Skip dust-zero donation outputs; the rounding remainder
            // already accrued to the miner via compute_split.
            continue;
        }
        new_outputs.push(RpcTransactionOutput {
            value: *amount,
            script_public_key: pay_to_address_script(&donation.address),
            verbose_data: None,
        });
    }
    coinbase.outputs = new_outputs;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_addr(payload_byte: u8) -> Address {
        let payload = vec![payload_byte; 32];
        Address::new(Prefix::Devnet, sophis_addresses::Version::PubKeyDilithium, &payload)
    }

    #[test]
    fn parse_empty_is_empty() {
        let donations = parse_donations(&[], &[], Prefix::Devnet).unwrap();
        assert!(donations.is_empty());
    }

    #[test]
    fn parse_length_mismatch_rejected() {
        let err = parse_donations(&[String::from(&dev_addr(1))], &[10, 20], Prefix::Devnet).unwrap_err();
        assert!(matches!(err, DonateError::LengthMismatch { .. }));
    }

    #[test]
    fn parse_percent_sum_over_100_rejected() {
        let addrs = vec![String::from(&dev_addr(1)), String::from(&dev_addr(2))];
        let err = parse_donations(&addrs, &[60, 50], Prefix::Devnet).unwrap_err();
        assert!(matches!(err, DonateError::PercentOverflow { total: 110 }));
    }

    #[test]
    fn parse_too_many_donations_rejected() {
        let addrs: Vec<String> = (0..MAX_DONATION_OUTPUTS + 1).map(|i| String::from(&dev_addr(i as u8))).collect();
        let pcts = vec![1u8; MAX_DONATION_OUTPUTS + 1];
        let err = parse_donations(&addrs, &pcts, Prefix::Devnet).unwrap_err();
        assert!(matches!(err, DonateError::TooManyDonations { .. }));
    }

    #[test]
    fn parse_prefix_mismatch_rejected() {
        let mainnet_addr = Address::new(Prefix::Mainnet, sophis_addresses::Version::PubKeyDilithium, &[1u8; 32]);
        let addrs = vec![String::from(&mainnet_addr)];
        let err = parse_donations(&addrs, &[10], Prefix::Devnet).unwrap_err();
        assert!(matches!(err, DonateError::PrefixMismatch { .. }));
    }

    #[test]
    fn parse_invalid_address_rejected() {
        let err = parse_donations(&[String::from("not_a_valid_address")], &[10], Prefix::Devnet).unwrap_err();
        assert!(matches!(err, DonateError::InvalidAddress { .. }));
    }

    #[test]
    fn parse_happy_path() {
        let addrs = vec![String::from(&dev_addr(1)), String::from(&dev_addr(2))];
        let donations = parse_donations(&addrs, &[3, 2], Prefix::Devnet).unwrap();
        assert_eq!(donations.len(), 2);
        assert_eq!(donations[0].percent, 3);
        assert_eq!(donations[1].percent, 2);
    }

    #[test]
    fn split_zero_donations_returns_full_to_miner() {
        let (miner, donations) = compute_split(100_000, &[]);
        assert_eq!(miner, 100_000);
        assert!(donations.is_empty());
    }

    #[test]
    fn split_zero_percent_keeps_full_to_miner() {
        let donations = vec![Donation { address: dev_addr(1), percent: 0 }];
        let (miner, amts) = compute_split(100_000, &donations);
        assert_eq!(miner, 100_000);
        assert_eq!(amts, vec![0]);
    }

    #[test]
    fn split_full_100_percent_goes_to_donations() {
        let donations = vec![Donation { address: dev_addr(1), percent: 100 }];
        let (miner, amts) = compute_split(100, &donations);
        assert_eq!(miner, 0);
        assert_eq!(amts, vec![100]);
    }

    #[test]
    fn split_50_30_20_exact() {
        let donations = vec![
            Donation { address: dev_addr(1), percent: 50 },
            Donation { address: dev_addr(2), percent: 30 },
            Donation { address: dev_addr(3), percent: 20 },
        ];
        let (miner, amts) = compute_split(100_000, &donations);
        assert_eq!(amts, vec![50_000, 30_000, 20_000]);
        assert_eq!(miner, 0);
    }

    #[test]
    fn split_rounding_remainder_accrues_to_miner() {
        // 10 sompi with 33% donation → floor(10 * 33 / 100) = 3, miner = 10 - 3 = 7.
        let donations = vec![Donation { address: dev_addr(1), percent: 33 }];
        let (miner, amts) = compute_split(10, &donations);
        assert_eq!(amts, vec![3]);
        assert_eq!(miner, 7);
        // No inflation, no loss: 7 + 3 == 10.
        assert_eq!(miner + amts.iter().sum::<u64>(), 10);
    }

    #[test]
    fn split_three_thirds_no_inflation() {
        // 100 sompi split 3 × 33% = 33+33+33 = 99 donated; miner = 100 - 99 = 1.
        let donations = vec![
            Donation { address: dev_addr(1), percent: 33 },
            Donation { address: dev_addr(2), percent: 33 },
            Donation { address: dev_addr(3), percent: 33 },
        ];
        let (miner, amts) = compute_split(100, &donations);
        assert_eq!(amts, vec![33, 33, 33]);
        assert_eq!(miner, 1);
        assert_eq!(miner + amts.iter().sum::<u64>(), 100);
    }

    #[test]
    fn split_huge_value_no_overflow() {
        // ~210M SPHS in sompi with 100% to one donation: must not overflow.
        let total = 210_000_000_u64 * 100_000_000_u64; // ~2.1e16 sompi, fits u64
        let donations = vec![Donation { address: dev_addr(1), percent: 100 }];
        let (miner, amts) = compute_split(total, &donations);
        assert_eq!(amts, vec![total]);
        assert_eq!(miner, 0);
    }

    fn make_coinbase_with_value(value: u64) -> RpcTransaction {
        use sophis_consensus_core::tx::ScriptPublicKey;
        use sophis_rpc_core::model::RpcSubnetworkId;
        RpcTransaction {
            version: 0,
            inputs: vec![],
            outputs: vec![RpcTransactionOutput {
                value,
                script_public_key: ScriptPublicKey::new(0, smallvec::smallvec![]),
                verbose_data: None,
            }],
            lock_time: 0,
            subnetwork_id: RpcSubnetworkId::default(),
            gas: 0,
            payload: vec![],
            mass: 0,
            verbose_data: None,
        }
    }

    #[test]
    fn rewrite_no_donations_is_noop() {
        let mut tx = make_coinbase_with_value(100_000);
        rewrite_coinbase_outputs(&mut tx, &[]);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 100_000);
    }

    #[test]
    fn rewrite_split_50_50_produces_two_outputs() {
        let mut tx = make_coinbase_with_value(100_000);
        let donations = vec![Donation { address: dev_addr(7), percent: 50 }];
        rewrite_coinbase_outputs(&mut tx, &donations);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0].value, 50_000); // miner
        assert_eq!(tx.outputs[1].value, 50_000); // donation
    }

    #[test]
    fn rewrite_skips_dust_zero_donation() {
        // Tiny reward + tiny percent → donation rounds to 0 → skip output.
        let mut tx = make_coinbase_with_value(50);
        let donations = vec![Donation { address: dev_addr(7), percent: 1 }];
        rewrite_coinbase_outputs(&mut tx, &donations);
        // floor(50 * 1 / 100) = 0 → only the miner output remains.
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 50);
    }

    #[test]
    fn rewrite_preserves_total_value() {
        let mut tx = make_coinbase_with_value(1_234_567);
        let donations = vec![
            Donation { address: dev_addr(1), percent: 7 },
            Donation { address: dev_addr(2), percent: 3 },
        ];
        rewrite_coinbase_outputs(&mut tx, &donations);
        let new_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
        assert_eq!(new_total, 1_234_567, "total must be conserved exactly");
    }
}
