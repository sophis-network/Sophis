use sophis_consensus_core::constants::{MAX_TX_VERSION, TX_VERSION};

pub(crate) const DEFAULT_MAXIMUM_TRANSACTION_COUNT: usize = 1_000_000;
pub(crate) const DEFAULT_MEMPOOL_SIZE_LIMIT: usize = 1_000_000_000;
pub(crate) const DEFAULT_MAXIMUM_BUILD_BLOCK_TEMPLATE_ATTEMPTS: u64 = 5;

pub(crate) const DEFAULT_TRANSACTION_EXPIRE_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
pub(crate) const DEFAULT_TRANSACTION_EXPIRE_SCAN_INTERVAL_SECONDS: u64 = 60;
pub(crate) const DEFAULT_ACCEPTED_TRANSACTION_EXPIRE_INTERVAL_SECONDS: u64 = 120;
pub(crate) const DEFAULT_ACCEPTED_TRANSACTION_EXPIRE_SCAN_INTERVAL_SECONDS: u64 = 10;
pub(crate) const DEFAULT_ORPHAN_EXPIRE_INTERVAL_SECONDS: u64 = 60;
pub(crate) const DEFAULT_ORPHAN_EXPIRE_SCAN_INTERVAL_SECONDS: u64 = 10;

pub(crate) const DEFAULT_MAXIMUM_ORPHAN_TRANSACTION_MASS: u64 = 100_000;
pub(crate) const DEFAULT_MAXIMUM_ORPHAN_TRANSACTION_COUNT: u64 = 500;

/// DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE specifies the minimum transaction fee for a transaction to be accepted to
/// the mempool and relayed. It is specified in sompi per 1kg (or 1000 grams) of transaction mass.
pub(crate) const DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE: u64 = 1000;

/// Standard transaction version range might be different from what consensus accepts, therefore
/// we define separate values in mempool. After L1 (sub-fase L1.3), the
/// mempool standard window matches the full consensus range
/// `[TX_VERSION, MAX_TX_VERSION]` so v=1 ALT-aware transactions can be
/// relayed without manual configuration overrides.
pub(crate) const DEFAULT_MINIMUM_STANDARD_TRANSACTION_VERSION: u16 = TX_VERSION;
pub(crate) const DEFAULT_MAXIMUM_STANDARD_TRANSACTION_VERSION: u16 = MAX_TX_VERSION;

#[derive(Clone, Debug)]
pub struct Config {
    pub maximum_transaction_count: usize,
    pub mempool_size_limit: usize,
    pub maximum_build_block_template_attempts: u64,
    pub transaction_expire_interval_daa_score: u64,
    pub transaction_expire_scan_interval_daa_score: u64,
    pub transaction_expire_scan_interval_milliseconds: u64,
    pub accepted_transaction_expire_interval_daa_score: u64,
    pub accepted_transaction_expire_scan_interval_daa_score: u64,
    pub accepted_transaction_expire_scan_interval_milliseconds: u64,
    pub orphan_expire_interval_daa_score: u64,
    pub orphan_expire_scan_interval_daa_score: u64,
    pub maximum_orphan_transaction_mass: u64,
    pub maximum_orphan_transaction_count: u64,
    pub accept_non_standard: bool,
    pub maximum_mass_per_block: u64,
    pub minimum_relay_transaction_fee: u64,
    pub minimum_standard_transaction_version: u16,
    pub maximum_standard_transaction_version: u16,
    pub network_blocks_per_second: u64,
}

impl Config {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maximum_transaction_count: usize,
        mempool_size_limit: usize,
        maximum_build_block_template_attempts: u64,
        transaction_expire_interval_daa_score: u64,
        transaction_expire_scan_interval_daa_score: u64,
        transaction_expire_scan_interval_milliseconds: u64,
        accepted_transaction_expire_interval_daa_score: u64,
        accepted_transaction_expire_scan_interval_daa_score: u64,
        accepted_transaction_expire_scan_interval_milliseconds: u64,
        orphan_expire_interval_daa_score: u64,
        orphan_expire_scan_interval_daa_score: u64,
        maximum_orphan_transaction_mass: u64,
        maximum_orphan_transaction_count: u64,
        accept_non_standard: bool,
        maximum_mass_per_block: u64,
        minimum_relay_transaction_fee: u64,
        minimum_standard_transaction_version: u16,
        maximum_standard_transaction_version: u16,
        network_blocks_per_second: u64,
    ) -> Self {
        Self {
            maximum_transaction_count,
            mempool_size_limit,
            maximum_build_block_template_attempts,
            transaction_expire_interval_daa_score,
            transaction_expire_scan_interval_daa_score,
            transaction_expire_scan_interval_milliseconds,
            accepted_transaction_expire_interval_daa_score,
            accepted_transaction_expire_scan_interval_daa_score,
            accepted_transaction_expire_scan_interval_milliseconds,
            orphan_expire_interval_daa_score,
            orphan_expire_scan_interval_daa_score,
            maximum_orphan_transaction_mass,
            maximum_orphan_transaction_count,
            accept_non_standard,
            maximum_mass_per_block,
            minimum_relay_transaction_fee,
            minimum_standard_transaction_version,
            maximum_standard_transaction_version,
            network_blocks_per_second,
        }
    }

    /// Build a default config.
    /// The arguments should be obtained from the current consensus [`sophis_consensus_core::config::params::Params`] instance.
    pub fn build_default(target_milliseconds_per_block: u64, relay_non_std_transactions: bool, max_block_mass: u64) -> Self {
        Self {
            maximum_transaction_count: DEFAULT_MAXIMUM_TRANSACTION_COUNT,
            mempool_size_limit: DEFAULT_MEMPOOL_SIZE_LIMIT,
            maximum_build_block_template_attempts: DEFAULT_MAXIMUM_BUILD_BLOCK_TEMPLATE_ATTEMPTS,
            transaction_expire_interval_daa_score: DEFAULT_TRANSACTION_EXPIRE_INTERVAL_SECONDS * 1000 / target_milliseconds_per_block,
            transaction_expire_scan_interval_daa_score: DEFAULT_TRANSACTION_EXPIRE_SCAN_INTERVAL_SECONDS * 1000
                / target_milliseconds_per_block,
            transaction_expire_scan_interval_milliseconds: DEFAULT_TRANSACTION_EXPIRE_SCAN_INTERVAL_SECONDS * 1000,
            accepted_transaction_expire_interval_daa_score: DEFAULT_ACCEPTED_TRANSACTION_EXPIRE_INTERVAL_SECONDS * 1000
                / target_milliseconds_per_block,
            accepted_transaction_expire_scan_interval_daa_score: DEFAULT_ACCEPTED_TRANSACTION_EXPIRE_SCAN_INTERVAL_SECONDS * 1000
                / target_milliseconds_per_block,
            accepted_transaction_expire_scan_interval_milliseconds: DEFAULT_ACCEPTED_TRANSACTION_EXPIRE_SCAN_INTERVAL_SECONDS * 1000,
            orphan_expire_interval_daa_score: DEFAULT_ORPHAN_EXPIRE_INTERVAL_SECONDS * 1000 / target_milliseconds_per_block,
            orphan_expire_scan_interval_daa_score: DEFAULT_ORPHAN_EXPIRE_SCAN_INTERVAL_SECONDS * 1000 / target_milliseconds_per_block,
            maximum_orphan_transaction_mass: DEFAULT_MAXIMUM_ORPHAN_TRANSACTION_MASS,
            maximum_orphan_transaction_count: DEFAULT_MAXIMUM_ORPHAN_TRANSACTION_COUNT,
            accept_non_standard: relay_non_std_transactions,
            maximum_mass_per_block: max_block_mass,
            minimum_relay_transaction_fee: DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE,
            minimum_standard_transaction_version: DEFAULT_MINIMUM_STANDARD_TRANSACTION_VERSION,
            maximum_standard_transaction_version: DEFAULT_MAXIMUM_STANDARD_TRANSACTION_VERSION,
            network_blocks_per_second: 1000 / target_milliseconds_per_block,
        }
    }

    pub fn apply_ram_scale(mut self, ram_scale: f64) -> Self {
        // Allow only scaling down
        self.maximum_transaction_count = (self.maximum_transaction_count as f64 * ram_scale.min(1.0)) as usize;
        self.mempool_size_limit = (self.mempool_size_limit as f64 * ram_scale.min(1.0)) as usize;
        self
    }

    /// Returns the minimum standard fee/mass ratio currently required by the mempool
    pub(crate) fn minimum_feerate(&self) -> f64 {
        // The parameter minimum_relay_transaction_fee is in sompi/kg units so divide by 1000 to get sompi/gram
        self.minimum_relay_transaction_fee as f64 / 1000.0
    }
}

// Audit category-D coverage closure, item 4 (Session 16, 2026-05-16):
// config.rs was 28% — `Config` is pure (new / build_default /
// apply_ram_scale / minimum_feerate). All exercised here.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_default_derives_fields_from_block_time() {
        let c = Config::build_default(1000, true, 500_000);
        assert_eq!(c.maximum_transaction_count, DEFAULT_MAXIMUM_TRANSACTION_COUNT);
        assert_eq!(c.mempool_size_limit, DEFAULT_MEMPOOL_SIZE_LIMIT);
        assert!(c.accept_non_standard); // relay_non_std_transactions = true
        assert_eq!(c.maximum_mass_per_block, 500_000);
        // 1000 ms/block → 1 block/s; daa-score interval = secs * 1000 / ms_per_block
        assert_eq!(c.network_blocks_per_second, 1);
        assert_eq!(c.transaction_expire_interval_daa_score, DEFAULT_TRANSACTION_EXPIRE_INTERVAL_SECONDS);
        assert_eq!(c.minimum_relay_transaction_fee, DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE);
        assert_eq!(c.minimum_standard_transaction_version, DEFAULT_MINIMUM_STANDARD_TRANSACTION_VERSION);
        assert_eq!(c.maximum_standard_transaction_version, DEFAULT_MAXIMUM_STANDARD_TRANSACTION_VERSION);

        // 100 ms/block → 10 blocks/s.
        let fast = Config::build_default(100, false, 1);
        assert_eq!(fast.network_blocks_per_second, 10);
        assert!(!fast.accept_non_standard);
    }

    #[test]
    fn apply_ram_scale_only_scales_down() {
        let base = Config::build_default(1000, false, 1);
        let (bc, bs) = (base.maximum_transaction_count, base.mempool_size_limit);
        let halved = Config::build_default(1000, false, 1).apply_ram_scale(0.5);
        assert_eq!(halved.maximum_transaction_count, bc / 2);
        assert_eq!(halved.mempool_size_limit, bs / 2);
        // ram_scale > 1.0 is clamped to 1.0 (only scaling down allowed).
        let up = Config::build_default(1000, false, 1).apply_ram_scale(4.0);
        assert_eq!(up.maximum_transaction_count, bc);
        assert_eq!(up.mempool_size_limit, bs);
    }

    #[test]
    fn minimum_feerate_is_fee_per_kg_over_1000() {
        let mut c = Config::build_default(1000, false, 1);
        c.minimum_relay_transaction_fee = 2500;
        assert_eq!(c.minimum_feerate(), 2.5);
    }

    #[test]
    fn new_sets_every_field_verbatim() {
        let c = Config::new(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, true, 14, 15, 16, 17, 18);
        assert_eq!(c.maximum_transaction_count, 1);
        assert_eq!(c.mempool_size_limit, 2);
        assert_eq!(c.maximum_build_block_template_attempts, 3);
        assert_eq!(c.transaction_expire_interval_daa_score, 4);
        assert!(c.accept_non_standard);
        assert_eq!(c.maximum_mass_per_block, 14);
        assert_eq!(c.minimum_relay_transaction_fee, 15);
        assert_eq!(c.minimum_standard_transaction_version, 16);
        assert_eq!(c.maximum_standard_transaction_version, 17);
        assert_eq!(c.network_blocks_per_second, 18);
        // Clone + Debug derives.
        assert_eq!(c.clone().maximum_orphan_transaction_count, c.maximum_orphan_transaction_count);
        assert!(!format!("{c:?}").is_empty());
    }
}
