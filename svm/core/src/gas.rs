/// Gas cost weights — calibrate with devnet/testnet data before mainnet.
pub const GAS_DILITHIUM_VERIFY: u64 = 10_000;
pub const GAS_SHA3_384: u64 = 100;
pub const GAS_PER_DATUM_BYTE: u64 = 10;
pub const GAS_PER_TX_BYTE: u64 = 1;
/// Risc0 STARK proof verification — extremely expensive; batch use only.
/// ~50–100M zkVM cycles per proof; placeholder, calibrate post-devnet.
pub const GAS_RISC0_VERIFY: u64 = 10_000_000;
/// Plonky3 STARK proof verification — also expensive but cheaper than Risc0
/// (no zkVM emulation overhead; pure FRI verifier). Verify_air ~0.19s release;
/// gas cost is a placeholder pending devnet calibration. Set higher than
/// dilithium and lower than risc0 to reflect relative wall-clock.
pub const GAS_PLONKY3_VERIFY: u64 = 1_000_000;
/// Phase 6 — DA presence check. RocksDB lookup is O(1); cost is dominated by
/// the gas-meter overhead, not the I/O. Calibrate post-devnet.
pub const GAS_DA_VERIFY: u64 = 2_000;
/// L1 — ALT reference resolution. Same shape as the DA path: O(1) RocksDB
/// lookup plus a small write back into linear memory. Slightly cheaper than
/// the DA case because no confirmation bookkeeping happens. Calibrate
/// post-devnet.
pub const GAS_ALT_RESOLVE: u64 = 1_500;
/// J4 — fixed cost of emitting one event. Frozen ABI; matches the value
/// declared in `docs/J4_EVENTS_DESIGN.md` and exposed in the J4 memory
/// index (constants frozen ABI).
pub const GAS_EVENT_EMIT_BASE: u64 = 1_000;
/// J4 — per-byte cost of the `data` payload of an emitted event.
/// Topics are not metered separately — they are bounded to 4 × 32 bytes
/// max and carry a fixed ceiling. Frozen ABI.
pub const GAS_EVENT_EMIT_PER_BYTE: u64 = 8;
/// J3 — single VRF lookup. Cost dominated by RocksDB chain-index lookup
/// plus a small SHA3-384 mix. Cheaper than ALT resolve because the
/// output is a fixed 32 bytes (no variable buffer write).
/// Calibrate post-devnet.
pub const GAS_VRF_RANDOM: u64 = 500;

/// Minimum SOF deposit to create a Contract UTXO (storage rent, refunded on spend).
pub const STORAGE_BASE_DEPOSIT: u64 = 100_000_000; // sompi
/// Additional deposit per datum byte.
pub const STORAGE_BYTE_RATE: u64 = 1_000; // sompi

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gas(pub u64);

impl Gas {
    pub fn saturating_add(self, rhs: Gas) -> Gas {
        Gas(self.0.saturating_add(rhs.0))
    }
}

impl std::ops::Add for Gas {
    type Output = Gas;
    fn add(self, rhs: Gas) -> Gas {
        Gas(self.0.checked_add(rhs.0).expect("gas overflow"))
    }
}

/// Per-network gas configuration. Values are calibrated post-devnet.
#[derive(Debug, Clone)]
pub struct GasConfig {
    pub max_gas_per_tx: u64,
    /// Conversion: 1 Wasmtime fuel unit = wasm_fuel_ratio gas units.
    pub wasm_fuel_ratio: u64,
    pub dilithium_verify_cost: u64,
    pub sha3_cost: u64,
    pub datum_byte_cost: u64,
    pub tx_byte_cost: u64,
    pub risc0_verify_cost: u64,
    pub plonky3_verify_cost: u64,
    pub da_verify_cost: u64,
    pub alt_resolve_cost: u64,
    pub event_emit_base_cost: u64,
    pub event_emit_per_byte_cost: u64,
    pub vrf_random_cost: u64,
}

impl Default for GasConfig {
    fn default() -> Self {
        Self {
            max_gas_per_tx: 10_000_000,
            wasm_fuel_ratio: 1,
            dilithium_verify_cost: GAS_DILITHIUM_VERIFY,
            sha3_cost: GAS_SHA3_384,
            datum_byte_cost: GAS_PER_DATUM_BYTE,
            tx_byte_cost: GAS_PER_TX_BYTE,
            risc0_verify_cost: GAS_RISC0_VERIFY,
            plonky3_verify_cost: GAS_PLONKY3_VERIFY,
            da_verify_cost: GAS_DA_VERIFY,
            alt_resolve_cost: GAS_ALT_RESOLVE,
            event_emit_base_cost: GAS_EVENT_EMIT_BASE,
            event_emit_per_byte_cost: GAS_EVENT_EMIT_PER_BYTE,
            vrf_random_cost: GAS_VRF_RANDOM,
        }
    }
}

impl GasConfig {
    /// Minimum SOF deposit required for a contract output with this datum size.
    pub fn storage_deposit(&self, datum_bytes: usize) -> u64 {
        // saturating_mul prevents overflow before the addition
        STORAGE_BASE_DEPOSIT.saturating_add((datum_bytes as u64).saturating_mul(STORAGE_BYTE_RATE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_saturating_add_saturates() {
        assert_eq!(Gas(2).saturating_add(Gas(3)), Gas(5));
        assert_eq!(Gas(u64::MAX).saturating_add(Gas(1)), Gas(u64::MAX));
    }

    #[test]
    fn gas_add_operator_and_ord() {
        assert_eq!(Gas(10) + Gas(5), Gas(15));
        assert!(Gas(1) < Gas(2));
        assert_eq!(Gas::default(), Gas(0));
        assert_eq!(Gas(7), Gas(7));
    }

    #[test]
    #[should_panic(expected = "gas overflow")]
    fn gas_add_operator_panics_on_overflow() {
        let _ = Gas(u64::MAX) + Gas(1);
    }

    #[test]
    fn gas_config_default_matches_constants() {
        let c = GasConfig::default();
        assert_eq!(c.max_gas_per_tx, 10_000_000);
        assert_eq!(c.wasm_fuel_ratio, 1);
        assert_eq!(c.dilithium_verify_cost, GAS_DILITHIUM_VERIFY);
        assert_eq!(c.sha3_cost, GAS_SHA3_384);
        assert_eq!(c.datum_byte_cost, GAS_PER_DATUM_BYTE);
        assert_eq!(c.tx_byte_cost, GAS_PER_TX_BYTE);
        assert_eq!(c.risc0_verify_cost, GAS_RISC0_VERIFY);
        assert_eq!(c.plonky3_verify_cost, GAS_PLONKY3_VERIFY);
        assert_eq!(c.da_verify_cost, GAS_DA_VERIFY);
        assert_eq!(c.alt_resolve_cost, GAS_ALT_RESOLVE);
        assert_eq!(c.event_emit_base_cost, GAS_EVENT_EMIT_BASE);
        assert_eq!(c.event_emit_per_byte_cost, GAS_EVENT_EMIT_PER_BYTE);
        assert_eq!(c.vrf_random_cost, GAS_VRF_RANDOM);
    }

    #[test]
    fn storage_deposit_scales_and_saturates() {
        let c = GasConfig::default();
        assert_eq!(c.storage_deposit(0), STORAGE_BASE_DEPOSIT);
        assert_eq!(c.storage_deposit(10), STORAGE_BASE_DEPOSIT + 10 * STORAGE_BYTE_RATE);
        // saturating: enormous datum size must not panic/overflow.
        assert_eq!(c.storage_deposit(usize::MAX), u64::MAX);
    }
}
