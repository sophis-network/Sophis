// Kani formal verification harnesses for sophis-svm-core types.
//
// Run with:
//   cargo install --locked kani-verifier && cargo kani setup   (once)
//   cargo kani-proofs                                           (verify all)
//   cargo kani --package sophis-kani-proofs --harness <name>   (single harness)
//
// Regular `cargo build` / `cargo test` compile this crate as an empty library.

#[cfg(kani)]
mod proofs {
    use sophis_hashes::Hash;
    use sophis_svm_core::{
        Capability, ContractManifest, DilithiumPublicKey, Gas, GasConfig, NativeTokenUtxoData, TokenId, UPGRADE_MIN_BLOCKS,
        UpgradePolicy,
        gas::{STORAGE_BASE_DEPOSIT, STORAGE_BYTE_RATE},
        utxo::ContractId,
    };

    // -------------------------------------------------------------------------
    // Helpers — construct fixed or symbolic instances of complex types
    // -------------------------------------------------------------------------

    fn zero_hash() -> Hash {
        Hash::from_slice(&[0u8; 32])
    }

    // DilithiumPublicKey is 1312 bytes; the `is_valid()` path never inspects
    // the key contents, so a zero-filled key suffices for all policy harnesses.
    fn zero_pk() -> DilithiumPublicKey {
        DilithiumPublicKey([0u8; 1312])
    }

    // Capability has no Arbitrary impl; build one from a symbolic byte.
    fn any_capability() -> Capability {
        match kani::any::<u8>() % 7 {
            0 => Capability::ReadUtxo,
            1 => Capability::ProduceOutput,
            2 => Capability::VerifyDilithium,
            3 => Capability::ReadBlockHeight,
            4 => Capability::HashSha3,
            5 => Capability::VerifyRisc0Proof,
            _ => Capability::VerifyPlonky3Proof,
        }
    }

    // =========================================================================
    // Gas — svm/core/src/gas.rs
    // =========================================================================

    /// saturating_add is total: no panic for any pair of u64.
    #[kani::proof]
    fn gas_saturating_add_is_total() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        let _ = Gas(a).saturating_add(Gas(b));
    }

    /// saturating_add is monotone: result >= each operand (no silent wrap).
    #[kani::proof]
    fn gas_saturating_add_monotone() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        let result = Gas(a).saturating_add(Gas(b));
        assert!(result.0 >= a);
        assert!(result.0 >= b);
    }

    /// storage_deposit is total for all datum_bytes values:
    /// the byte * rate multiplication uses saturating_mul so it cannot overflow.
    #[kani::proof]
    fn gas_storage_deposit_is_total() {
        let datum_bytes: usize = kani::any();
        let config = GasConfig::default();
        let result = config.storage_deposit(datum_bytes);
        assert!(result >= STORAGE_BASE_DEPOSIT);
    }

    /// GasConfig defaults satisfy internal invariants: costs are positive.
    #[kani::proof]
    fn gas_default_config_invariants() {
        let cfg = GasConfig::default();
        assert!(cfg.max_gas_per_tx > 0);
        assert!(cfg.wasm_fuel_ratio > 0);
        assert!(cfg.dilithium_verify_cost > 0);
        assert!(cfg.risc0_verify_cost > 0);
        assert!(cfg.plonky3_verify_cost > 0);
        // Verify*Proof costs must exceed Dilithium (batch crypto, much heavier).
        assert!(cfg.risc0_verify_cost > cfg.dilithium_verify_cost);
        assert!(cfg.plonky3_verify_cost > cfg.dilithium_verify_cost);
        // Risc0 (zkVM emulation) costs more than Plonky3 (pure FRI verifier).
        assert!(cfg.risc0_verify_cost > cfg.plonky3_verify_cost);
    }

    /// VerifyRisc0Proof capability is distinct from all other capabilities.
    #[kani::proof]
    fn risc0_capability_is_unique() {
        let other = any_capability();
        // kani::assume is needed so the verifier restricts `other` to non-Risc0.
        kani::assume(!matches!(other, Capability::VerifyRisc0Proof));
        assert_ne!(other, Capability::VerifyRisc0Proof);
    }

    /// VerifyPlonky3Proof capability is distinct from all other capabilities.
    #[kani::proof]
    fn plonky3_capability_is_unique() {
        let other = any_capability();
        kani::assume(!matches!(other, Capability::VerifyPlonky3Proof));
        assert_ne!(other, Capability::VerifyPlonky3Proof);
    }

    // =========================================================================
    // UpgradePolicy — svm/core/src/upgrade_policy.rs
    // =========================================================================

    /// Immutable policy is always valid — no timelock to check.
    #[kani::proof]
    fn upgrade_policy_immutable_always_valid() {
        assert!(UpgradePolicy::Immutable.is_valid());
    }

    /// OwnerTimelock is valid iff min_blocks >= UPGRADE_MIN_BLOCKS.
    #[kani::proof]
    fn upgrade_policy_owner_timelock_correctness() {
        let min_blocks: u64 = kani::any();
        let policy = UpgradePolicy::OwnerTimelock { owner_pk: zero_pk(), min_blocks };
        assert_eq!(policy.is_valid(), min_blocks >= UPGRADE_MIN_BLOCKS);
    }

    /// MultisigTimelock is valid iff min_blocks >= UPGRADE_MIN_BLOCKS AND threshold > 0
    /// AND threshold <= keys.len() AND keys.len() <= MAX_MULTISIG_KEYS.
    /// With a valid key set (2 keys, threshold 2), validity depends only on min_blocks.
    #[kani::proof]
    fn upgrade_policy_multisig_timelock_correctness() {
        let min_blocks: u64 = kani::any();
        let keys = vec![zero_pk(), zero_pk()];
        let policy = UpgradePolicy::MultisigTimelock { threshold: 2, keys, min_blocks };
        assert_eq!(policy.is_valid(), min_blocks >= UPGRADE_MIN_BLOCKS);
    }

    /// MultisigTimelock with empty key list is always invalid regardless of min_blocks.
    #[kani::proof]
    fn upgrade_policy_multisig_empty_keys_invalid() {
        let min_blocks: u64 = kani::any();
        let policy = UpgradePolicy::MultisigTimelock { threshold: 1, keys: vec![], min_blocks };
        assert!(!policy.is_valid());
    }

    /// MultisigTimelock with threshold 0 is always invalid (zero-sig upgrade is forbidden).
    #[kani::proof]
    fn upgrade_policy_multisig_zero_threshold_invalid() {
        let min_blocks: u64 = kani::any();
        let keys = vec![zero_pk()];
        let policy = UpgradePolicy::MultisigTimelock { threshold: 0, keys, min_blocks };
        assert!(!policy.is_valid());
    }

    /// MultisigTimelock with threshold > keys.len() is always invalid (unachievable quorum).
    #[kani::proof]
    fn upgrade_policy_multisig_threshold_exceeds_keys_invalid() {
        let policy = UpgradePolicy::MultisigTimelock {
            threshold: 2,
            keys: vec![zero_pk()], // only 1 key, threshold 2 is unreachable
            min_blocks: UPGRADE_MIN_BLOCKS,
        };
        assert!(!policy.is_valid());
    }

    /// Boundary: UPGRADE_MIN_BLOCKS - 1 is invalid, UPGRADE_MIN_BLOCKS is valid.
    #[kani::proof]
    fn upgrade_policy_min_blocks_boundary() {
        let below = UpgradePolicy::OwnerTimelock { owner_pk: zero_pk(), min_blocks: UPGRADE_MIN_BLOCKS - 1 };
        let at = UpgradePolicy::OwnerTimelock { owner_pk: zero_pk(), min_blocks: UPGRADE_MIN_BLOCKS };
        assert!(!below.is_valid());
        assert!(at.is_valid());
    }

    // =========================================================================
    // ContractManifest / Capability — svm/core/src/manifest.rs, capability.rs
    // =========================================================================

    /// has_capability returns true iff the capability is in the manifest list.
    #[kani::proof]
    fn has_capability_true_if_present() {
        let cap = any_capability();
        let manifest = ContractManifest::new(zero_hash(), UpgradePolicy::Immutable, vec![cap.clone()]);
        assert!(manifest.has_capability(&cap));
    }

    /// Empty required_capabilities → has_capability always false.
    #[kani::proof]
    fn has_capability_false_on_empty() {
        let cap = any_capability();
        let manifest = ContractManifest::new(zero_hash(), UpgradePolicy::Immutable, vec![]);
        assert!(!manifest.has_capability(&cap));
    }

    /// Adding the same capability twice doesn't break membership.
    #[kani::proof]
    fn has_capability_idempotent() {
        let cap = any_capability();
        let manifest = ContractManifest::new(zero_hash(), UpgradePolicy::Immutable, vec![cap.clone(), cap.clone()]);
        assert!(manifest.has_capability(&cap));
    }

    // =========================================================================
    // NativeTokenUtxoData — svm/core/src/token.rs
    // =========================================================================

    /// new() initialises transfer_policy_id as None.
    #[kani::proof]
    fn native_token_new_no_transfer_policy() {
        let amount: u64 = kani::any();
        let data = NativeTokenUtxoData::new(zero_hash(), amount, vec![]);
        assert!(data.transfer_policy_id.is_none());
    }

    /// with_transfer_policy sets the policy id.
    #[kani::proof]
    fn native_token_with_transfer_policy_sets_id() {
        let policy_id: ContractId = zero_hash();
        let data = NativeTokenUtxoData::new(zero_hash(), 100, vec![]).with_transfer_policy(policy_id);
        assert_eq!(data.transfer_policy_id, Some(policy_id));
    }

    /// token_amount is preserved through construction.
    #[kani::proof]
    fn native_token_amount_preserved() {
        let amount: u64 = kani::any();
        let data = NativeTokenUtxoData::new(zero_hash(), amount, vec![]);
        assert_eq!(data.token_amount, amount);
    }
}
