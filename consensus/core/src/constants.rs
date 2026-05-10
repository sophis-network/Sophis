/// BLOCK_VERSION represents the current block version
pub const BLOCK_VERSION: u16 = 1;

/// TX_VERSION is the default version used when constructing new transactions.
/// Existing v=0 transactions remain valid forever; producers that do not need
/// L1 ALT references should keep using this constant.
pub const TX_VERSION: u16 = 0;

/// MAX_TX_VERSION is the highest transaction version the consensus layer
/// accepts. Versions in `[TX_VERSION, MAX_TX_VERSION]` are all valid; each
/// version may enable additional features (currently only v=1 enables L1 ALT
/// creation outputs and ALT references — see `consensus/core/src/alt/`).
///
/// Activated at genesis on every network: there is no soft-fork window
/// because Sophis has not launched, so `min_alt_activation_daa_score = 0`.
/// See `docs/L1_ALT_DESIGN.md` §3.1 for the version semantics matrix.
pub const MAX_TX_VERSION: u16 = 1;

pub const LOCK_TIME_THRESHOLD: u64 = 500_000_000_000;

/// MAX_SCRIPT_PUBLIC_KEY_VERSION is the current latest supported public key script version.
///
/// Allocated SPK versions:
///  - 0  standard (P2PKH-Dilithium / P2SH-Dilithium)
///  - 1  SCRIPT_VERSION_CONTRACT (sVM dispatch)
///  - 2  SCRIPT_VERSION_TOKEN (native token UTXO)
///  - 3  BRIDGE_VAULT_VERSION (Phase 3 internal rollup deposit; `rollup/bridge/deposit/src/lib.rs`)
///  - 4  BRIDGE_CLAIM_VERSION (Phase 3 internal rollup withdrawal claim; `rollup/bridge/withdrawal/src/lib.rs`)
///  - 5  SCRIPT_VERSION_CARRIER (Phase 6 DA carrier output; `da` module)
pub const MAX_SCRIPT_PUBLIC_KEY_VERSION: u16 = 5;

/// SCRIPT_VERSION_CONTRACT marks a Contract UTXO (sVM dispatch).
/// script_public_key.script() for this version contains borsh-serialized ContractUtxoData.
pub const SCRIPT_VERSION_CONTRACT: u16 = 1;

/// SCRIPT_VERSION_TOKEN marks a Native Token UTXO.
/// script_public_key.script() for this version contains borsh-serialized NativeTokenUtxoData.
pub const SCRIPT_VERSION_TOKEN: u16 = 2;

/// SCRIPT_VERSION_CARRIER marks a Phase 6 Data Availability carrier output.
/// script_public_key.script() carries the CARRIER_MAGIC header + opaque bytes.
/// Carrier outputs are unspendable and must have value == 0.
/// See `da::parse_carrier_header` and `oracle/docs/PHASE6_DA_DESIGN.md`.
///
/// Versions 3 and 4 are reserved by the Phase 3 internal rollup
/// (`BRIDGE_VAULT_VERSION` and `BRIDGE_CLAIM_VERSION`); the carrier was
/// allocated to 5 to avoid the collision the original design doc missed.
pub const SCRIPT_VERSION_CARRIER: u16 = 5;

/// SompiPerSophis is the number of sompi in one sophis (1 SPHS).
pub const SOMPI_PER_SOPHIS: u64 = 100_000_000;

/// The parameter for scaling inverse SPHS value to mass units (KIP-0009)
pub const STORAGE_MASS_PARAMETER: u64 = SOMPI_PER_SOPHIS * 10_000;

/// The parameter defining how much mass per byte to charge for when calculating
/// transient storage mass. Since normally the block mass limit is 500_000, this limits
/// block body byte size to 125_000 (KIP-0013).
pub const TRANSIENT_BYTE_TO_MASS_FACTOR: u64 = 4;

/// MaxSompi is the maximum transaction amount allowed in sompi.
pub const MAX_SOMPI: u64 = 210_000_000 * SOMPI_PER_SOPHIS;

// MAX_TX_IN_SEQUENCE_NUM is the maximum sequence number the sequence field
// of a transaction input can be.
pub const MAX_TX_IN_SEQUENCE_NUM: u64 = u64::MAX;

// SEQUENCE_LOCK_TIME_MASK is a mask that extracts the relative lock time
// when masked against the transaction input sequence number.
pub const SEQUENCE_LOCK_TIME_MASK: u64 = 0x00000000ffffffff;

// SEQUENCE_LOCK_TIME_DISABLED is a flag that if set on a transaction
// input's sequence number, the sequence number will not be interpreted
// as a relative lock time.
pub const SEQUENCE_LOCK_TIME_DISABLED: u64 = 1 << 63;

/// UNACCEPTED_DAA_SCORE is used to for UtxoEntries that were created by
/// transactions in the mempool, or otherwise not-yet-accepted transactions.
pub const UNACCEPTED_DAA_SCORE: u64 = u64::MAX;
