use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_256, Sha3_384};

// ---------------------------------------------------------------------------
// Primitive types
// ---------------------------------------------------------------------------

/// SHA3-384 of a Dilithium ML-DSA-44 verification key.
/// L2 uses derivation path m/44'/111111'/0'/1/0 — distinct from L1 (0'/0/0).
/// Same mnemonic, different key → no on-chain linkability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct L2Address(pub [u8; 48]);

impl L2Address {
    pub fn from_verkey(vk: &[u8]) -> Self {
        let mut h = Sha3_384::new();
        h.update(vk);
        Self(h.finalize().into())
    }
}

/// SHA3-384 Merkle root of the live L2 UTXO set.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StateRoot(pub [u8; 48]);

impl Default for StateRoot {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

/// Unique identifier for an L2 UTXO.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct L2UtxoId {
    pub txid: [u8; 32],
    pub index: u32,
}

// ---------------------------------------------------------------------------
// UTXO
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct L2Utxo {
    pub id: L2UtxoId,
    pub address: L2Address,
    pub amount: u64, // sompi
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

/// Body of an L2 tx — what inputs must sign over.
/// Excludes signatures/verkeys so sig_hash is stable at signing time.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct L2TxBody {
    pub input_utxo_ids: Vec<L2UtxoId>,
    pub outputs: Vec<L2TxOutput>,
    pub fee: u64,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct L2TxOutput {
    pub address: L2Address,
    pub amount: u64,
}

/// One signed input: identifies the UTXO being spent + Dilithium proof of ownership.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct L2TxInput {
    pub utxo_id: L2UtxoId,
    pub verification_key: Box<[u8; 1312]>, // ML-DSA-44 verkey
    pub signature: Box<[u8; 2420]>,        // ML-DSA-44 signature over sig_hash
}

/// A complete L2 transaction.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct L2Tx {
    pub body: L2TxBody,
    pub inputs: Vec<L2TxInput>,
}

impl L2Tx {
    /// Bytes that every input must sign. Excludes signatures/verkeys.
    pub fn sig_hash(&self) -> [u8; 32] {
        let bytes = borsh::to_vec(&self.body).unwrap_or_default();
        let mut h = Sha3_256::new();
        h.update(b"sophis-l2-sighash:");
        h.update(&bytes);
        h.finalize().into()
    }

    /// Full transaction ID (post-signing, includes everything).
    pub fn txid(&self) -> [u8; 32] {
        let bytes = borsh::to_vec(self).unwrap_or_default();
        let mut h = Sha3_256::new();
        h.update(b"sophis-l2-txid:");
        h.update(&bytes);
        h.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Bridge primitives
// ---------------------------------------------------------------------------

/// Deposit: locks SPHS on L1 → mints L2 UTXO.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Deposit {
    pub l1_tx_id: [u8; 32],
    pub l1_output_index: u32,
    pub l2_address: L2Address,
    pub amount: u64,
}

/// Withdrawal: burns L2 UTXO → releases SPHS on L1.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Withdrawal {
    pub l2_tx_id: [u8; 32],
    pub l1_address: [u8; 48], // SHA3-384 of L1 Dilithium verkey
    pub amount: u64,
}

// ---------------------------------------------------------------------------
// Batch
// ---------------------------------------------------------------------------

/// A batch of L2 txs submitted by the sequencer for ZK proving.
/// Trigger: 100 txs OR 30 seconds (whichever comes first).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Batch {
    pub sequence: u64,
    /// L1 DAG block that anchors this batch (sequencer = miner of block N×100).
    pub l1_anchor_block: u64,
    pub prev_state_root: StateRoot,
    pub txs: Vec<L2Tx>,
    pub deposits: Vec<Deposit>,
    pub withdrawals: Vec<Withdrawal>,
}

impl Batch {
    pub fn hash(&self) -> [u8; 32] {
        let bytes = borsh::to_vec(self).unwrap_or_default();
        let mut h = Sha3_256::new();
        h.update(b"sophis-l2-batch:");
        h.update(&bytes);
        h.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Journal (public output committed on L1 after proof verification)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BatchJournal {
    pub sequence: u64,
    pub prev_state_root: StateRoot,
    pub new_state_root: StateRoot,
    pub batch_hash: [u8; 32],
    pub deposit_count: u32,
    pub withdrawal_count: u32,
    /// SHA3-384("sophis-l2-withdrawals:" || borsh(withdrawals)).
    /// Lets the bridge withdrawal contract verify a specific withdrawal is in this batch.
    pub withdrawals_hash: [u8; 48],
    pub l1_anchor_block: u64,
    /// Phase 6 — `bundle_id = SHA3-384(borsh(Batch))` of the calldata published
    /// in the companion `T_carrier` transaction. Allows any verifier to bind
    /// the journal to its source bytes by calling
    /// `Capability::VerifyDataAvailability(bundle_id)` on the L1.
    /// All-zero is a sentinel that means "no DA carrier published" — used
    /// only for legacy or test paths; production sequencers must populate it.
    pub da_bundle_id: [u8; 48],
}

/// Hash a slice of withdrawals for inclusion in the BatchJournal.
pub fn hash_withdrawals(withdrawals: &[Withdrawal]) -> [u8; 48] {
    let bytes = borsh::to_vec(withdrawals).unwrap_or_default();
    let mut h = Sha3_384::new();
    h.update(b"sophis-l2-withdrawals:");
    h.update(&bytes);
    h.finalize().into()
}
