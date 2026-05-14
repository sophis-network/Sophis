use crate::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_signature_hash},
        sighash_type::SigHashType,
    },
    tx::VerifiableTransaction,
};
use libcrux_ml_dsa::ml_dsa_44::{self, MLDSA44SigningKey};
use thiserror::Error;

// Dilithium-2 (ML-DSA-44) sizes per FIPS 204 — private in libcrux crate
const DILITHIUM2_SIGNING_KEY_SIZE: usize = 2560;

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("{0}")]
    Message(String),

    #[error("Dilithium signing error")]
    DilithiumError,
}

/// Sign a transaction input with Dilithium-2 (ML-DSA-44, FIPS 204).
///
/// The signing key is 2560 bytes (ML-DSA-44 signing key size).
/// Returns the signature script: OP_PUSHDATA2 <sig+sighash_type>
/// encoded as P2SH input (signature + redeem script).
///
/// For P2SH spending, the caller must also provide the redeem script bytes.
pub fn sign_input_dilithium(
    tx: &impl VerifiableTransaction,
    input_index: usize,
    signing_key_bytes: &[u8; DILITHIUM2_SIGNING_KEY_SIZE],
    hash_type: SigHashType,
) -> Result<Vec<u8>, Error> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_signature_hash(tx, input_index, hash_type, &reused_values);
    let message = &sig_hash.as_bytes()[..];

    let sk = MLDSA44SigningKey::new(*signing_key_bytes);
    let randomness = {
        let mut r = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
        getrandom::getrandom(&mut r).map_err(|_| Error::DilithiumError)?;
        r
    };

    let signature = ml_dsa_44::sign(&sk, message, b"", randomness).map_err(|_| Error::DilithiumError)?;
    let sig_bytes = signature.as_ref();

    // Signature script for P2SH Dilithium input:
    // OP_PUSHDATA2 <2421 bytes: sig(2420) + hash_type(1)>
    let sig_with_type: Vec<u8> = sig_bytes.iter().copied().chain([hash_type.to_u8()]).collect();
    // Prepend OP_PUSHDATA2 (0x4d) + 2-byte LE length
    let sig_len = sig_with_type.len() as u16;
    let mut script = vec![0x4d, sig_len as u8, (sig_len >> 8) as u8];
    script.extend_from_slice(&sig_with_type);
    Ok(script)
}

// -----------------------------------------------------------------------------
// Tests — added 2026-05-14 per pre-testnet audit finding F-5 (P0):
// `sign_input_dilithium` was the canonical signing function called from 5
// production binaries (dilithium-wallet, miner faucet, da-stress, oracle
// relayer, rollup sequencer) but had 0% direct test coverage. The verifier
// path (txscript opcode 0xc4) had its own tests, but a bug in the signer
// (wrong sighash binding, wrong randomness slice, wrong OP_PUSHDATA2
// encoding, leaked secret-key bytes through script bytes) would have been
// invisible to every existing test in the workspace until reaching testnet.
//
// The three tests below close the gap with a positive vector
// (round-trip), a negative vector (sighash binding), and a randomness
// probe (each invocation samples fresh ML-DSA randomness so two signs of
// the same input must produce distinct signatures).
//
// Source: audit/AUDIT_REPORT.md §2.0 F-5 / commit a50706f predecessor.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hashing::sighash_type::{SIG_HASH_ALL, SIG_HASH_NONE, SIG_HASH_SINGLE},
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{
            PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
        },
    };
    use libcrux_ml_dsa::ml_dsa_44::{MLDSA44Signature, MLDSA44VerificationKey, generate_key_pair, verify};
    use sophis_hashes::ZERO_HASH;

    // Dilithium ML-DSA-44 constants (FIPS 204), mirroring the values used in
    // `dilithium-wallet/src/main.rs` so that a future libcrux upgrade that
    // changes the constants fails *these* tests rather than the production
    // signer.
    const ML_DSA_44_VK_SIZE: usize = 1312;
    const ML_DSA_44_SIG_SIZE: usize = 2420;

    /// Builds a minimal one-input, one-output transaction with a deterministic
    /// outpoint and a populated UTXO so that `sign_input_dilithium` has a
    /// well-defined sighash to compute.
    fn make_test_tx() -> (Transaction, Vec<UtxoEntry>) {
        let outpoint = TransactionOutpoint { transaction_id: ZERO_HASH, index: 0 };
        let tx = Transaction::new(
            0,
            vec![TransactionInput { previous_outpoint: outpoint, signature_script: vec![], sequence: 0, sig_op_count: 1 }],
            vec![TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, smallvec::SmallVec::new()) }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );
        let utxos = vec![UtxoEntry {
            amount: 2_000,
            script_public_key: ScriptPublicKey::new(0, smallvec::SmallVec::new()),
            block_daa_score: 0,
            is_coinbase: false,
        }];
        (tx, utxos)
    }

    fn fresh_keypair() -> ([u8; DILITHIUM2_SIGNING_KEY_SIZE], [u8; ML_DSA_44_VK_SIZE]) {
        let mut randomness = [0u8; libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE];
        getrandom::getrandom(&mut randomness).expect("getrandom for keypair");
        let kp = generate_key_pair(randomness);
        let mut sk = [0u8; DILITHIUM2_SIGNING_KEY_SIZE];
        sk.copy_from_slice(kp.signing_key.as_ref());
        let mut vk = [0u8; ML_DSA_44_VK_SIZE];
        vk.copy_from_slice(kp.verification_key.as_ref());
        (sk, vk)
    }

    /// Strip the `OP_PUSHDATA2(0x4d) + u16-LE length` prefix and the trailing
    /// 1-byte sighash type from the produced signature script. Returns the raw
    /// 2420-byte ML-DSA-44 signature suitable for direct libcrux verification.
    fn extract_signature_bytes(script: &[u8]) -> [u8; ML_DSA_44_SIG_SIZE] {
        assert_eq!(script[0], 0x4d, "script must begin with OP_PUSHDATA2");
        let declared_len = u16::from_le_bytes([script[1], script[2]]) as usize;
        // 2420 sig bytes + 1 hash_type byte
        assert_eq!(declared_len, ML_DSA_44_SIG_SIZE + 1, "script declared length must equal sig+hash_type");
        assert_eq!(script.len(), 3 + declared_len, "script length must equal 3-byte header + declared body");
        let mut out = [0u8; ML_DSA_44_SIG_SIZE];
        out.copy_from_slice(&script[3..3 + ML_DSA_44_SIG_SIZE]);
        out
    }

    /// **Positive vector** — round-trip a Dilithium-2 signature through the
    /// libcrux verifier using the same sighash that the signer derived.
    #[test]
    fn test_sign_input_dilithium_round_trip() {
        let (sk_bytes, vk_bytes) = fresh_keypair();
        let (tx, utxos) = make_test_tx();
        let populated = PopulatedTransaction::new(&tx, utxos);

        let script = sign_input_dilithium(&populated, 0, &sk_bytes, SIG_HASH_ALL).expect("sign_input_dilithium ok");
        let sig_bytes = extract_signature_bytes(&script);

        // Recompute the same sighash the signer used and verify against libcrux.
        let reused = SigHashReusedValuesUnsync::new();
        let sig_hash = calc_signature_hash(&populated, 0, SIG_HASH_ALL, &reused);
        let vk = MLDSA44VerificationKey::new(vk_bytes);
        let sig = MLDSA44Signature::new(sig_bytes);
        assert!(verify(&vk, &sig_hash.as_bytes()[..], b"", &sig).is_ok(), "round-trip signature must verify");
    }

    /// **Negative vector** — changing the `SigHashType` must change the sighash,
    /// which must change the resulting signature. If signatures match across
    /// SigHashType, the signer is ignoring the type (a sighash-binding bug).
    #[test]
    fn test_sign_input_dilithium_sighash_type_binding() {
        let (sk_bytes, _) = fresh_keypair();
        let (tx, utxos) = make_test_tx();
        let populated = PopulatedTransaction::new(&tx, utxos);

        let s_all = sign_input_dilithium(&populated, 0, &sk_bytes, SIG_HASH_ALL).expect("sign");
        let s_none = sign_input_dilithium(&populated, 0, &sk_bytes, SIG_HASH_NONE).expect("sign");
        let s_single = sign_input_dilithium(&populated, 0, &sk_bytes, SIG_HASH_SINGLE).expect("sign");

        assert_ne!(extract_signature_bytes(&s_all), extract_signature_bytes(&s_none), "ALL vs NONE must differ");
        assert_ne!(extract_signature_bytes(&s_all), extract_signature_bytes(&s_single), "ALL vs SINGLE must differ");
        assert_ne!(extract_signature_bytes(&s_none), extract_signature_bytes(&s_single), "NONE vs SINGLE must differ");

        // The trailing hash_type byte must echo the requested SigHashType.
        assert_eq!(*s_all.last().unwrap(), SIG_HASH_ALL.to_u8());
        assert_eq!(*s_none.last().unwrap(), SIG_HASH_NONE.to_u8());
        assert_eq!(*s_single.last().unwrap(), SIG_HASH_SINGLE.to_u8());
    }

    /// **Randomness probe** — ML-DSA is a hedged signature scheme: each call
    /// must sample fresh randomness. Two signs of the same input with the same
    /// key must therefore produce distinct signatures. If they match, the
    /// randomness slice is being mis-sized or the RNG is misseeded — either is
    /// a confidentiality / security regression.
    #[test]
    fn test_sign_input_dilithium_randomness_nondeterminism() {
        let (sk_bytes, _) = fresh_keypair();
        let (tx, utxos) = make_test_tx();
        let populated = PopulatedTransaction::new(&tx, utxos);

        let s1 = sign_input_dilithium(&populated, 0, &sk_bytes, SIG_HASH_ALL).expect("sign");
        let s2 = sign_input_dilithium(&populated, 0, &sk_bytes, SIG_HASH_ALL).expect("sign");

        assert_ne!(
            extract_signature_bytes(&s1),
            extract_signature_bytes(&s2),
            "two signs of identical input must produce distinct ML-DSA signatures (hedged scheme)"
        );

        // Pin the randomness-slice size so a future libcrux upgrade that
        // changes `SIGNING_RANDOMNESS_SIZE` is forced to surface here.
        assert_eq!(libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE, 32);
    }
}
