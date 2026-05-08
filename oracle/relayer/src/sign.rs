//! Sub-fase 5.4.d — Dilithium ML-DSA-44 signing of `RelayerBundle`.
//!
//! The relayer holds an ML-DSA-44 signing key (2560 bytes, FIPS 204) plus
//! its derived verification key (1312 bytes). It signs a SHA3-256
//! commitment over the bundle so the on-chain contract can re-derive the
//! same hash from the wire payload and verify the signature with
//! `Capability::VerifyDilithium`.
//!
//! ## Bundle commitment (stable ABI)
//!
//! ```text
//! commit := SHA3-256(
//!     BUNDLE_DOMAIN_V1
//!     || borsh(journal)
//!     || u64_le(now_secs)
//!     || u32_le(oracle_proof.len()) || oracle_proof
//!     || u32_le(verify_air_proof.len()) || verify_air_proof          (zero-length if absent)
//!     || u32_le(verify_air_public_values.len()) || verify_air_public_values
//! )
//! ```
//!
//! Length prefixes make the layout unambiguous regardless of optional
//! companion presence. `now_secs` is folded into the commitment so the
//! contract's `OracleAir` public-values reconstruction matches the
//! prover's choice exactly.
//!
//! ## Wire payload (sub-fase 5.4.e will ship this in the contract invocation tx)
//!
//! ```text
//! [u8;  N1]     borsh(journal)               (N1 prefixed by leading u32_le)
//! [u8;  N2]     oracle_proof                 (N2 prefixed by leading u32_le)
//! [u8;  N3]     verify_air_proof             (N3 prefixed; 0 if absent)
//! [u8;  N4]     verify_air_public_values     (N4 prefixed; 0 if absent)
//! [u8;   8]     now_secs                     (u64_le)
//! [u8; 1312]    relayer_verification_key
//! [u8; 2420]    relayer_signature
//! ```
//!
//! Layout chosen so the contract can decode in one streaming pass:
//! length-prefixed variable parts first, then fixed-size trailers.

use libcrux_ml_dsa::ml_dsa_44::{self, MLDSA44Signature, MLDSA44SigningKey, MLDSA44VerificationKey};
use sha3::{Digest, Sha3_256};
use std::path::Path;

use crate::pipeline::RelayerBundle;

pub const BUNDLE_DOMAIN_V1: &[u8] = b"sophis-oracle-relayer-bundle-v1:";
pub const ML_DSA_44_SK_SIZE: usize = 2560;
pub const ML_DSA_44_VK_SIZE: usize = 1312;
pub const ML_DSA_44_SIG_SIZE: usize = 2420;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("io error reading key file: {0}")]
    Io(#[from] std::io::Error),
    #[error("signing key file has wrong length: got {got}, want {want}")]
    BadSigningKeyLen { got: usize, want: usize },
    #[error("verification key file has wrong length: got {got}, want {want}")]
    BadVerificationKeyLen { got: usize, want: usize },
    #[error("borsh serialization failed: {0}")]
    Serialization(String),
    #[error("Dilithium signing failed")]
    DilithiumSign,
    #[error("getrandom failed: {0}")]
    GetRandom(String),
}

/// Loaded relayer keypair. The VK is kept alongside the SK because the
/// wire payload includes the VK — contracts validate the relayer against
/// an on-chain allowlist of VK fingerprints, not against an external
/// registry.
pub struct RelayerKey {
    pub signing_key: Box<[u8; ML_DSA_44_SK_SIZE]>,
    pub verification_key: Box<[u8; ML_DSA_44_VK_SIZE]>,
}

impl RelayerKey {
    /// Load a relayer key from disk.
    ///
    /// Layout: `<sk_path>` is 2560 raw bytes; `<sk_path>.vk` (sibling
    /// suffix) is 1312 raw bytes. Both are required — we never derive the
    /// VK from the SK at load time because libcrux exposes the keypair
    /// only through `generate_key_pair`, not key-derivation, so the safe
    /// thing is to demand both files were written together.
    pub fn load(sk_path: &Path) -> Result<Self, SignError> {
        let sk_bytes = std::fs::read(sk_path)?;
        if sk_bytes.len() != ML_DSA_44_SK_SIZE {
            return Err(SignError::BadSigningKeyLen { got: sk_bytes.len(), want: ML_DSA_44_SK_SIZE });
        }
        let mut sk_arr = [0u8; ML_DSA_44_SK_SIZE];
        sk_arr.copy_from_slice(&sk_bytes);

        let vk_path = vk_sibling_path(sk_path);
        let vk_bytes = std::fs::read(&vk_path)?;
        if vk_bytes.len() != ML_DSA_44_VK_SIZE {
            return Err(SignError::BadVerificationKeyLen { got: vk_bytes.len(), want: ML_DSA_44_VK_SIZE });
        }
        let mut vk_arr = [0u8; ML_DSA_44_VK_SIZE];
        vk_arr.copy_from_slice(&vk_bytes);

        Ok(RelayerKey { signing_key: Box::new(sk_arr), verification_key: Box::new(vk_arr) })
    }
}

fn vk_sibling_path(sk_path: &Path) -> std::path::PathBuf {
    let mut p = sk_path.as_os_str().to_owned();
    p.push(".vk");
    p.into()
}

/// Compute the bundle commitment hash (32 bytes) used as the message the
/// relayer signs. Stable ABI — changing this is a hard fork of the
/// relayer↔contract protocol.
pub fn bundle_commitment(bundle: &RelayerBundle) -> Result<[u8; 32], SignError> {
    let journal_bytes = borsh::to_vec(&bundle.journal).map_err(|e| SignError::Serialization(e.to_string()))?;
    let mut hasher = Sha3_256::new();
    hasher.update(BUNDLE_DOMAIN_V1);
    hasher.update(&journal_bytes);
    hasher.update(bundle.now_secs.to_le_bytes());
    hasher.update((bundle.oracle_proof_bytes.len() as u32).to_le_bytes());
    hasher.update(&bundle.oracle_proof_bytes);
    let va_proof: &[u8] = bundle.verify_air_proof_bytes.as_deref().unwrap_or(&[]);
    hasher.update((va_proof.len() as u32).to_le_bytes());
    hasher.update(va_proof);
    let va_pv: &[u8] = bundle.verify_air_public_values.as_deref().unwrap_or(&[]);
    hasher.update((va_pv.len() as u32).to_le_bytes());
    hasher.update(va_pv);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Sign the bundle commitment with the relayer's ML-DSA-44 secret key.
/// Returns a 2420-byte signature.
pub fn sign_bundle(bundle: &RelayerBundle, key: &RelayerKey) -> Result<[u8; ML_DSA_44_SIG_SIZE], SignError> {
    let commit = bundle_commitment(bundle)?;
    let sk = MLDSA44SigningKey::new(*key.signing_key);
    let mut randomness = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
    getrandom::getrandom(&mut randomness).map_err(|e| SignError::GetRandom(e.to_string()))?;
    let signature: MLDSA44Signature = ml_dsa_44::sign(&sk, &commit, b"", randomness).map_err(|_| SignError::DilithiumSign)?;
    let sig_bytes = signature.as_ref();
    let mut out = [0u8; ML_DSA_44_SIG_SIZE];
    out.copy_from_slice(sig_bytes);
    Ok(out)
}

/// Verify a bundle signature against a verification key. Used by tests
/// and by the on-chain contract emulator. Returns `true` iff the
/// signature is valid for the bundle's commitment hash.
pub fn verify_bundle_signature(
    bundle: &RelayerBundle,
    signature: &[u8; ML_DSA_44_SIG_SIZE],
    vk_bytes: &[u8; ML_DSA_44_VK_SIZE],
) -> Result<bool, SignError> {
    let commit = bundle_commitment(bundle)?;
    let vk = MLDSA44VerificationKey::new(*vk_bytes);
    let sig = MLDSA44Signature::new(*signature);
    Ok(ml_dsa_44::verify(&vk, &commit, b"", &sig).is_ok())
}

/// SignedBundle is the value the submit layer (5.4.e) ships on the wire.
#[derive(Debug, Clone)]
pub struct SignedBundle {
    pub bundle: RelayerBundle,
    pub signature: [u8; ML_DSA_44_SIG_SIZE],
    pub verification_key: Box<[u8; ML_DSA_44_VK_SIZE]>,
}

impl SignedBundle {
    /// Encode to the wire payload format documented in the module header.
    /// Sub-fase 5.4.e calls this and wraps the bytes inside a
    /// `ScriptPublicKey` of an `ORACLE_INVOKE_VERSION` UTXO.
    pub fn encode_wire(&self) -> Result<Vec<u8>, SignError> {
        let journal_bytes = borsh::to_vec(&self.bundle.journal).map_err(|e| SignError::Serialization(e.to_string()))?;
        let va_proof: &[u8] = self.bundle.verify_air_proof_bytes.as_deref().unwrap_or(&[]);
        let va_pv: &[u8] = self.bundle.verify_air_public_values.as_deref().unwrap_or(&[]);

        let mut out = Vec::with_capacity(
            4 + journal_bytes.len()
                + 4 + self.bundle.oracle_proof_bytes.len()
                + 4 + va_proof.len()
                + 4 + va_pv.len()
                + 8 + ML_DSA_44_VK_SIZE + ML_DSA_44_SIG_SIZE,
        );
        push_lp(&mut out, &journal_bytes);
        push_lp(&mut out, &self.bundle.oracle_proof_bytes);
        push_lp(&mut out, va_proof);
        push_lp(&mut out, va_pv);
        out.extend_from_slice(&self.bundle.now_secs.to_le_bytes());
        out.extend_from_slice(&self.verification_key[..]);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Decode a wire payload back into its components. Used by the on-chain
/// emulator and by integration tests in 5.4.f.
pub fn decode_wire(payload: &[u8]) -> Option<DecodedWire> {
    let mut cur = 0usize;
    let journal = read_lp(payload, &mut cur)?;
    let oracle_proof = read_lp(payload, &mut cur)?;
    let verify_air_proof = read_lp(payload, &mut cur)?;
    let verify_air_pv = read_lp(payload, &mut cur)?;
    if cur + 8 + ML_DSA_44_VK_SIZE + ML_DSA_44_SIG_SIZE > payload.len() {
        return None;
    }
    let mut now_arr = [0u8; 8];
    now_arr.copy_from_slice(&payload[cur..cur + 8]);
    cur += 8;
    let now_secs = u64::from_le_bytes(now_arr);
    let mut vk = [0u8; ML_DSA_44_VK_SIZE];
    vk.copy_from_slice(&payload[cur..cur + ML_DSA_44_VK_SIZE]);
    cur += ML_DSA_44_VK_SIZE;
    let mut sig = [0u8; ML_DSA_44_SIG_SIZE];
    sig.copy_from_slice(&payload[cur..cur + ML_DSA_44_SIG_SIZE]);
    cur += ML_DSA_44_SIG_SIZE;
    if cur != payload.len() {
        return None;
    }
    Some(DecodedWire {
        journal_borsh: journal,
        oracle_proof,
        verify_air_proof: if verify_air_proof.is_empty() { None } else { Some(verify_air_proof) },
        verify_air_pv: if verify_air_pv.is_empty() { None } else { Some(verify_air_pv) },
        now_secs,
        verification_key: Box::new(vk),
        signature: Box::new(sig),
    })
}

fn read_lp(payload: &[u8], cur: &mut usize) -> Option<Vec<u8>> {
    if *cur + 4 > payload.len() {
        return None;
    }
    let mut lenb = [0u8; 4];
    lenb.copy_from_slice(&payload[*cur..*cur + 4]);
    *cur += 4;
    let len = u32::from_le_bytes(lenb) as usize;
    if *cur + len > payload.len() {
        return None;
    }
    let v = payload[*cur..*cur + len].to_vec();
    *cur += len;
    Some(v)
}

#[derive(Debug, Clone)]
pub struct DecodedWire {
    pub journal_borsh: Vec<u8>,
    pub oracle_proof: Vec<u8>,
    pub verify_air_proof: Option<Vec<u8>>,
    pub verify_air_pv: Option<Vec<u8>>,
    pub now_secs: u64,
    pub verification_key: Box<[u8; ML_DSA_44_VK_SIZE]>,
    pub signature: Box<[u8; ML_DSA_44_SIG_SIZE]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{build_bundle, fixture_submission, PipelinePolicy};
    use libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE;
    use sophis_oracle_core::{FeedId, PublisherKey};
    use std::io::Write;

    fn make_keypair() -> RelayerKey {
        let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        getrandom::getrandom(&mut randomness).unwrap();
        let kp = ml_dsa_44::generate_key_pair(randomness);
        let mut sk = [0u8; ML_DSA_44_SK_SIZE];
        let mut vk = [0u8; ML_DSA_44_VK_SIZE];
        sk.copy_from_slice(kp.signing_key.as_ref());
        vk.copy_from_slice(kp.verification_key.as_ref());
        RelayerKey { signing_key: Box::new(sk), verification_key: Box::new(vk) }
    }

    fn ok_policy() -> PipelinePolicy {
        PipelinePolicy {
            feed: FeedId(*b"BTC/USD\0"),
            publisher: PublisherKey([1u8; 32]),
            min_price: 1_000_00,
            max_price: 1_000_000_00,
            max_age_secs: 60,
            verify_air_companion: false,
        }
    }

    fn ok_bundle() -> RelayerBundle {
        let sub = fixture_submission(65_000_00, 1_700_000_080, [1u8; 32]);
        build_bundle(sub, &ok_policy(), 100, 99, 1_700_000_120).unwrap()
    }

    #[test]
    fn bundle_commitment_is_deterministic() {
        let b = ok_bundle();
        let c1 = bundle_commitment(&b).unwrap();
        let c2 = bundle_commitment(&b).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn bundle_commitment_changes_with_journal_mutation() {
        let mut b = ok_bundle();
        let c1 = bundle_commitment(&b).unwrap();
        b.journal.price ^= 1;
        let c2 = bundle_commitment(&b).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn bundle_commitment_changes_with_now_secs() {
        let mut b = ok_bundle();
        let c1 = bundle_commitment(&b).unwrap();
        b.now_secs += 1;
        let c2 = bundle_commitment(&b).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let kp = make_keypair();
        let bundle = ok_bundle();
        let sig = sign_bundle(&bundle, &kp).expect("sign ok");
        assert!(verify_bundle_signature(&bundle, &sig, &kp.verification_key).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_bundle() {
        let kp = make_keypair();
        let bundle = ok_bundle();
        let sig = sign_bundle(&bundle, &kp).expect("sign ok");
        let mut bad = bundle.clone();
        bad.journal.price ^= 1;
        assert!(!verify_bundle_signature(&bad, &sig, &kp.verification_key).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_vk() {
        let kp = make_keypair();
        let other = make_keypair();
        let bundle = ok_bundle();
        let sig = sign_bundle(&bundle, &kp).expect("sign ok");
        assert!(!verify_bundle_signature(&bundle, &sig, &other.verification_key).unwrap());
    }

    #[test]
    fn wire_round_trip_no_companion() {
        let kp = make_keypair();
        let bundle = ok_bundle();
        let sig = sign_bundle(&bundle, &kp).expect("sign ok");
        let signed = SignedBundle { bundle: bundle.clone(), signature: sig, verification_key: kp.verification_key.clone() };
        let wire = signed.encode_wire().unwrap();
        let decoded = decode_wire(&wire).expect("decode ok");
        let expected_journal = borsh::to_vec(&bundle.journal).unwrap();
        assert_eq!(decoded.journal_borsh, expected_journal);
        assert_eq!(decoded.oracle_proof, bundle.oracle_proof_bytes);
        assert!(decoded.verify_air_proof.is_none());
        assert!(decoded.verify_air_pv.is_none());
        assert_eq!(decoded.now_secs, bundle.now_secs);
        assert_eq!(*decoded.signature, sig);
        assert_eq!(decoded.verification_key.as_ref(), kp.verification_key.as_ref());
    }

    #[test]
    fn wire_round_trip_with_companion() {
        let kp = make_keypair();
        let mut bundle = ok_bundle();
        bundle.verify_air_proof_bytes = Some(vec![0xab; 256]);
        bundle.verify_air_public_values = Some(vec![0xcd; 96]);
        let sig = sign_bundle(&bundle, &kp).expect("sign ok");
        let signed = SignedBundle { bundle: bundle.clone(), signature: sig, verification_key: kp.verification_key.clone() };
        let wire = signed.encode_wire().unwrap();
        let decoded = decode_wire(&wire).expect("decode ok");
        assert_eq!(decoded.verify_air_proof.as_deref(), Some(&[0xab; 256][..]));
        assert_eq!(decoded.verify_air_pv.as_deref(), Some(&[0xcd; 96][..]));
    }

    #[test]
    fn decode_wire_rejects_truncated() {
        let kp = make_keypair();
        let bundle = ok_bundle();
        let sig = sign_bundle(&bundle, &kp).expect("sign ok");
        let signed = SignedBundle { bundle, signature: sig, verification_key: kp.verification_key };
        let wire = signed.encode_wire().unwrap();
        assert!(decode_wire(&wire[..wire.len() - 1]).is_none());
        assert!(decode_wire(&wire[..10]).is_none());
    }

    #[test]
    fn decode_wire_rejects_trailing_garbage() {
        let kp = make_keypair();
        let bundle = ok_bundle();
        let sig = sign_bundle(&bundle, &kp).expect("sign ok");
        let signed = SignedBundle { bundle, signature: sig, verification_key: kp.verification_key };
        let mut wire = signed.encode_wire().unwrap();
        wire.push(0xff);
        assert!(decode_wire(&wire).is_none());
    }

    #[test]
    fn load_key_round_trip() {
        let kp = make_keypair();
        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("relayer.sk");
        let vk_path = dir.path().join("relayer.sk.vk");
        std::fs::File::create(&sk_path).unwrap().write_all(kp.signing_key.as_ref()).unwrap();
        std::fs::File::create(&vk_path).unwrap().write_all(kp.verification_key.as_ref()).unwrap();
        let loaded = RelayerKey::load(&sk_path).expect("load ok");
        assert_eq!(loaded.signing_key.as_ref(), kp.signing_key.as_ref());
        assert_eq!(loaded.verification_key.as_ref(), kp.verification_key.as_ref());
    }

    #[test]
    fn load_key_rejects_wrong_size() {
        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("bad.sk");
        std::fs::File::create(&sk_path).unwrap().write_all(&[0u8; 100]).unwrap();
        assert!(matches!(RelayerKey::load(&sk_path), Err(SignError::BadSigningKeyLen { .. })));
    }
}
