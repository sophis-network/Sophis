//! Descriptor → `ScriptPublicKey` resolution per `wallet/descriptors/DESIGN.md` §8.
//!
//! v1 supports only `pkh-mldsa44(<literal vk>)` resolution. Multi-sig
//! descriptors and HD `xpub` syntax parse and round-trip but resolve fails
//! with a clear error pointing at the unblocking work (D1 / D2).

use sophis_consensus_core::tx::ScriptPublicKey;
use sophis_txscript::standard::{dilithium_redeem_script, pay_to_script_hash_script};

use crate::error::ResolveError;
use crate::types::{Descriptor, KeyData};

impl Descriptor {
    /// Resolve this descriptor to one or more `ScriptPublicKey` values
    /// suitable for transaction outputs.
    ///
    /// v1 always returns a singleton `Vec` for `Pkh` with a literal vk.
    /// The `Vec` return type anticipates future HD descriptors that resolve
    /// to multiple addresses (one per derivation index).
    ///
    /// # Errors
    /// - [`ResolveError::HdDerivationNotYetSupported`] for `xpub` keys (D1).
    /// - [`ResolveError::MultiSigNotYetSupported`] for any `Multi` descriptor (D2).
    /// - [`ResolveError::RedeemScriptError`] if the upstream `dilithium_redeem_script`
    ///   call fails (e.g., script-builder pushdata size error — should not happen
    ///   for canonical 1312-byte vk inputs, but errors are surfaced rather than
    ///   panicked).
    pub fn resolve(&self) -> Result<Vec<ScriptPublicKey>, ResolveError> {
        match self {
            Descriptor::Pkh { key } => match &key.data {
                KeyData::VkHex(vk_box) => {
                    let redeem = dilithium_redeem_script(vk_box.as_bytes()).map_err(|e| ResolveError::RedeemScriptError(e.to_string()))?;
                    let spk = pay_to_script_hash_script(&redeem);
                    Ok(vec![spk])
                }
                KeyData::XpubReserved(_) => Err(ResolveError::HdDerivationNotYetSupported),
            },
            Descriptor::Multi { .. } => Err(ResolveError::MultiSigNotYetSupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Descriptor, DescriptorKey, KeyData};
    use sophis_wallet_pskt::crypto::{DILITHIUM44_VK_SIZE, DilithiumPubKey};

    fn make_test_vk(byte: u8) -> DilithiumPubKey {
        DilithiumPubKey::from_bytes([byte; DILITHIUM44_VK_SIZE])
    }

    #[test]
    fn resolve_pkh_literal_vk_succeeds() {
        let vk = make_test_vk(0xab);
        let d = Descriptor::Pkh { key: DescriptorKey::new_literal(vk) };
        let spks = d.resolve().expect("pkh resolves");
        assert_eq!(spks.len(), 1);
        // Sanity: the SPK must be non-empty and have at least the P2SH
        // structure (OP_HASH256 + push + redeem-hash + OP_EQUAL = ~36 bytes).
        let spk = &spks[0];
        assert!(!spk.script().is_empty());
    }

    #[test]
    fn resolve_pkh_xpub_returns_hd_not_supported() {
        let d = Descriptor::Pkh {
            key: DescriptorKey { origin: None, data: KeyData::XpubReserved("xpub6ASuArn...placeholder/0/*".to_string()) },
        };
        assert_eq!(d.resolve().unwrap_err(), ResolveError::HdDerivationNotYetSupported);
    }

    #[test]
    fn resolve_multi_returns_not_supported() {
        let keys = vec![DescriptorKey::new_literal(make_test_vk(0x01)), DescriptorKey::new_literal(make_test_vk(0x02))];
        let d = Descriptor::Multi { threshold: 2, keys };
        assert_eq!(d.resolve().unwrap_err(), ResolveError::MultiSigNotYetSupported);
    }

    #[test]
    fn resolve_pkh_deterministic() {
        let vk = make_test_vk(0x55);
        let d1 = Descriptor::Pkh { key: DescriptorKey::new_literal(vk.clone()) };
        let d2 = Descriptor::Pkh { key: DescriptorKey::new_literal(vk) };
        let spk1 = &d1.resolve().expect("ok")[0];
        let spk2 = &d2.resolve().expect("ok")[0];
        assert_eq!(spk1, spk2, "Same vk must resolve to identical ScriptPublicKey");
    }

    #[test]
    fn resolve_pkh_different_vks_different_spks() {
        let vk_a = make_test_vk(0x11);
        let vk_b = make_test_vk(0x22);
        let d_a = Descriptor::Pkh { key: DescriptorKey::new_literal(vk_a) };
        let d_b = Descriptor::Pkh { key: DescriptorKey::new_literal(vk_b) };
        let spk_a = &d_a.resolve().expect("ok")[0];
        let spk_b = &d_b.resolve().expect("ok")[0];
        assert_ne!(spk_a, spk_b);
    }
}
