//! `Display` impl for `Descriptor` per `wallet/descriptors/DESIGN.md` §4 grammar.
//!
//! Canonical output:
//! - `pkh-mldsa44(<key>)#checksum`
//! - `multi-mldsa44(<threshold>,<key>,<key>,...)#checksum`
//!
//! The `Display` form is the canonical textual form. `Display` always emits
//! lowercase hex for vk and fingerprint values; uppercase hex on input is
//! normalized away by parse + display round-trip.

use std::fmt;

use crate::checksum;
use crate::types::{Descriptor, DescriptorKey, KeyData, KeyOrigin};

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let body = match self {
            Descriptor::Pkh { key } => format!("pkh-mldsa44({})", DescriptorKeyDisplay(key)),
            Descriptor::Multi { threshold, keys } => {
                let parts: Vec<String> = keys.iter().map(|k| format!("{}", DescriptorKeyDisplay(k))).collect();
                format!("multi-mldsa44({},{})", threshold, parts.join(","))
            }
        };
        // Compute checksum. If for some pathological reason it fails (which
        // should not happen given the grammar restricts to ASCII subset),
        // surface the failure as a fmt::Error.
        let cs = checksum::create(&body).map_err(|_| fmt::Error)?;
        write!(f, "{body}#{cs}")
    }
}

/// Newtype wrapper to give `DescriptorKey` a `Display` impl without imposing
/// it on the public type (which keeps `Display` intentionally on the
/// `Descriptor` boundary only).
struct DescriptorKeyDisplay<'a>(&'a DescriptorKey);

impl fmt::Display for DescriptorKeyDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(origin) = &self.0.origin {
            write!(f, "[{}]", KeyOriginDisplay(origin))?;
        }
        match &self.0.data {
            KeyData::VkHex(vk_box) => f.write_str(&hex::encode(vk_box.as_bytes())),
            KeyData::XpubReserved(s) => f.write_str(s),
        }
    }
}

struct KeyOriginDisplay<'a>(&'a KeyOrigin);

impl fmt::Display for KeyOriginDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.fingerprint.to_hex())?;
        for step in &self.0.derivation_path {
            write!(f, "/{}", step.index)?;
            if step.hardened {
                f.write_str("h")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::fingerprint;
    use crate::types::{DerivationStep, KeyOrigin};
    use sophis_wallet_pskt::crypto::{DILITHIUM44_VK_SIZE, DilithiumPubKey};

    fn make_test_vk(byte: u8) -> DilithiumPubKey {
        DilithiumPubKey::from_bytes([byte; DILITHIUM44_VK_SIZE])
    }

    #[test]
    fn display_pkh_no_origin() {
        let vk = make_test_vk(0xab);
        let d = Descriptor::Pkh { key: DescriptorKey::new_literal(vk) };
        let s = d.to_string();
        assert!(s.starts_with("pkh-mldsa44("));
        assert!(s.contains("ab"));
        assert!(s.contains("#"));
        // Length: "pkh-mldsa44(" + 2624 + ")" + "#" + 8 = 12 + 2624 + 1 + 1 + 8 = 2646.
        assert_eq!(s.len(), "pkh-mldsa44()#".len() + 2624 + 8);
    }

    #[test]
    fn display_pkh_with_origin() {
        let vk = make_test_vk(0xcd);
        let fp = fingerprint(&vk);
        let origin = KeyOrigin {
            fingerprint: fp,
            derivation_path: vec![
                DerivationStep { index: 44, hardened: true },
                DerivationStep { index: 2025, hardened: true },
                DerivationStep { index: 0, hardened: true },
            ],
        };
        let d = Descriptor::Pkh { key: DescriptorKey { origin: Some(origin), data: KeyData::VkHex(Box::new(vk)) } };
        let s = d.to_string();
        assert!(s.contains(&format!("[{}/44h/2025h/0h]", fp.to_hex())));
    }

    #[test]
    fn display_multi() {
        let keys = vec![
            DescriptorKey::new_literal(make_test_vk(0x01)),
            DescriptorKey::new_literal(make_test_vk(0x02)),
            DescriptorKey::new_literal(make_test_vk(0x03)),
        ];
        let d = Descriptor::Multi { threshold: 2, keys };
        let s = d.to_string();
        assert!(s.starts_with("multi-mldsa44(2,"));
        // Three vk hexes separated by commas → 2624 chars × 3 + 2 commas.
        assert_eq!(s.matches(',').count(), 3); // 1 after threshold + 2 between keys
    }

    #[test]
    fn round_trip_pkh_no_origin() {
        let vk = make_test_vk(0x42);
        let original = Descriptor::Pkh { key: DescriptorKey::new_literal(vk) };
        let s = original.to_string();
        let parsed: Descriptor = s.parse().expect("parse roundtrip");
        assert_eq!(original, parsed);
        assert_eq!(s, parsed.to_string(), "Display is idempotent");
    }

    #[test]
    fn round_trip_pkh_with_origin() {
        let vk = make_test_vk(0x77);
        let fp = fingerprint(&vk);
        let origin = KeyOrigin {
            fingerprint: fp,
            derivation_path: vec![
                DerivationStep { index: 44, hardened: true },
                DerivationStep { index: 2025, hardened: false },
            ],
        };
        let original = Descriptor::Pkh { key: DescriptorKey { origin: Some(origin), data: KeyData::VkHex(Box::new(vk)) } };
        let s = original.to_string();
        let parsed: Descriptor = s.parse().expect("parse roundtrip");
        assert_eq!(original, parsed);
    }

    #[test]
    fn round_trip_multi_2of3() {
        let keys = vec![
            DescriptorKey::new_literal(make_test_vk(0xa1)),
            DescriptorKey::new_literal(make_test_vk(0xa2)),
            DescriptorKey::new_literal(make_test_vk(0xa3)),
        ];
        let original = Descriptor::Multi { threshold: 2, keys };
        let s = original.to_string();
        let parsed: Descriptor = s.parse().expect("parse roundtrip");
        assert_eq!(original, parsed);
    }
}
