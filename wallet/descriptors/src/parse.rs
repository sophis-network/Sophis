//! Descriptor parser per `wallet/descriptors/DESIGN.md` §4 grammar.
//!
//! Implements `FromStr for Descriptor`. Single-pass recursive-descent;
//! no external parser-combinator dependency.

use std::str::FromStr;

use sophis_wallet_pskt::crypto::{DILITHIUM44_VK_SIZE, DilithiumPubKey};

use crate::checksum;
use crate::error::ParseError;
use crate::fingerprint::{Fingerprint, fingerprint};
use crate::types::{DerivationStep, Descriptor, DescriptorKey, KeyData, KeyOrigin, MAX_MULTI_KEYS};

/// Hex character count for a Dilithium ML-DSA-44 verification key.
const VK_HEX_LEN: usize = DILITHIUM44_VK_SIZE * 2; // 2624

impl FromStr for Descriptor {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(ParseError::EmptyInput);
        }

        // Split off `#checksum` first.
        let (body, given_checksum) = match input.rfind('#') {
            Some(idx) => (&input[..idx], &input[idx + 1..]),
            None => return Err(ParseError::MissingChecksum),
        };

        // Validate checksum before parsing the body — fail fast on typos.
        match checksum::verify(body, given_checksum) {
            Ok(()) => {}
            Err(checksum::ChecksumError::InvalidLength(_)) => {
                return Err(ParseError::MissingChecksum);
            }
            Err(checksum::ChecksumError::InvalidChar(c)) => {
                return Err(ParseError::InvalidChecksumChar(c));
            }
            Err(checksum::ChecksumError::Mismatch) => {
                let expected = checksum::create(body).map_err(|e| ParseError::UnexpectedToken(e.to_string()))?;
                return Err(ParseError::ChecksumMismatch { expected, actual: given_checksum.to_string() });
            }
        }

        parse_script_expr(body)
    }
}

/// Parse the `script_expr` portion: either `pkh-mldsa44(<key>)` or
/// `multi-mldsa44(<threshold>, <key>, ..., <key>)`.
fn parse_script_expr(body: &str) -> Result<Descriptor, ParseError> {
    // Find the opening parenthesis.
    let open = body.find('(').ok_or_else(|| ParseError::InvalidScriptType(body.to_string()))?;
    let script_type = &body[..open];

    // Body must end with ')'.
    if !body.ends_with(')') {
        return Err(ParseError::UnclosedParenthesis);
    }
    let inner = &body[open + 1..body.len() - 1];

    match script_type {
        "pkh-mldsa44" => parse_pkh(inner),
        "multi-mldsa44" => parse_multi(inner),
        other => Err(ParseError::InvalidScriptType(other.to_string())),
    }
}

fn parse_pkh(inner: &str) -> Result<Descriptor, ParseError> {
    let key = parse_descriptor_key(inner)?;
    Ok(Descriptor::Pkh { key })
}

fn parse_multi(inner: &str) -> Result<Descriptor, ParseError> {
    // Split on commas at depth 0 (so `[fp/path]` brackets don't split).
    let parts = split_top_level_commas(inner)?;
    if parts.len() < 2 {
        return Err(ParseError::EmptyKeyList);
    }

    // First part is the threshold.
    let threshold: u32 = parts[0].parse().map_err(|_| ParseError::InvalidDerivationStep(parts[0].to_string()))?;

    let key_count = parts.len() - 1;
    if key_count > MAX_MULTI_KEYS {
        return Err(ParseError::TooManyKeys { provided: key_count, max: MAX_MULTI_KEYS });
    }
    if threshold == 0 || (threshold as usize) > key_count {
        return Err(ParseError::ThresholdOutOfRange { threshold, max: key_count as u32 });
    }

    let keys: Result<Vec<_>, _> = parts[1..].iter().map(|s| parse_descriptor_key(s)).collect();
    Ok(Descriptor::Multi { threshold, keys: keys? })
}

/// Split `s` on commas that are NOT inside `[...]` brackets.
fn split_top_level_commas(s: &str) -> Result<Vec<&str>, ParseError> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth < 0 {
                    return Err(ParseError::UnclosedBracket);
                }
            }
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(ParseError::UnclosedBracket);
    }
    parts.push(&s[start..]);
    Ok(parts)
}

/// Parse one `key_expr`: `[origin]?key_data`.
fn parse_descriptor_key(s: &str) -> Result<DescriptorKey, ParseError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ParseError::UnexpectedToken("empty key expression".to_string()));
    }

    let (origin, key_str) = if let Some(stripped) = s.strip_prefix('[') {
        let close = stripped.find(']').ok_or(ParseError::UnclosedBracket)?;
        let origin_str = &stripped[..close];
        let rest = &stripped[close + 1..];
        (Some(parse_key_origin(origin_str)?), rest)
    } else {
        (None, s)
    };

    let data = parse_key_data(key_str)?;

    // Optional cross-check: if origin has a fingerprint AND the key is a
    // literal vk, verify the fingerprint matches.
    if let (Some(o), KeyData::VkHex(vk_box)) = (&origin, &data) {
        let derived = fingerprint(vk_box);
        if derived != o.fingerprint {
            return Err(ParseError::FingerprintMismatch);
        }
    }

    Ok(DescriptorKey { origin, data })
}

/// Parse `fingerprint_hex (/derivation_step)*`.
fn parse_key_origin(s: &str) -> Result<KeyOrigin, ParseError> {
    let mut parts = s.split('/');
    let fp_str = parts.next().ok_or(ParseError::InvalidFingerprintLength)?;
    let fp = match Fingerprint::from_hex(fp_str) {
        Some(fp) => fp,
        None => {
            return Err(if fp_str.len() != 8 { ParseError::InvalidFingerprintLength } else { ParseError::InvalidFingerprintHex });
        }
    };

    let mut derivation_path = Vec::new();
    for step in parts {
        derivation_path.push(parse_derivation_step(step)?);
    }

    Ok(KeyOrigin { fingerprint: fp, derivation_path })
}

fn parse_derivation_step(s: &str) -> Result<DerivationStep, ParseError> {
    let (num_str, hardened) = if let Some(stripped) = s.strip_suffix('\'') {
        (stripped, true)
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, true)
    } else {
        (s, false)
    };
    let index: u32 = num_str.parse().map_err(|_| ParseError::InvalidDerivationStep(s.to_string()))?;
    Ok(DerivationStep { index, hardened })
}

/// Parse the key body — either literal vk hex (2624 chars) or `xpub...`
/// reserved syntax (D1).
fn parse_key_data(s: &str) -> Result<KeyData, ParseError> {
    if s.starts_with("xpub") {
        return Ok(KeyData::XpubReserved(s.to_string()));
    }

    if s.len() != VK_HEX_LEN {
        return Err(ParseError::InvalidVkLength { provided: s.len(), expected: VK_HEX_LEN });
    }

    // Lowercase canonicalize for hex parsing.
    let normalized = s.to_lowercase();
    let bytes = hex::decode(&normalized).map_err(|e| ParseError::InvalidVkHex(e.to_string()))?;
    let arr: [u8; DILITHIUM44_VK_SIZE] = bytes.try_into().map_err(|_| ParseError::InvalidVkHex("length conversion".to_string()))?;
    Ok(KeyData::VkHex(Box::new(DilithiumPubKey::from_bytes(arr))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_wallet_pskt::crypto::DILITHIUM44_VK_SIZE;

    fn make_test_vk() -> DilithiumPubKey {
        DilithiumPubKey::from_bytes([0xab; DILITHIUM44_VK_SIZE])
    }

    fn make_canonical_pkh_string() -> String {
        let vk = make_test_vk();
        let body = format!("pkh-mldsa44({})", hex::encode(vk.as_bytes()));
        let cs = checksum::create(&body).expect("checksum");
        format!("{}#{}", body, cs)
    }

    #[test]
    fn parse_pkh_with_literal_vk() {
        let input = make_canonical_pkh_string();
        let d: Descriptor = input.parse().expect("parse");
        match d {
            Descriptor::Pkh { key } => {
                assert!(key.origin.is_none());
                match key.data {
                    KeyData::VkHex(vk_box) => {
                        assert_eq!(vk_box.as_bytes(), &[0xab; DILITHIUM44_VK_SIZE]);
                    }
                    _ => panic!("expected VkHex"),
                }
            }
            _ => panic!("expected Pkh"),
        }
    }

    #[test]
    fn parse_pkh_with_key_origin() {
        let vk = make_test_vk();
        let fp = fingerprint(&vk);
        let body = format!("pkh-mldsa44([{}/44h/2025h/0h]{})", fp.to_hex(), hex::encode(vk.as_bytes()));
        let cs = checksum::create(&body).expect("checksum");
        let input = format!("{}#{}", body, cs);
        let d: Descriptor = input.parse().expect("parse");
        match d {
            Descriptor::Pkh { key } => {
                let origin = key.origin.as_ref().expect("origin present");
                assert_eq!(origin.fingerprint, fp);
                assert_eq!(origin.derivation_path.len(), 3);
                assert!(origin.derivation_path.iter().all(|s| s.hardened));
            }
            _ => panic!("expected Pkh"),
        }
    }

    #[test]
    fn parse_pkh_fingerprint_mismatch_rejected() {
        let vk = make_test_vk();
        // Use a wrong fingerprint deliberately.
        let wrong_fp = "00000000";
        let body = format!("pkh-mldsa44([{}]{})", wrong_fp, hex::encode(vk.as_bytes()));
        let cs = checksum::create(&body).expect("checksum");
        let input = format!("{}#{}", body, cs);
        assert_eq!(input.parse::<Descriptor>().unwrap_err(), ParseError::FingerprintMismatch);
    }

    #[test]
    fn parse_multi_2of3() {
        let vk1 = DilithiumPubKey::from_bytes([0x01; DILITHIUM44_VK_SIZE]);
        let vk2 = DilithiumPubKey::from_bytes([0x02; DILITHIUM44_VK_SIZE]);
        let vk3 = DilithiumPubKey::from_bytes([0x03; DILITHIUM44_VK_SIZE]);
        let body =
            format!("multi-mldsa44(2,{},{},{})", hex::encode(vk1.as_bytes()), hex::encode(vk2.as_bytes()), hex::encode(vk3.as_bytes()));
        let cs = checksum::create(&body).expect("checksum");
        let input = format!("{}#{}", body, cs);
        let d: Descriptor = input.parse().expect("parse");
        match d {
            Descriptor::Multi { threshold, keys } => {
                assert_eq!(threshold, 2);
                assert_eq!(keys.len(), 3);
            }
            _ => panic!("expected Multi"),
        }
    }

    #[test]
    fn parse_multi_threshold_zero_rejected() {
        let vk1 = DilithiumPubKey::from_bytes([0x01; DILITHIUM44_VK_SIZE]);
        let body = format!("multi-mldsa44(0,{})", hex::encode(vk1.as_bytes()));
        let cs = checksum::create(&body).expect("checksum");
        let input = format!("{}#{}", body, cs);
        assert!(matches!(input.parse::<Descriptor>(), Err(ParseError::ThresholdOutOfRange { .. })));
    }

    #[test]
    fn parse_multi_threshold_too_high_rejected() {
        let vk1 = DilithiumPubKey::from_bytes([0x01; DILITHIUM44_VK_SIZE]);
        let body = format!("multi-mldsa44(3,{})", hex::encode(vk1.as_bytes()));
        let cs = checksum::create(&body).expect("checksum");
        let input = format!("{}#{}", body, cs);
        assert!(matches!(input.parse::<Descriptor>(), Err(ParseError::ThresholdOutOfRange { .. })));
    }

    #[test]
    fn parse_unknown_script_type_rejected() {
        // Use a syntactically valid checksum so we get past the checksum stage.
        let body = "wpkh-mldsa44(00)";
        let cs = checksum::create(body).expect("checksum");
        let input = format!("{}#{}", body, cs);
        assert!(matches!(input.parse::<Descriptor>(), Err(ParseError::InvalidScriptType(_))));
    }

    #[test]
    fn parse_missing_checksum_rejected() {
        let vk = make_test_vk();
        let input = format!("pkh-mldsa44({})", hex::encode(vk.as_bytes()));
        assert_eq!(input.parse::<Descriptor>().unwrap_err(), ParseError::MissingChecksum);
    }

    #[test]
    fn parse_checksum_mismatch_rejected() {
        let vk = make_test_vk();
        let body = format!("pkh-mldsa44({})", hex::encode(vk.as_bytes()));
        let input = format!("{}#qqqqqqqq", body);
        assert!(matches!(input.parse::<Descriptor>(), Err(ParseError::ChecksumMismatch { .. })));
    }

    #[test]
    fn parse_empty_input_rejected() {
        assert_eq!("".parse::<Descriptor>().unwrap_err(), ParseError::EmptyInput);
    }

    #[test]
    fn parse_xpub_reserved_syntax() {
        // xpub is parsed but resolve will reject (test in K3.6).
        let body = "pkh-mldsa44(xpub6ASuArnXKPbf...placeholder/0/*)";
        let cs = checksum::create(body).expect("checksum");
        let input = format!("{}#{}", body, cs);
        let d: Descriptor = input.parse().expect("parse xpub syntax");
        match d {
            Descriptor::Pkh { key } => match key.data {
                KeyData::XpubReserved(s) => assert!(s.starts_with("xpub")),
                _ => panic!("expected XpubReserved"),
            },
            _ => panic!("expected Pkh"),
        }
    }

    #[test]
    fn parse_vk_invalid_length_rejected() {
        // 100 hex chars instead of 2624.
        let body = "pkh-mldsa44(abcdef)";
        let cs = checksum::create(body).expect("checksum");
        let input = format!("{}#{}", body, cs);
        assert!(matches!(input.parse::<Descriptor>(), Err(ParseError::InvalidVkLength { .. })));
    }
}
