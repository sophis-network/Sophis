//! BIP-152-style compact-size length prefix.
//!
//! Encoding:
//!   - n < 253:                        1 byte (n)
//!   - n < 2^16:                       1 byte (0xFD) + 2 bytes LE
//!   - n < 2^32:                       1 byte (0xFE) + 4 bytes LE
//!   - else:                           1 byte (0xFF) + 8 bytes LE
//!
//! Sophis K2 follows BIP-152 exactly so wire-format-agnostic Bitcoin
//! tooling can parse our element counts without modification.

use crate::error::{FilterError, FilterResult};

pub fn encode_compact_size(n: u64, out: &mut Vec<u8>) {
    if n < 253 {
        out.push(n as u8);
    } else if n < 0x10000 {
        out.push(0xFD);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n < 0x1_0000_0000 {
        out.push(0xFE);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Returns `(value, bytes_consumed)`.
pub fn decode_compact_size(bytes: &[u8]) -> FilterResult<(u64, usize)> {
    if bytes.is_empty() {
        return Err(FilterError::TooShort(0));
    }
    let head = bytes[0];
    match head {
        0xFD => {
            if bytes.len() < 3 {
                return Err(FilterError::MalformedCompactSize);
            }
            let v = u16::from_le_bytes([bytes[1], bytes[2]]) as u64;
            if v < 253 {
                return Err(FilterError::MalformedCompactSize); // non-canonical
            }
            Ok((v, 3))
        }
        0xFE => {
            if bytes.len() < 5 {
                return Err(FilterError::MalformedCompactSize);
            }
            let v = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
            if v < 0x10000 {
                return Err(FilterError::MalformedCompactSize); // non-canonical
            }
            Ok((v, 5))
        }
        0xFF => {
            if bytes.len() < 9 {
                return Err(FilterError::MalformedCompactSize);
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[1..9]);
            let v = u64::from_le_bytes(buf);
            if v < 0x1_0000_0000 {
                return Err(FilterError::MalformedCompactSize); // non-canonical
            }
            Ok((v, 9))
        }
        n => Ok((n as u64, 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(n: u64) {
        let mut buf = Vec::new();
        encode_compact_size(n, &mut buf);
        let (decoded, consumed) = decode_compact_size(&buf).unwrap();
        assert_eq!(decoded, n);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn small_under_253_one_byte() {
        roundtrip(0);
        roundtrip(1);
        roundtrip(252);
        let mut buf = Vec::new();
        encode_compact_size(100, &mut buf);
        assert_eq!(buf, vec![100]);
    }

    #[test]
    fn medium_uses_fd_prefix() {
        let mut buf = Vec::new();
        encode_compact_size(1000, &mut buf);
        assert_eq!(buf[0], 0xFD);
        assert_eq!(buf.len(), 3);
        roundtrip(253);
        roundtrip(0xFFFF);
    }

    #[test]
    fn large_uses_fe_prefix() {
        let mut buf = Vec::new();
        encode_compact_size(0x1_0000, &mut buf);
        assert_eq!(buf[0], 0xFE);
        assert_eq!(buf.len(), 5);
        roundtrip(0xFFFF_FFFF);
    }

    #[test]
    fn extra_large_uses_ff_prefix() {
        let mut buf = Vec::new();
        encode_compact_size(0x1_0000_0000, &mut buf);
        assert_eq!(buf[0], 0xFF);
        assert_eq!(buf.len(), 9);
        roundtrip(u64::MAX);
    }

    #[test]
    fn empty_input_errors() {
        assert_eq!(decode_compact_size(&[]).unwrap_err(), FilterError::TooShort(0));
    }

    #[test]
    fn non_canonical_fd_rejected() {
        // 0xFD prefix but value < 253 (would have fit in 1 byte)
        let bad = [0xFD, 100, 0];
        assert_eq!(decode_compact_size(&bad).unwrap_err(), FilterError::MalformedCompactSize);
    }

    #[test]
    fn non_canonical_fe_rejected() {
        // 0xFE prefix but value < 0x10000
        let bad = [0xFE, 0, 0, 0, 0];
        assert_eq!(decode_compact_size(&bad).unwrap_err(), FilterError::MalformedCompactSize);
    }

    #[test]
    fn truncated_prefix_errors() {
        assert!(decode_compact_size(&[0xFD, 1]).is_err());
        assert!(decode_compact_size(&[0xFE, 1, 2]).is_err());
        assert!(decode_compact_size(&[0xFF, 1, 2, 3, 4]).is_err());
    }
}
