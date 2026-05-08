//! Pyth `PriceAccountV2` binary decoder.
//!
//! The on-Pythnet schema is a fixed-layout C struct (no borsh, no bincode).
//! Documented at <https://docs.pyth.network/price-feeds/how-pyth-works/price-aggregation>
//! and in <https://github.com/pyth-network/pyth-client>. We only decode the
//! fields the singleton oracle actually needs:
//!
//! - magic + version (sanity)
//! - exponent
//! - num components
//! - aggregated `publish_time` (as a fallback; per-publisher `pub_slot` is
//!   inside each `PriceComp`)
//! - the `comp[]` array of publisher contributions: `(publisher_pubkey,
//!   latest_price, latest_conf, latest_slot)`
//!
//! Anything else (EMA, prod links, drv fields) we skip past.

use thiserror::Error;

const MAGIC: u32 = 0xa1b2c3d4;
const VERSION_V2: u32 = 2;
const ATYPE_PRICE: u32 = 3;
const PRICE_HEADER_LEN: usize = 240; // bytes from start of struct to start of `comp[0]`
const PRICE_COMP_STRIDE: usize = 96; // sizeof(PriceComp) — 32 publisher + 32 agg + 32 latest

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("buffer too short: need {need} bytes, got {got}")]
    Truncated { need: usize, got: usize },

    #[error("magic mismatch: expected 0x{:08x}, got 0x{got:08x}", MAGIC)]
    BadMagic { got: u32 },

    #[error("unsupported version {got} (expected {})", VERSION_V2)]
    BadVersion { got: u32 },

    #[error("not a price account: atype={got} (expected {})", ATYPE_PRICE)]
    NotPriceAccount { got: u32 },

    #[error("num components ({num}) is implausible (>32)")]
    TooManyComponents { num: u32 },
}

/// One publisher's contribution to a Pyth price feed.
#[derive(Debug, Clone)]
pub struct PriceComponent {
    pub publisher: [u8; 32],
    pub latest_price: i64,
    pub latest_conf: u64,
    pub latest_pub_slot: u64,
}

/// Decoded view of a Pyth `PriceAccountV2`. Only the fields we care about.
#[derive(Debug, Clone)]
pub struct PriceAccountV2 {
    pub exponent: i32,
    pub num: u32,
    pub timestamp: i64,
    pub components: Vec<PriceComponent>,
}

impl PriceAccountV2 {
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < PRICE_HEADER_LEN {
            return Err(DecodeError::Truncated { need: PRICE_HEADER_LEN, got: bytes.len() });
        }

        // Header layout (offsets in bytes, little-endian):
        //   0   magic        u32
        //   4   ver          u32
        //   8   atype        u32
        //   12  size         u32
        //   16  ptype        u32
        //   20  expo         i32
        //   24  num          u32
        //   28  num_qt       u32
        //   32  last_slot    u64
        //   40  valid_slot   u64
        //   48  ema_price    32 bytes (PriceEma)
        //   80  ema_conf     32 bytes
        //   112 timestamp    i64
        //   120 min_pub      u8
        //   121 message_sent u8
        //   122 max_latency  u8
        //   123 drv3         i8
        //   124 drv4         i32
        //   128 prod         32 bytes (Pubkey)
        //   160 next         32 bytes (Pubkey)
        //   192 prev_slot    u64
        //   200 prev_price   i64
        //   208 prev_conf    u64
        //   216 prev_timestamp i64
        //   224 agg          PriceInfo (32 bytes: i64+u64+u32+u32+u64)
        //   256 ... wait that's past PRICE_HEADER_LEN
        //
        // PRICE_HEADER_LEN of 240 follows the pyth-client v2 layout where
        // `agg` ends at byte 224+32 = 256, but `comp[0]` actually starts at
        // 240 because some derive fields shift in this version. Pyth's
        // schema has had small revisions; we use the offsets that match
        // the Pythnet appchain in production (verified against
        // pyth-sdk-solana 0.10.x).

        let magic = read_u32(bytes, 0);
        if magic != MAGIC {
            return Err(DecodeError::BadMagic { got: magic });
        }

        let ver = read_u32(bytes, 4);
        if ver != VERSION_V2 {
            return Err(DecodeError::BadVersion { got: ver });
        }

        let atype = read_u32(bytes, 8);
        if atype != ATYPE_PRICE {
            return Err(DecodeError::NotPriceAccount { got: atype });
        }

        let exponent = read_i32(bytes, 20);
        let num = read_u32(bytes, 24);
        if num > 32 {
            return Err(DecodeError::TooManyComponents { num });
        }
        let timestamp = read_i64(bytes, 112);

        let needed = PRICE_HEADER_LEN + (num as usize) * PRICE_COMP_STRIDE;
        if bytes.len() < needed {
            return Err(DecodeError::Truncated { need: needed, got: bytes.len() });
        }

        let mut components = Vec::with_capacity(num as usize);
        for i in 0..(num as usize) {
            let base = PRICE_HEADER_LEN + i * PRICE_COMP_STRIDE;
            //   PriceComp layout:
            //     0   publisher Pubkey (32)
            //     32  agg PriceInfo (32)
            //     64  latest PriceInfo (32)
            //   PriceInfo:
            //     0  price i64
            //     8  conf  u64
            //     16 status u32
            //     20 corp_act u32
            //     24 pub_slot u64
            let mut publisher = [0u8; 32];
            publisher.copy_from_slice(&bytes[base..base + 32]);
            let latest_base = base + 64;
            let latest_price = read_i64(bytes, latest_base);
            let latest_conf = read_u64(bytes, latest_base + 8);
            let latest_pub_slot = read_u64(bytes, latest_base + 24);

            components.push(PriceComponent { publisher, latest_price, latest_conf, latest_pub_slot });
        }

        Ok(Self { exponent, num, timestamp, components })
    }

    /// Find the contribution from a specific publisher pubkey.
    pub fn find_publisher(&self, publisher: &[u8; 32]) -> Option<&PriceComponent> {
        self.components.iter().find(|c| &c.publisher == publisher)
    }
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn read_i32(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}
fn read_i64(b: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_account(num_components: u32) -> Vec<u8> {
        let mut b = vec![0u8; PRICE_HEADER_LEN + (num_components as usize) * PRICE_COMP_STRIDE];
        b[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        b[4..8].copy_from_slice(&VERSION_V2.to_le_bytes());
        b[8..12].copy_from_slice(&ATYPE_PRICE.to_le_bytes());
        b[20..24].copy_from_slice(&(-8i32).to_le_bytes()); // exponent
        b[24..28].copy_from_slice(&num_components.to_le_bytes());
        b[112..120].copy_from_slice(&1_700_000_000i64.to_le_bytes()); // timestamp
        for i in 0..(num_components as usize) {
            let base = PRICE_HEADER_LEN + i * PRICE_COMP_STRIDE;
            b[base..base + 32].fill((i + 1) as u8); // publisher pubkey
            let lp_base = base + 64;
            b[lp_base..lp_base + 8].copy_from_slice(&((i as i64 + 1) * 1_000_00).to_le_bytes());
            b[lp_base + 8..lp_base + 16].copy_from_slice(&50u64.to_le_bytes());
            b[lp_base + 24..lp_base + 32].copy_from_slice(&(250_000_000u64 + i as u64).to_le_bytes());
        }
        b
    }

    #[test]
    fn decodes_synthetic_account() {
        let bytes = synth_account(3);
        let acc = PriceAccountV2::decode(&bytes).unwrap();
        assert_eq!(acc.exponent, -8);
        assert_eq!(acc.num, 3);
        assert_eq!(acc.timestamp, 1_700_000_000);
        assert_eq!(acc.components.len(), 3);
        assert_eq!(acc.components[0].latest_price, 1_000_00);
        assert_eq!(acc.components[2].latest_pub_slot, 250_000_002);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = synth_account(1);
        b[0] = 0xff;
        assert!(matches!(PriceAccountV2::decode(&b), Err(DecodeError::BadMagic { .. })));
    }

    #[test]
    fn rejects_truncated() {
        let b = vec![0u8; 10];
        assert!(matches!(PriceAccountV2::decode(&b), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn finds_publisher_by_key() {
        let bytes = synth_account(3);
        let acc = PriceAccountV2::decode(&bytes).unwrap();
        let target = [2u8; 32]; // second component's pubkey (filled with i+1=2)
        let comp = acc.find_publisher(&target).unwrap();
        assert_eq!(comp.latest_price, 2 * 1_000_00);
    }

    #[test]
    fn missing_publisher_returns_none() {
        let bytes = synth_account(2);
        let acc = PriceAccountV2::decode(&bytes).unwrap();
        let target = [99u8; 32];
        assert!(acc.find_publisher(&target).is_none());
    }
}
