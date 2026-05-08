/// Maximum WASM bytecode size per contract.
pub const MAX_BYTECODE_SIZE: usize = 1024 * 1024; // 1 MiB

/// Default fuel budget per transaction execution.
/// Calibrate with devnet/testnet data before mainnet.
pub const DEFAULT_FUEL_BUDGET: u64 = 10_000_000;

/// Maximum linear memory a contract can use (in pages; 1 page = 64 KiB).
pub const MAX_MEMORY_PAGES: u32 = 256; // 16 MiB

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub max_bytecode_size: usize,
    pub default_fuel_budget: u64,
    pub max_memory_pages: u32,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self { max_bytecode_size: MAX_BYTECODE_SIZE, default_fuel_budget: DEFAULT_FUEL_BUDGET, max_memory_pages: MAX_MEMORY_PAGES }
    }
}
