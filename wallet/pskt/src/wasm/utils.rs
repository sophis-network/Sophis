use separator::{Separatable, separated_float, separated_int, separated_uint_with_output};
use sophis_consensus_core::constants::*;
use sophis_consensus_core::network::NetworkType;

#[inline]
pub fn sompi_to_sophis(sompi: u64) -> f64 {
    sompi as f64 / SOMPI_PER_SOPHIS as f64
}

#[inline]
pub fn sophis_to_sompi(sophis: f64) -> u64 {
    (sophis * SOMPI_PER_SOPHIS as f64) as u64
}

#[inline]
pub fn sompi_to_sophis_string(sompi: u64) -> String {
    sompi_to_sophis(sompi).separated_string()
}

#[inline]
pub fn sompi_to_sophis_string_with_trailing_zeroes(sompi: u64) -> String {
    separated_float!(format!("{:.8}", sompi_to_sophis(sompi)))
}

pub fn sophis_suffix(network_type: &NetworkType) -> &'static str {
    match network_type {
        NetworkType::Mainnet => "SPHS",
        NetworkType::Testnet => "TSPHS",
        NetworkType::Simnet => "SSPHS",
        NetworkType::Devnet => "DSPHS",
    }
}

#[inline]
pub fn sompi_to_sophis_string_with_suffix(sompi: u64, network_type: &NetworkType) -> String {
    let sophis = sompi_to_sophis_string(sompi);
    let suffix = sophis_suffix(network_type);
    format!("{sophis} {suffix}")
}
