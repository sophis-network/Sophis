//! `sophis-oracle-publisher` — CLI signer for the Phase 9 PQC-native oracle.
//!
//! Signs `PriceAttestation` structs with Dilithium ML-DSA-44 and emits the
//! canonical hex-encoded bytes to stdout. Submission to a Sophis node is
//! out of scope for v1: pipe the hex into `dilithium-wallet send-raw`
//! (or any equivalent tx-construction tool) to wrap the attestation in
//! a transaction that the Phase 9 contract validates.
//!
//! Subcommands:
//!
//! - `keygen`  derive a Dilithium pubkey from a BIP-39 mnemonic file
//! - `sign`    sign a single (asset, price, conf, sequence) attestation
//! - `verify`  verify a hex-encoded attestation against the canonical
//!             Phase 9 domain separator (debug helper)
//!
//! Key sources:
//!
//! - `--mnemonic-file <path>`     BIP-39 24-word file (same path
//!                                 `dilithium-wallet` uses)
//! - `--signing-key-file <path>`  raw 2560-byte ML-DSA-44 signing key
//!
//! Output formats: hex (default) or raw bytes (`--output raw`).

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command};
use sophis_oracle_publisher::{
    PublisherError, build_and_sign_attestation, decode_attestation_hex,
    derive_keypair_from_mnemonic, encode_attestation_hex, parse_decimal_e8_signed,
    parse_decimal_e8_unsigned, verify_attestation_at,
};
use sophis_oracle_pqc_core::{
    DILITHIUM_PUBKEY_SIZE, DILITHIUM_SIGNING_KEY_SIZE, SIGNING_RANDOMNESS_SIZE,
};

fn main() -> ExitCode {
    let matches = build_cli().get_matches();

    let result = match matches.subcommand() {
        Some(("keygen", sub)) => run_keygen(sub),
        Some(("sign", sub)) => run_sign(sub),
        Some(("verify", sub)) => run_verify(sub),
        _ => {
            let _ = build_cli().print_help();
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sophis-oracle-publisher: {e}");
            ExitCode::FAILURE
        }
    }
}

fn build_cli() -> Command {
    Command::new("sophis-oracle-publisher")
        .about("Sign PriceAttestations for the Phase 9 PQC-native oracle (SIP-11)")
        .version(env!("CARGO_PKG_VERSION"))
        .arg_required_else_help(true)
        .subcommand(
            Command::new("keygen")
                .about("Derive a Dilithium ML-DSA-44 pubkey from a BIP-39 mnemonic file")
                .arg(
                    Arg::new("mnemonic-file")
                        .long("mnemonic-file")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Path to a file containing a BIP-39 24-word mnemonic on one line"),
                )
                .arg(
                    Arg::new("output-pubkey")
                        .long("output-pubkey")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("If set, write the 1312-byte raw pubkey to this path (otherwise: hex to stdout)"),
                )
                .arg(
                    Arg::new("output-signing-key")
                        .long("output-signing-key")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("If set, write the 2560-byte raw signing key to this path (mode 0600 on Unix)"),
                ),
        )
        .subcommand(
            Command::new("sign")
                .about("Sign one PriceAttestation and emit the canonical bytes")
                .arg(key_source_mnemonic_arg())
                .arg(key_source_signing_key_arg())
                .arg(
                    Arg::new("asset")
                        .long("asset")
                        .required(true)
                        .help("Asset symbol with `/` separator, e.g. `BTC/USD` (canonical SIP-11 D7)"),
                )
                .arg(
                    Arg::new("price")
                        .long("price")
                        .required(true)
                        .help("Decimal price (up to 8 fractional digits), e.g. `65000.00`"),
                )
                .arg(
                    Arg::new("conf")
                        .long("conf")
                        .required(true)
                        .help("Decimal 1-sigma confidence interval (up to 8 fractional digits)"),
                )
                .arg(
                    Arg::new("sequence")
                        .long("sequence")
                        .required(true)
                        .value_parser(clap::value_parser!(u64))
                        .help("Monotonic per-publisher per-asset sequence number"),
                )
                .arg(
                    Arg::new("ts")
                        .long("ts")
                        .value_parser(clap::value_parser!(u64))
                        .help("Publisher wall-clock timestamp (Unix epoch seconds). Default: current OS time"),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .value_parser(["hex", "raw"])
                        .default_value("hex")
                        .help("Output format. `hex`=lowercase hex to stdout; `raw`=binary bytes to stdout"),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a hex-encoded PriceAttestation against the Phase 9 domain")
                .arg(
                    Arg::new("hex")
                        .long("hex")
                        .help("Hex-encoded attestation. If absent, reads hex from stdin (trimmed)"),
                )
                .arg(
                    Arg::new("now")
                        .long("now")
                        .value_parser(clap::value_parser!(u64))
                        .help("Override the 'now' timestamp used for skew checking. Default: current OS time"),
                )
                .arg(
                    Arg::new("quiet")
                        .long("quiet")
                        .short('q')
                        .action(ArgAction::SetTrue)
                        .help("Exit 0 on valid, 1 on invalid, with no stdout output"),
                ),
        )
}

fn key_source_mnemonic_arg() -> Arg {
    Arg::new("mnemonic-file")
        .long("mnemonic-file")
        .value_parser(clap::value_parser!(PathBuf))
        .conflicts_with("signing-key-file")
        .help("Path to a BIP-39 24-word mnemonic file")
}

fn key_source_signing_key_arg() -> Arg {
    Arg::new("signing-key-file")
        .long("signing-key-file")
        .value_parser(clap::value_parser!(PathBuf))
        .conflicts_with("mnemonic-file")
        .help("Path to a raw 2560-byte ML-DSA-44 signing key file")
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

fn run_keygen(matches: &ArgMatches) -> Result<(), String> {
    let mnemonic_path: &PathBuf = matches.get_one("mnemonic-file").expect("required by clap");
    let phrase = fs::read_to_string(mnemonic_path)
        .map_err(|e| format!("cannot read mnemonic file {}: {e}", mnemonic_path.display()))?;
    let (vk, sk) = derive_keypair_from_mnemonic(phrase.trim()).map_err(|e| e.to_string())?;

    if let Some(path) = matches.get_one::<PathBuf>("output-pubkey") {
        write_bytes_to_path(path, &vk).map_err(|e| format!("cannot write pubkey: {e}"))?;
        eprintln!("wrote {} bytes to {}", vk.len(), path.display());
    } else {
        let mut hex_buf = vec![0u8; vk.len() * 2];
        faster_hex::hex_encode(&vk, &mut hex_buf).expect("hex encode fits");
        println!("{}", String::from_utf8(hex_buf).expect("ascii hex"));
    }

    if let Some(path) = matches.get_one::<PathBuf>("output-signing-key") {
        write_bytes_to_path(path, &sk).map_err(|e| format!("cannot write signing key: {e}"))?;
        set_owner_only_permissions(path).map_err(|e| format!("cannot lock down signing key permissions: {e}"))?;
        eprintln!("wrote {} bytes to {} (owner-only permissions)", sk.len(), path.display());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

fn run_sign(matches: &ArgMatches) -> Result<(), String> {
    let (vk, sk) = load_keypair(matches)?;

    let asset: &String = matches.get_one("asset").expect("required by clap");
    let price_str: &String = matches.get_one("price").expect("required by clap");
    let conf_str: &String = matches.get_one("conf").expect("required by clap");
    let sequence: u64 = *matches.get_one("sequence").expect("required by clap");
    let publish_ts: u64 = matches
        .get_one::<u64>("ts")
        .copied()
        .unwrap_or_else(unix_now_secs);
    let output_format: &String = matches.get_one("output").expect("has default");

    let price_e8 = parse_decimal_e8_signed(price_str).map_err(|e| e.to_string())?;
    let conf_e8 = parse_decimal_e8_unsigned(conf_str).map_err(|e| e.to_string())?;

    let sign_randomness = fresh_randomness::<SIGNING_RANDOMNESS_SIZE>()
        .map_err(|e| format!("cannot read OS randomness for signing: {e}"))?;

    let attestation = build_and_sign_attestation(
        asset.as_bytes(),
        price_e8,
        conf_e8,
        publish_ts,
        sequence,
        vk,
        &sk,
        sign_randomness,
    )
    .map_err(|e| e.to_string())?;

    match output_format.as_str() {
        "hex" => {
            let hex = encode_attestation_hex(&attestation).map_err(|e| e.to_string())?;
            println!("{hex}");
        }
        "raw" => {
            let bytes = attestation
                .to_bytes()
                .map_err(|e| format!("borsh encode failed: {e:?}"))?;
            std::io::stdout()
                .write_all(&bytes)
                .map_err(|e| format!("cannot write raw bytes to stdout: {e}"))?;
        }
        _ => unreachable!("clap restricts --output to hex|raw"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn run_verify(matches: &ArgMatches) -> Result<(), String> {
    let hex_input = match matches.get_one::<String>("hex") {
        Some(h) => h.clone(),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("cannot read hex from stdin: {e}"))?;
            buf
        }
    };
    let attestation = decode_attestation_hex(hex_input.trim()).map_err(|e| e.to_string())?;
    let now: u64 = matches
        .get_one::<u64>("now")
        .copied()
        .unwrap_or_else(unix_now_secs);
    let quiet = matches.get_flag("quiet");

    match verify_attestation_at(&attestation, now) {
        Ok(()) => {
            if !quiet {
                println!(
                    "OK  asset_id={}  price_e8={}  conf_e8={}  publish_ts={}  sequence={}",
                    hex_short(&attestation.core.asset_id),
                    attestation.core.price_e8,
                    attestation.core.conf_e8,
                    attestation.core.publish_ts,
                    attestation.core.sequence,
                );
            }
            Ok(())
        }
        Err(PublisherError::VerifyFailed(inner)) => {
            if !quiet {
                println!("FAIL  reason={inner:?}");
            }
            Err(format!("verification failed: {inner:?}"))
        }
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn load_keypair(
    matches: &ArgMatches,
) -> Result<([u8; DILITHIUM_PUBKEY_SIZE], [u8; DILITHIUM_SIGNING_KEY_SIZE]), String> {
    if let Some(path) = matches.get_one::<PathBuf>("mnemonic-file") {
        let phrase = fs::read_to_string(path)
            .map_err(|e| format!("cannot read mnemonic file {}: {e}", path.display()))?;
        return derive_keypair_from_mnemonic(phrase.trim()).map_err(|e| e.to_string());
    }
    if let Some(path) = matches.get_one::<PathBuf>("signing-key-file") {
        let bytes = fs::read(path)
            .map_err(|e| format!("cannot read signing-key file {}: {e}", path.display()))?;
        if bytes.len() != DILITHIUM_SIGNING_KEY_SIZE {
            return Err(format!(
                "signing-key file is {} bytes, expected {}",
                bytes.len(),
                DILITHIUM_SIGNING_KEY_SIZE
            ));
        }
        let mut sk = [0u8; DILITHIUM_SIGNING_KEY_SIZE];
        sk.copy_from_slice(&bytes);
        // We do not derive the pubkey from a raw signing-key file in v1;
        // operators who use this path must keep the pubkey alongside.
        // For a fresh keypair derived now, the keygen subcommand emits both.
        // To stay self-contained, re-derive by running keygen via libcrux
        // KeyPair::from(signing_key) would require a private API we do not
        // expose; v1 requires the pubkey to be passed via mnemonic flow.
        return Err(format!(
            "raw signing-key flow needs companion pubkey; v1 supports --mnemonic-file only for sign (provided signing-key path: {})",
            path.display()
        ));
    }
    Err("must pass --mnemonic-file (--signing-key-file flow not implemented in v1 sign subcommand)".into())
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fresh_randomness<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}

fn write_bytes_to_path(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &PathBuf) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &PathBuf) -> std::io::Result<()> {
    // Windows ACL changes are operator responsibility; we don't tamper.
    Ok(())
}

fn hex_short(bytes: &[u8; 32]) -> String {
    let mut buf = vec![0u8; 16];
    faster_hex::hex_encode(&bytes[..8], &mut buf).expect("hex encode fits");
    String::from_utf8(buf).expect("ascii hex")
}
