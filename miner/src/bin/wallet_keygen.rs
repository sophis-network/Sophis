//! BIP39 wallet key generator for Sophis.
//!
//! Renamed from `devfund_keygen` after the 2026-05-04 regulatory pivot
//! eliminated the devfund on-chain (see `DECISOES_2026-05-04.md`,
//! decision #2, and `MONETARY_POLICY.md` § 2). The binary stays useful
//! as a personal wallet generator (BIP39 24 words, derivation
//! `m/44'/111111'/0'/0/0`) but no longer has any privileged role —
//! the coinbase is 100% to the miner.
//!
//! Run ONCE, on an offline computer if possible. Store the 24 words in
//! a physically secure location (safe, paper backup, etc.).
//!
//! Usage:
//!   sophis-miner.exe wallet-keygen           # generate a new mnemonic
//!   sophis-miner.exe wallet-keygen --verify  # re-derive from an existing mnemonic
//!
//!   cargo run -p sophis-miner --bin wallet_keygen
//!   cargo run -p sophis-miner --bin wallet_keygen -- --verify

use sophis_addresses::{Address, Prefix, Version};
use sophis_bip32::{ChildNumber, ExtendedPrivateKey, Language, Mnemonic, PrivateKey, SecretKey, SecretKeyExt, WordCount};

// Caminho de derivação BIP44: m / purpose' / coin_type' / account' / change / index
// Sophis coin_type = 111111
const DERIVATION_PATH: &str = "m/44'/111111'/0'/0/0";

fn derive_address(mnemonic: &Mnemonic, prefix: Prefix) -> (String, String) {
    let seed = mnemonic.to_seed("");

    let xprv = ExtendedPrivateKey::<SecretKey>::new(seed.as_bytes()).expect("falha ao criar chave mestre");

    // m/44'/111111'/0'/0/0
    let key = xprv
        .derive_child(ChildNumber::new(44, true).unwrap())       // 44'  purpose
        .unwrap()
        .derive_child(ChildNumber::new(111111, true).unwrap())   // 111111'  coin type
        .unwrap()
        .derive_child(ChildNumber::new(0, true).unwrap())        // 0'  account
        .unwrap()
        .derive_child(ChildNumber::new(0, false).unwrap())       // 0  receive
        .unwrap()
        .derive_child(ChildNumber::new(0, false).unwrap())       // 0  index
        .unwrap();

    let secret_key = key.private_key();
    let xonly = secret_key.get_public_key().x_only_public_key().0;
    let address = Address::new(prefix, Version::PubKeyDilithium, &xonly.serialize());
    let privkey_hex = hex::encode(secret_key.to_bytes());

    (String::from(&address), privkey_hex)
}

fn print_separator() {
    println!("{}", "═".repeat(64));
}

fn main() {
    let verify_mode = std::env::args().any(|a| a == "--verify");

    print_separator();
    println!("  GERADOR DE CHAVES — DEV FUND SOPHIS ($SPHS)");
    println!("  Derivação: {DERIVATION_PATH}");
    print_separator();
    println!();

    let mnemonic = if verify_mode {
        println!("  Digite as 24 palavras separadas por espaço:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("erro ao ler entrada");
        let phrase = input.trim();
        Mnemonic::new(phrase, Language::English).expect("Frase inválida — verifique as palavras e a ortografia")
    } else {
        Mnemonic::random(WordCount::Words24, Language::English).expect("erro ao gerar mnemônica")
    };

    // Deriva endereços e chave privada para o índice 0
    let (mainnet_addr, privkey_hex) = derive_address(&mnemonic, Prefix::Mainnet);
    let (testnet_addr, _) = derive_address(&mnemonic, Prefix::Testnet);
    let (devnet_addr, _) = derive_address(&mnemonic, Prefix::Devnet);

    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │  FRASE MNEMÔNICA (24 PALAVRAS) — GUARDE COM SEGURANÇA  │");
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();

    // Exibe em 4 linhas de 6 palavras para facilitar anotação
    let words: Vec<&str> = mnemonic.phrase().split_whitespace().collect();
    for (i, chunk) in words.chunks(6).enumerate() {
        let line = chunk.iter().enumerate().map(|(j, w)| format!("{:>2}. {:<12}", i * 6 + j + 1, w)).collect::<Vec<_>>().join("  ");
        println!("  {line}");
    }

    println!();
    print_separator();
    println!("  ENDEREÇOS DERIVADOS ({DERIVATION_PATH})");
    print_separator();
    println!();
    println!("  Mainnet  : {mainnet_addr}");
    println!("  Testnet  : {testnet_addr}");
    println!("  Devnet   : {devnet_addr}");
    println!();
    print_separator();
    println!("  CHAVE PRIVADA DO ÍNDICE 0 (somente se necessário para assinar)");
    print_separator();
    println!();
    println!("  {privkey_hex}");
    println!();
    print_separator();
    println!("  PRÓXIMOS PASSOS");
    print_separator();
    println!();
    println!("  1. Anote as 24 palavras em papel e guarde em local seguro.");
    println!("     NUNCA fotografe, copie em nuvem ou envie por mensagem.");
    println!();
    println!("  2. Use o endereço mainnet abaixo como destino do seu miner:");
    println!("       {mainnet_addr}");
    println!();
    println!("     (Endereço testnet, para treino):");
    println!("       {testnet_addr}");
    println!();
    println!("  3. Para verificar que a frase gera os mesmos endereços:");
    println!("       cargo run -p sophis-miner --bin wallet_keygen -- --verify");
    println!();
    print_separator();
}
