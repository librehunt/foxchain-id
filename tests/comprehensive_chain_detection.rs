//! Comprehensive per-chain detection tests
//!
//! Covers every chain present in metadata/chains/ for all supported input types:
//! - Address detection (positive + no false-positive BlockHash)
//! - Transaction detection (positive + non-regression)
//! - Block hash detection (positive where template exists, negative where absent)
//! - Scanner URL correctness
//! - Confidence score ranges
//! - Normalization (lowercase hex, checksum EVM address, etc.)
//!
//! Chain inventory (29 chains total):
//!
//! WITH block_hash_scanner_url_template (21):
//!   EVM (confidence 0.55):    ethereum, bsc, polygon, avalanche, arbitrum, optimism,
//!                              fantom, gnosis, celo, base
//!   UTXO (confidence 0.50):   bitcoin, litecoin, dogecoin
//!   Solana (confidence 0.75): solana
//!   Tron (confidence 0.50):   tron
//!   Cosmos w/ template:        cosmos_hub, osmosis, juno
//!   Substrate w/ template:     polkadot, kusama
//!   Cardano (confidence 0.50): cardano
//!
//! WITHOUT block_hash_scanner_url_template (8):
//!   Cosmos (no template):      akash, kava, regen, secret_network, sentinel, stargaze, terra
//!   Substrate (no template):   substrate

use foxchain_id::{identify, InputType};

// ============================================================================
// Shared test inputs
// ============================================================================

/// Real Ethereum block #1 hash (keccak-256, 0x + 64 hex = 66 chars)
const EVM_BLOCK_HASH: &str = "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6";

/// Bitcoin genesis block hash (SHA-256d, 64 hex, no 0x).
/// Valid input for ALL chains that use 64-char hex no-0x:
/// bitcoin, litecoin, dogecoin, tron, cosmos_hub, osmosis, juno, polkadot, kusama, cardano
const HEX64_BLOCK_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

/// Real Solana blockhash (32-byte hash in Base58, 44 chars)
const SOLANA_BLOCK_HASH: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

/// Known EVM tx hash (same format as EVM block hash — ambiguous)
const EVM_TX_HASH: &str = "0xcdf331416ac94df404cfa95b13ecd4b23b2b1de895c945e25ff1b557c597a64e";

/// Bitcoin genesis coinbase tx hash (same format as Bitcoin block hash — ambiguous)
const BITCOIN_TX_HASH: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

/// Solana tx signature (85-90 char Base58 — DIFFERENT from Solana block hash)
const SOLANA_TX_SIG: &str =
    "5wpHU1gGYcgKabL7heGGgiKBx3WJMruHiN34sCjTYwQu4sk9H2uMyZsm1P28RqaJPVELtcVxNmSGieq6V5ZZxpDT";

/// Substrate extrinsic ID (block_height-index format)
const SUBSTRATE_EXTRINSIC: &str = "28815161-0";

/// EVM address (42 chars, 0x + 40 hex)
const EVM_ADDRESS: &str = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";

/// Bitcoin P2PKH address (genesis block miner address)
const BITCOIN_ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";

/// Bitcoin Bech32 address
const BITCOIN_BECH32: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

/// Solana address / Ed25519 public key (32-44 char Base58)
const SOLANA_ADDRESS: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

// ============================================================================
// Helper
// ============================================================================

fn block_hash_chains(input: &str) -> Vec<String> {
    identify(input)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.input_type == InputType::BlockHash)
        .map(|c| c.chain)
        .collect()
}

fn tx_chains(input: &str) -> Vec<String> {
    identify(input)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.input_type == InputType::Transaction)
        .map(|c| c.chain)
        .collect()
}

fn address_chains(input: &str) -> Vec<String> {
    identify(input)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.input_type == InputType::Address)
        .map(|c| c.chain)
        .collect()
}

fn get_block_hash_candidate(
    input: &str,
    chain: &str,
) -> Option<foxchain_id::IdentificationCandidate> {
    identify(input)
        .ok()?
        .into_iter()
        .find(|c| c.input_type == InputType::BlockHash && c.chain == chain)
}

fn get_tx_candidate(input: &str, chain: &str) -> Option<foxchain_id::IdentificationCandidate> {
    identify(input)
        .ok()?
        .into_iter()
        .find(|c| c.input_type == InputType::Transaction && c.chain == chain)
}

// ============================================================================
// 1. EVM chains — block hash detection (all 10 chains)
// ============================================================================

#[test]
fn test_evm_all_chains_return_block_hash() {
    let evm_chains = [
        "ethereum",
        "bsc",
        "polygon",
        "avalanche",
        "arbitrum",
        "optimism",
        "fantom",
        "gnosis",
        "celo",
        "base",
    ];
    let chains = block_hash_chains(EVM_BLOCK_HASH);

    for &chain in &evm_chains {
        assert!(
            chains.contains(&chain.to_string()),
            "EVM chain '{chain}' should return BlockHash candidate for EVM block hash input"
        );
    }
}

#[test]
fn test_evm_all_chains_confidence_is_0_55() {
    let evm_chains = [
        "ethereum",
        "bsc",
        "polygon",
        "avalanche",
        "arbitrum",
        "optimism",
        "fantom",
        "gnosis",
        "celo",
        "base",
    ];
    for &chain in &evm_chains {
        let c = get_block_hash_candidate(EVM_BLOCK_HASH, chain)
            .unwrap_or_else(|| panic!("No BlockHash candidate for EVM chain '{chain}'"));
        assert!(
            (c.confidence - 0.55).abs() < 1e-9,
            "EVM chain '{chain}' should have confidence 0.55, got {}",
            c.confidence
        );
    }
}

#[test]
fn test_evm_all_chains_normalized_lowercase() {
    let evm_chains = [
        "ethereum",
        "bsc",
        "polygon",
        "avalanche",
        "arbitrum",
        "optimism",
        "fantom",
        "gnosis",
        "celo",
        "base",
    ];
    let upper_input = EVM_BLOCK_HASH.to_uppercase().replacen("0X", "0x", 1);
    for &chain in &evm_chains {
        let c = get_block_hash_candidate(&upper_input, chain)
            .unwrap_or_else(|| panic!("No BlockHash candidate for EVM chain '{chain}'"));
        assert_eq!(
            c.normalized,
            c.normalized.to_lowercase(),
            "EVM chain '{chain}' block hash should be normalized to lowercase"
        );
        assert!(
            c.normalized.starts_with("0x"),
            "EVM chain '{chain}' normalized should start with 0x"
        );
        assert_eq!(
            c.normalized.len(),
            66,
            "EVM chain '{chain}' normalized should be 66 chars"
        );
    }
}

#[test]
fn test_evm_all_chains_scanner_url_correct() {
    let expected = [
        ("ethereum", "etherscan.io/block/"),
        ("bsc", "bscscan.com/block/"),
        ("polygon", "polygonscan.com/block/"),
        ("avalanche", "snowtrace.io/block/"),
        ("arbitrum", "arbiscan.io/block/"),
        ("optimism", "optimistic.etherscan.io/block/"),
        ("fantom", "ftmscan.com/block/"),
        ("gnosis", "gnosisscan.io/block/"),
        ("celo", "celoscan.io/block/"),
        ("base", "basescan.org/block/"),
    ];
    for (chain, url_fragment) in &expected {
        let c = get_block_hash_candidate(EVM_BLOCK_HASH, chain)
            .unwrap_or_else(|| panic!("No BlockHash candidate for EVM chain '{chain}'"));
        let url = c
            .scanner_url
            .as_deref()
            .unwrap_or_else(|| panic!("EVM chain '{chain}' block hash should have a scanner_url"));
        assert!(
            url.contains(url_fragment),
            "EVM chain '{chain}' scanner URL should contain '{url_fragment}', got: {url}"
        );
        // URL must contain the normalized hash
        assert!(
            url.contains(&EVM_BLOCK_HASH.to_lowercase()),
            "EVM chain '{chain}' scanner URL should contain the hash, got: {url}"
        );
    }
}

#[test]
fn test_evm_block_hash_also_returns_transaction_candidates() {
    // EVM block hash and tx hash are format-identical — both must be returned
    let chains = tx_chains(EVM_BLOCK_HASH);
    assert!(
        chains.contains(&"ethereum".to_string()),
        "Ethereum should also return Transaction candidate (ambiguity)"
    );
    let bh_chains = block_hash_chains(EVM_BLOCK_HASH);
    assert!(
        !bh_chains.is_empty(),
        "Should also return BlockHash candidates"
    );
}

// ============================================================================
// 2. UTXO chains — block hash detection (bitcoin, litecoin, dogecoin)
// ============================================================================

#[test]
fn test_utxo_all_chains_return_block_hash() {
    let utxo_chains = ["bitcoin", "litecoin", "dogecoin"];
    let chains = block_hash_chains(HEX64_BLOCK_HASH);

    for &chain in &utxo_chains {
        assert!(
            chains.contains(&chain.to_string()),
            "UTXO chain '{chain}' should return BlockHash candidate for 64-char hex input"
        );
    }
}

#[test]
fn test_utxo_all_chains_confidence_is_0_50() {
    let utxo_chains = ["bitcoin", "litecoin", "dogecoin"];
    for &chain in &utxo_chains {
        let c = get_block_hash_candidate(HEX64_BLOCK_HASH, chain)
            .unwrap_or_else(|| panic!("No BlockHash candidate for UTXO chain '{chain}'"));
        assert!(
            (c.confidence - 0.50).abs() < 1e-9,
            "UTXO chain '{chain}' should have confidence 0.50, got {}",
            c.confidence
        );
    }
}

#[test]
fn test_utxo_all_chains_scanner_url_correct() {
    let expected = [
        ("bitcoin", "blockchain.com/explorer/blocks/btc/"),
        ("litecoin", "litecoinspace.org/block/"),
        ("dogecoin", "blockchair.com/dogecoin/block/"),
    ];
    for (chain, url_fragment) in &expected {
        let c = get_block_hash_candidate(HEX64_BLOCK_HASH, chain)
            .unwrap_or_else(|| panic!("No BlockHash candidate for UTXO chain '{chain}'"));
        let url = c
            .scanner_url
            .as_deref()
            .unwrap_or_else(|| panic!("UTXO chain '{chain}' block hash should have a scanner_url"));
        assert!(
            url.contains(url_fragment),
            "UTXO chain '{chain}' scanner URL should contain '{url_fragment}', got: {url}"
        );
    }
}

#[test]
fn test_utxo_block_hash_normalized_lowercase() {
    let upper = "000000000019D6689C085AE165831E934FF763AE46A2A6C172B3F1B60A8CE26F";
    for chain in &["bitcoin", "litecoin", "dogecoin"] {
        let c = get_block_hash_candidate(upper, chain)
            .unwrap_or_else(|| panic!("No BlockHash candidate for UTXO chain '{chain}'"));
        assert_eq!(
            c.normalized,
            c.normalized.to_lowercase(),
            "UTXO chain '{chain}' block hash should be normalized to lowercase"
        );
        assert_eq!(
            c.normalized.len(),
            64,
            "UTXO chain '{chain}' normalized block hash should be 64 chars"
        );
    }
}

#[test]
fn test_utxo_block_hash_also_returns_transaction() {
    // 64-char hex is ambiguous for UTXO chains
    let bh_chains = block_hash_chains(HEX64_BLOCK_HASH);
    let tx_chains_list = tx_chains(HEX64_BLOCK_HASH);
    assert!(
        bh_chains.contains(&"bitcoin".to_string()),
        "Bitcoin should return BlockHash"
    );
    assert!(
        tx_chains_list.contains(&"bitcoin".to_string()),
        "Bitcoin should also return Transaction (ambiguity)"
    );
}

// ============================================================================
// 3. Solana — block hash detection (distinctive format)
// ============================================================================

#[test]
fn test_solana_block_hash_detected() {
    let chains = block_hash_chains(SOLANA_BLOCK_HASH);
    assert!(
        chains.contains(&"solana".to_string()),
        "Solana should return BlockHash candidate for 32-44 char Base58 input"
    );
}

#[test]
fn test_solana_block_hash_confidence_is_0_75() {
    let c = get_block_hash_candidate(SOLANA_BLOCK_HASH, "solana")
        .expect("No BlockHash candidate for Solana");
    assert!(
        (c.confidence - 0.75).abs() < 1e-9,
        "Solana block hash should have confidence 0.75, got {}",
        c.confidence
    );
}

#[test]
fn test_solana_block_hash_confidence_higher_than_evm() {
    let solana_c = get_block_hash_candidate(SOLANA_BLOCK_HASH, "solana")
        .expect("No BlockHash candidate for Solana");
    let evm_c = get_block_hash_candidate(EVM_BLOCK_HASH, "ethereum")
        .expect("No BlockHash candidate for Ethereum");
    assert!(
        solana_c.confidence > evm_c.confidence,
        "Solana block hash confidence ({}) should be > EVM ({})",
        solana_c.confidence,
        evm_c.confidence
    );
}

#[test]
fn test_solana_block_hash_preserves_base58_casing() {
    let c = get_block_hash_candidate(SOLANA_BLOCK_HASH, "solana")
        .expect("No BlockHash candidate for Solana");
    assert_eq!(
        c.normalized, SOLANA_BLOCK_HASH,
        "Solana block hash should preserve Base58 casing"
    );
}

#[test]
fn test_solana_block_hash_scanner_url() {
    let c = get_block_hash_candidate(SOLANA_BLOCK_HASH, "solana")
        .expect("No BlockHash candidate for Solana");
    let url = c
        .scanner_url
        .as_deref()
        .expect("Solana block hash should have scanner_url");
    assert!(
        url.contains("solscan.io/block/"),
        "Solana scanner URL should point to solscan block, got: {url}"
    );
    assert!(
        url.contains(SOLANA_BLOCK_HASH),
        "Solana scanner URL should contain the hash, got: {url}"
    );
}

#[test]
fn test_solana_tx_signature_not_block_hash() {
    // 85-90 char Base58 tx signature should NOT trigger BlockHash
    let chains = block_hash_chains(SOLANA_TX_SIG);
    assert!(
        !chains.contains(&"solana".to_string()),
        "Solana tx signature (85-90 char Base58) should NOT return BlockHash"
    );
}

#[test]
fn test_solana_tx_signature_still_returns_transaction() {
    let chains = tx_chains(SOLANA_TX_SIG);
    assert!(
        chains.contains(&"solana".to_string()),
        "Solana tx signature should return Transaction candidate"
    );
}

// ============================================================================
// 4. Tron — block hash detection
// ============================================================================

#[test]
fn test_tron_block_hash_detected() {
    let chains = block_hash_chains(HEX64_BLOCK_HASH);
    assert!(
        chains.contains(&"tron".to_string()),
        "Tron should return BlockHash candidate for 64-char hex input"
    );
}

#[test]
fn test_tron_block_hash_confidence_is_0_50() {
    let c = get_block_hash_candidate(HEX64_BLOCK_HASH, "tron")
        .expect("No BlockHash candidate for Tron");
    assert!(
        (c.confidence - 0.50).abs() < 1e-9,
        "Tron block hash should have confidence 0.50, got {}",
        c.confidence
    );
}

#[test]
fn test_tron_block_hash_scanner_url() {
    let c = get_block_hash_candidate(HEX64_BLOCK_HASH, "tron")
        .expect("No BlockHash candidate for Tron");
    let url = c
        .scanner_url
        .as_deref()
        .expect("Tron block hash should have scanner_url");
    assert!(
        url.contains("tronscan.org") && url.contains("/block/"),
        "Tron scanner URL should point to tronscan block, got: {url}"
    );
}

// ============================================================================
// 5. Cosmos chains WITH template — cosmos_hub, osmosis, juno
// ============================================================================

#[test]
fn test_cosmos_chains_with_template_return_block_hash() {
    let cosmos_chains = ["cosmos_hub", "osmosis", "juno"];
    let chains = block_hash_chains(HEX64_BLOCK_HASH);

    for &chain in &cosmos_chains {
        assert!(
            chains.contains(&chain.to_string()),
            "Cosmos chain '{chain}' should return BlockHash candidate for 64-char hex input"
        );
    }
}

#[test]
fn test_cosmos_chains_with_template_confidence_is_0_50() {
    let cosmos_chains = ["cosmos_hub", "osmosis", "juno"];
    for &chain in &cosmos_chains {
        let c = get_block_hash_candidate(HEX64_BLOCK_HASH, chain)
            .unwrap_or_else(|| panic!("No BlockHash candidate for Cosmos chain '{chain}'"));
        assert!(
            (c.confidence - 0.50).abs() < 1e-9,
            "Cosmos chain '{chain}' should have confidence 0.50, got {}",
            c.confidence
        );
    }
}

#[test]
fn test_cosmos_chains_with_template_scanner_urls() {
    let expected = [
        ("cosmos_hub", "mintscan.io/cosmos/blocks/"),
        ("osmosis", "mintscan.io/osmosis/blocks/"),
        ("juno", "mintscan.io/juno/blocks/"),
    ];
    for (chain, url_fragment) in &expected {
        let c = get_block_hash_candidate(HEX64_BLOCK_HASH, chain)
            .unwrap_or_else(|| panic!("No BlockHash candidate for Cosmos chain '{chain}'"));
        let url = c
            .scanner_url
            .as_deref()
            .unwrap_or_else(|| panic!("Cosmos chain '{chain}' block hash should have scanner_url"));
        assert!(
            url.contains(url_fragment),
            "Cosmos chain '{chain}' scanner URL should contain '{url_fragment}', got: {url}"
        );
    }
}

// ============================================================================
// 6. Cosmos chains WITHOUT template — should NOT return BlockHash
// ============================================================================

#[test]
fn test_cosmos_chains_without_template_no_block_hash() {
    // These chains have no block_hash_scanner_url_template
    let no_template_chains = [
        "akash",
        "kava",
        "regen",
        "secret_network",
        "sentinel",
        "stargaze",
        "terra",
    ];
    let chains = block_hash_chains(HEX64_BLOCK_HASH);

    for &chain in &no_template_chains {
        assert!(
            !chains.contains(&chain.to_string()),
            "Cosmos chain '{chain}' (no block_hash_scanner_url_template) should NOT return BlockHash"
        );
    }
}

// ============================================================================
// 7. Substrate chains WITH template — polkadot, kusama
// ============================================================================

#[test]
fn test_substrate_chains_with_template_return_block_hash() {
    let substrate_chains = ["polkadot", "kusama"];
    let chains = block_hash_chains(HEX64_BLOCK_HASH);

    for &chain in &substrate_chains {
        assert!(
            chains.contains(&chain.to_string()),
            "Substrate chain '{chain}' should return BlockHash candidate for 64-char hex input"
        );
    }
}

#[test]
fn test_substrate_chains_with_template_confidence_is_0_50() {
    for chain in &["polkadot", "kusama"] {
        let c = get_block_hash_candidate(HEX64_BLOCK_HASH, chain)
            .unwrap_or_else(|| panic!("No BlockHash candidate for Substrate chain '{chain}'"));
        assert!(
            (c.confidence - 0.50).abs() < 1e-9,
            "Substrate chain '{chain}' should have confidence 0.50, got {}",
            c.confidence
        );
    }
}

#[test]
fn test_substrate_chains_with_template_scanner_urls() {
    let expected = [
        ("polkadot", "polkadot.subscan.io/block/"),
        ("kusama", "kusama.subscan.io/block/"),
    ];
    for (chain, url_fragment) in &expected {
        let c = get_block_hash_candidate(HEX64_BLOCK_HASH, chain)
            .unwrap_or_else(|| panic!("No BlockHash candidate for Substrate chain '{chain}'"));
        let url = c.scanner_url.as_deref().unwrap_or_else(|| {
            panic!("Substrate chain '{chain}' block hash should have scanner_url")
        });
        assert!(
            url.contains(url_fragment),
            "Substrate chain '{chain}' scanner URL should contain '{url_fragment}', got: {url}"
        );
    }
}

#[test]
fn test_substrate_generic_no_block_hash() {
    // Generic "substrate" chain has no block_hash_scanner_url_template
    let chains = block_hash_chains(HEX64_BLOCK_HASH);
    assert!(
        !chains.contains(&"substrate".to_string()),
        "Generic 'substrate' chain (no block_hash_scanner_url_template) should NOT return BlockHash"
    );
}

// ============================================================================
// 8. Cardano — block hash detection
// ============================================================================

#[test]
fn test_cardano_block_hash_detected() {
    let chains = block_hash_chains(HEX64_BLOCK_HASH);
    assert!(
        chains.contains(&"cardano".to_string()),
        "Cardano should return BlockHash candidate for 64-char hex input"
    );
}

#[test]
fn test_cardano_block_hash_confidence_is_0_50() {
    let c = get_block_hash_candidate(HEX64_BLOCK_HASH, "cardano")
        .expect("No BlockHash candidate for Cardano");
    assert!(
        (c.confidence - 0.50).abs() < 1e-9,
        "Cardano block hash should have confidence 0.50, got {}",
        c.confidence
    );
}

#[test]
fn test_cardano_block_hash_scanner_url() {
    let c = get_block_hash_candidate(HEX64_BLOCK_HASH, "cardano")
        .expect("No BlockHash candidate for Cardano");
    let url = c
        .scanner_url
        .as_deref()
        .expect("Cardano block hash should have scanner_url");
    assert!(
        url.contains("cardanoscan.io/block/"),
        "Cardano scanner URL should point to cardanoscan block, got: {url}"
    );
}

// ============================================================================
// 9. EVM address inputs — must NOT trigger BlockHash
// ============================================================================

#[test]
fn test_evm_address_never_returns_block_hash() {
    let evm_chains = [
        "ethereum",
        "bsc",
        "polygon",
        "avalanche",
        "arbitrum",
        "optimism",
        "fantom",
        "gnosis",
        "celo",
        "base",
    ];
    let bh_chains = block_hash_chains(EVM_ADDRESS);
    for &chain in &evm_chains {
        assert!(
            !bh_chains.contains(&chain.to_string()),
            "EVM address input should NOT return BlockHash for chain '{chain}'"
        );
    }
}

#[test]
fn test_evm_address_returns_address() {
    let addr_chains = address_chains(EVM_ADDRESS);
    assert!(
        addr_chains.contains(&"ethereum".to_string()),
        "EVM address should be identified as Address for ethereum"
    );
}

// ============================================================================
// 10. Bitcoin address inputs — must NOT trigger BlockHash
// ============================================================================

#[test]
fn test_bitcoin_p2pkh_address_no_block_hash() {
    let bh_chains = block_hash_chains(BITCOIN_ADDRESS);
    assert!(
        !bh_chains.contains(&"bitcoin".to_string()),
        "Bitcoin P2PKH address should NOT return BlockHash"
    );
}

#[test]
fn test_bitcoin_p2pkh_address_returns_address() {
    let addr_chains = address_chains(BITCOIN_ADDRESS);
    assert!(
        addr_chains.contains(&"bitcoin".to_string()),
        "Bitcoin P2PKH address should be identified as Address"
    );
}

#[test]
fn test_bitcoin_bech32_address_no_block_hash() {
    let bh_chains = block_hash_chains(BITCOIN_BECH32);
    assert!(
        !bh_chains.contains(&"bitcoin".to_string()),
        "Bitcoin Bech32 address should NOT return BlockHash"
    );
}

// ============================================================================
// 11. Solana: 32-44 char Base58 is ambiguous (Address + BlockHash both expected)
// ============================================================================

#[test]
fn test_solana_base58_returns_both_address_and_block_hash() {
    // Solana addresses and block hashes share the exact same format (32-byte Base58).
    // The library should return BOTH Address and BlockHash candidates.
    let results = identify(SOLANA_ADDRESS).expect("should identify 32-44 char Base58");
    let has_address = results.iter().any(|c| c.input_type == InputType::Address);
    let has_block_hash = results.iter().any(|c| c.input_type == InputType::BlockHash);

    assert!(
        has_address || has_block_hash,
        "32-44 char Base58 must return at least one of Address or BlockHash for Solana"
    );
    // Both should be present since format is identical
    assert!(
        has_address,
        "Solana Base58 should return Address candidate (same format as blockhash)"
    );
    assert!(
        has_block_hash,
        "Solana Base58 should also return BlockHash candidate (same format as address)"
    );
}

// ============================================================================
// 12. Transaction non-regression — existing tx detection must still work
// ============================================================================

#[test]
fn test_evm_tx_hash_still_returns_transaction_for_all_evm_chains() {
    let evm_chains = [
        "ethereum",
        "bsc",
        "polygon",
        "avalanche",
        "arbitrum",
        "optimism",
        "fantom",
        "gnosis",
        "celo",
        "base",
    ];
    let chains = tx_chains(EVM_TX_HASH);
    for &chain in &evm_chains {
        assert!(
            chains.contains(&chain.to_string()),
            "EVM chain '{chain}' should still return Transaction candidate (non-regression)"
        );
    }
}

#[test]
fn test_bitcoin_tx_hash_still_returns_transaction() {
    let chains = tx_chains(BITCOIN_TX_HASH);
    assert!(
        chains.contains(&"bitcoin".to_string()),
        "Bitcoin should still return Transaction candidate (non-regression)"
    );
}

#[test]
fn test_litecoin_tx_hash_still_returns_transaction() {
    // Litecoin uses same format as Bitcoin tx hash
    let chains = tx_chains(BITCOIN_TX_HASH);
    assert!(
        chains.contains(&"litecoin".to_string()),
        "Litecoin should still return Transaction candidate for 64-char hex (non-regression)"
    );
}

#[test]
fn test_dogecoin_tx_hash_still_returns_transaction() {
    let chains = tx_chains(BITCOIN_TX_HASH);
    assert!(
        chains.contains(&"dogecoin".to_string()),
        "Dogecoin should still return Transaction candidate for 64-char hex (non-regression)"
    );
}

#[test]
fn test_solana_tx_sig_non_regression_transaction() {
    let chains = tx_chains(SOLANA_TX_SIG);
    assert!(
        chains.contains(&"solana".to_string()),
        "Solana should still return Transaction candidate for 85-90 char Base58 (non-regression)"
    );
}

#[test]
fn test_substrate_extrinsic_still_returns_transaction() {
    let chains = tx_chains(SUBSTRATE_EXTRINSIC);
    assert!(
        chains.iter().any(|c| c == "polkadot" || c == "kusama" || c == "substrate"),
        "Substrate extrinsic ID should still return Transaction candidate (non-regression), got: {:?}",
        chains
    );
}

#[test]
fn test_tron_tx_hash_still_returns_transaction() {
    // Tron tx is 64-char hex no-0x
    let chains = tx_chains(BITCOIN_TX_HASH);
    assert!(
        chains.contains(&"tron".to_string()),
        "Tron should still return Transaction candidate for 64-char hex (non-regression)"
    );
}

#[test]
fn test_cosmos_hub_tx_hash_still_returns_transaction() {
    let chains = tx_chains(BITCOIN_TX_HASH);
    assert!(
        chains.contains(&"cosmos_hub".to_string()),
        "Cosmos Hub should still return Transaction candidate for 64-char hex (non-regression)"
    );
}

#[test]
fn test_cardano_tx_hash_still_returns_transaction() {
    let chains = tx_chains(BITCOIN_TX_HASH);
    assert!(
        chains.contains(&"cardano".to_string()),
        "Cardano should still return Transaction candidate for 64-char hex (non-regression)"
    );
}

// ============================================================================
// 13. Transaction confidence scores — non-regression
// ============================================================================

#[test]
fn test_evm_tx_hash_confidence() {
    let c = get_tx_candidate(EVM_TX_HASH, "ethereum").expect("No Transaction for ethereum");
    assert!(
        c.confidence > 0.0 && c.confidence <= 1.0,
        "Ethereum tx confidence should be in (0, 1], got {}",
        c.confidence
    );
}

#[test]
fn test_solana_tx_confidence() {
    // Solana tx signature (85-90 char Base58) confidence = 0.70
    // Higher than ambiguous 0.50 formats, because the length range is fairly distinctive
    let c = get_tx_candidate(SOLANA_TX_SIG, "solana").expect("No Transaction for solana");
    assert!(
        (c.confidence - 0.70).abs() < 1e-9,
        "Solana tx signature confidence should be 0.70, got {}",
        c.confidence
    );
}

// ============================================================================
// 14. Block hash: 21 chains total coverage check
// ============================================================================

#[test]
fn test_total_evm_block_hash_count() {
    // EVM block hash input should trigger exactly 10 EVM chains as BlockHash
    let bh_evm: Vec<_> = identify(EVM_BLOCK_HASH)
        .expect("should identify EVM block hash")
        .into_iter()
        .filter(|c| c.input_type == InputType::BlockHash)
        .collect();

    assert_eq!(
        bh_evm.len(),
        10,
        "EVM block hash (0x+64hex) should return exactly 10 BlockHash candidates (all EVM chains), got: {:?}",
        bh_evm.iter().map(|c| &c.chain).collect::<Vec<_>>()
    );
}

#[test]
fn test_total_hex64_block_hash_count() {
    // 64-char hex no-0x should match: bitcoin(1) + litecoin(1) + dogecoin(1) +
    // tron(1) + cosmos_hub(1) + osmosis(1) + juno(1) +
    // polkadot(1) + kusama(1) + cardano(1) = 10 chains
    let bh_candidates: Vec<_> = identify(HEX64_BLOCK_HASH)
        .expect("should identify 64-char hex")
        .into_iter()
        .filter(|c| c.input_type == InputType::BlockHash)
        .collect();

    let chains: Vec<&str> = bh_candidates.iter().map(|c| c.chain.as_str()).collect();
    let expected_chains = [
        "bitcoin",
        "litecoin",
        "dogecoin",
        "tron",
        "cosmos_hub",
        "osmosis",
        "juno",
        "polkadot",
        "kusama",
        "cardano",
    ];
    for &expected in &expected_chains {
        assert!(
            chains.contains(&expected),
            "64-char hex block hash should match chain '{expected}', got: {chains:?}"
        );
    }
    assert_eq!(
        bh_candidates.len(),
        10,
        "64-char hex block hash should return exactly 10 BlockHash candidates, got: {chains:?}"
    );
}

#[test]
fn test_total_solana_block_hash_count() {
    // Solana block hash (32-44 char Base58) should return exactly 1 BlockHash candidate (Solana)
    let bh_candidates: Vec<_> = identify(SOLANA_BLOCK_HASH)
        .expect("should identify Solana block hash")
        .into_iter()
        .filter(|c| c.input_type == InputType::BlockHash)
        .collect();

    assert_eq!(
        bh_candidates.len(),
        1,
        "Solana Base58 block hash should return exactly 1 BlockHash candidate (Solana), got: {:?}",
        bh_candidates.iter().map(|c| &c.chain).collect::<Vec<_>>()
    );
    assert_eq!(bh_candidates[0].chain, "solana");
}

// ============================================================================
// 15. Sorted by confidence (highest first)
// ============================================================================

#[test]
fn test_results_sorted_by_confidence_desc() {
    for input in &[EVM_BLOCK_HASH, HEX64_BLOCK_HASH, SOLANA_BLOCK_HASH] {
        let results = identify(input).expect("should identify input");
        for i in 1..results.len() {
            assert!(
                results[i - 1].confidence >= results[i].confidence,
                "Results should be sorted by confidence desc for input '{}': \
                position {} (confidence {}) < position {} (confidence {})",
                input,
                i - 1,
                results[i - 1].confidence,
                i,
                results[i].confidence
            );
        }
    }
}

// ============================================================================
// 16. Reasoning field is never empty
// ============================================================================

#[test]
fn test_block_hash_reasoning_not_empty() {
    for (input, label) in &[
        (EVM_BLOCK_HASH, "EVM"),
        (HEX64_BLOCK_HASH, "64-hex"),
        (SOLANA_BLOCK_HASH, "Solana"),
    ] {
        let results = identify(input).expect("should identify input");
        for c in results
            .iter()
            .filter(|c| c.input_type == InputType::BlockHash)
        {
            assert!(
                !c.reasoning.is_empty(),
                "{label} BlockHash candidate for chain '{}' should have non-empty reasoning",
                c.chain
            );
        }
    }
}

// ============================================================================
// 17. Edge cases
// ============================================================================

#[test]
fn test_63_char_hex_not_block_hash() {
    // One char short — not a valid block hash
    let input = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26";
    let result = identify(input);
    if let Ok(results) = result {
        assert!(
            results.iter().all(|c| c.input_type != InputType::BlockHash),
            "63-char hex should NOT return BlockHash"
        );
    }
}

#[test]
fn test_65_char_hex_not_block_hash() {
    // One char over 64 — not a valid block hash
    let input = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f00";
    let result = identify(input);
    if let Ok(results) = result {
        assert!(
            results.iter().all(|c| c.input_type != InputType::BlockHash),
            "65-char hex without 0x prefix should NOT return BlockHash"
        );
    }
}

#[test]
fn test_evm_hash_without_0x_prefix_not_evm_block_hash() {
    // EVM block hash without 0x → 64 raw hex → matches UTXO/Tron/Cosmos/Cardano/Substrate,
    // NOT EVM chains (which require the 0x prefix)
    let input = "88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6";
    let results = identify(input).expect("should identify 64-char hex");
    let bh_evm: Vec<_> = results
        .iter()
        .filter(|c| {
            c.input_type == InputType::BlockHash
                && ["ethereum", "bsc", "polygon", "avalanche", "arbitrum"]
                    .contains(&c.chain.as_str())
        })
        .collect();
    assert!(
        bh_evm.is_empty(),
        "64-char hex WITHOUT 0x should NOT trigger EVM BlockHash candidates"
    );
    // But should trigger non-EVM chains
    let bh_chains = block_hash_chains(input);
    assert!(
        bh_chains.contains(&"bitcoin".to_string()),
        "64-char hex without 0x SHOULD trigger Bitcoin BlockHash"
    );
}

#[test]
fn test_empty_input_returns_error() {
    assert!(identify("").is_err(), "Empty input should return error");
}

#[test]
fn test_random_string_returns_error() {
    assert!(
        identify("notahashnotanaddress").is_err(),
        "Unrecognized string should return error"
    );
}
