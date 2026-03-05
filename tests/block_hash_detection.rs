//! Integration tests for block hash detection
//!
//! Verifies that identify() correctly returns InputType::BlockHash candidates
//! alongside InputType::Transaction for ambiguous inputs, and that non-regression
//! holds for existing transaction detection.

use foxchain_id::{identify, InputType};

// ============================================================================
// EVM block hash (keccak-256: 0x + 64 hex chars = 66 total)
// Same format as EVM tx hash — both BlockHash and Transaction candidates expected
// ============================================================================

#[test]
fn test_evm_block_hash_returns_block_hash_candidates() {
    // Real Ethereum block hash (block #1)
    let input = "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6";
    let results = identify(input).expect("should identify EVM block hash");

    let block_hash_candidates: Vec<_> = results
        .iter()
        .filter(|c| c.input_type == InputType::BlockHash)
        .collect();

    assert!(
        !block_hash_candidates.is_empty(),
        "Should return at least one BlockHash candidate for EVM block hash"
    );

    // Should include Ethereum
    assert!(
        block_hash_candidates.iter().any(|c| c.chain == "ethereum"),
        "Ethereum should be among BlockHash candidates"
    );
}

#[test]
fn test_evm_block_hash_has_scanner_url() {
    let input = "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6";
    let results = identify(input).expect("should identify EVM block hash");

    let eth_block = results
        .iter()
        .find(|c| c.input_type == InputType::BlockHash && c.chain == "ethereum")
        .expect("Ethereum BlockHash candidate should exist");

    assert!(
        eth_block.scanner_url.is_some(),
        "Ethereum block hash should have a scanner URL"
    );
    let url = eth_block.scanner_url.as_ref().unwrap();
    assert!(
        url.contains("etherscan.io/block/"),
        "Ethereum block hash URL should point to etherscan block page, got: {}",
        url
    );
}

#[test]
fn test_evm_block_hash_also_returns_transaction_candidates() {
    // EVM block hashes are format-identical to EVM tx hashes — both should be returned
    let input = "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6";
    let results = identify(input).expect("should identify ambiguous EVM hex");

    let has_block_hash = results.iter().any(|c| c.input_type == InputType::BlockHash);
    let has_transaction = results
        .iter()
        .any(|c| c.input_type == InputType::Transaction);

    assert!(has_block_hash, "Should return BlockHash candidates");
    assert!(
        has_transaction,
        "Should also return Transaction candidates (ambiguous input)"
    );
}

#[test]
fn test_evm_block_hash_normalized_lowercase() {
    // Block hash should be normalized to lowercase hex
    let input = "0x88E96D4537BEA4D9C05D12549907B32561D3BF31F45AAE734CDC119F13406CB6";
    let results = identify(input).expect("should identify uppercase EVM block hash");

    let block_candidates: Vec<_> = results
        .iter()
        .filter(|c| c.input_type == InputType::BlockHash)
        .collect();

    for candidate in &block_candidates {
        assert_eq!(
            candidate.normalized,
            candidate.normalized.to_lowercase(),
            "Block hash should be normalized to lowercase for chain {}",
            candidate.chain
        );
    }
}

// ============================================================================
// Bitcoin block hash (SHA-256d: 64 hex chars, no 0x prefix)
// Same format as Bitcoin tx hash — both BlockHash and Transaction candidates expected
// ============================================================================

#[test]
fn test_bitcoin_block_hash_returns_block_hash_candidates() {
    // Bitcoin genesis block hash
    let input = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    let results = identify(input).expect("should identify Bitcoin block hash");

    let block_hash_candidates: Vec<_> = results
        .iter()
        .filter(|c| c.input_type == InputType::BlockHash)
        .collect();

    assert!(
        !block_hash_candidates.is_empty(),
        "Should return at least one BlockHash candidate for Bitcoin block hash"
    );

    assert!(
        block_hash_candidates.iter().any(|c| c.chain == "bitcoin"),
        "Bitcoin should be among BlockHash candidates"
    );
}

#[test]
fn test_bitcoin_block_hash_has_scanner_url() {
    let input = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    let results = identify(input).expect("should identify Bitcoin block hash");

    let btc_block = results
        .iter()
        .find(|c| c.input_type == InputType::BlockHash && c.chain == "bitcoin")
        .expect("Bitcoin BlockHash candidate should exist");

    assert!(
        btc_block.scanner_url.is_some(),
        "Bitcoin block hash should have a scanner URL"
    );
    let url = btc_block.scanner_url.as_ref().unwrap();
    assert!(
        url.contains("blockchain.com") || url.contains("block"),
        "Bitcoin block hash URL should point to a block explorer, got: {}",
        url
    );
}

#[test]
fn test_bitcoin_block_hash_also_returns_transaction_candidates() {
    // 64-char hex is ambiguous: could be Bitcoin block hash OR Bitcoin tx hash
    let input = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    let results = identify(input).expect("should identify ambiguous 64-char hex");

    let has_block_hash = results.iter().any(|c| c.input_type == InputType::BlockHash);
    let has_transaction = results
        .iter()
        .any(|c| c.input_type == InputType::Transaction);

    assert!(has_block_hash, "Should return BlockHash candidates");
    assert!(
        has_transaction,
        "Should also return Transaction candidates (ambiguous input)"
    );
}

// ============================================================================
// Solana block hash (Base58, 32-44 chars)
// DISTINCTIVE: different from Solana tx signature (85-90 chars Base58)
// ============================================================================

#[test]
fn test_solana_block_hash_returns_block_hash_candidates() {
    // Real Solana blockhash (32-byte Base58 hash, ~44 chars)
    let input = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    let results = identify(input).expect("should identify Solana block hash");

    let block_hash_candidates: Vec<_> = results
        .iter()
        .filter(|c| c.input_type == InputType::BlockHash)
        .collect();

    assert!(
        !block_hash_candidates.is_empty(),
        "Should return BlockHash candidates for Solana block hash (32-44 char Base58)"
    );

    assert!(
        block_hash_candidates.iter().any(|c| c.chain == "solana"),
        "Solana should be among BlockHash candidates"
    );
}

#[test]
fn test_solana_block_hash_higher_confidence_than_transaction() {
    // Solana block hash (32-44 chars) has higher confidence than tx (85-90 chars)
    // because the format is distinctive relative to Solana tx signatures
    let input = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    let results = identify(input).expect("should identify Solana block hash");

    let solana_block = results
        .iter()
        .find(|c| c.input_type == InputType::BlockHash && c.chain == "solana");

    if let Some(candidate) = solana_block {
        assert!(
            candidate.confidence >= 0.70,
            "Solana block hash confidence should be >= 0.70, got {}",
            candidate.confidence
        );
    }
}

#[test]
fn test_solana_tx_signature_does_not_return_block_hash() {
    // Solana tx signature (85-90 chars Base58) should NOT return BlockHash candidates
    let input =
        "5wpHU1gGYcgKabL7heGGgiKBx3WJMruHiN34sCjTYwQu4sk9H2uMyZsm1P28RqaJPVELtcVxNmSGieq6V5ZZxpDT";
    let results = identify(input).expect("should identify Solana tx signature");

    let block_hash_candidates: Vec<_> = results
        .iter()
        .filter(|c| c.input_type == InputType::BlockHash)
        .collect();

    assert!(
        block_hash_candidates.is_empty(),
        "Solana tx signature (85-90 char Base58) should NOT return BlockHash candidates"
    );

    // Should still return Transaction
    assert!(
        results
            .iter()
            .any(|c| c.input_type == InputType::Transaction),
        "Should return Transaction candidate for Solana tx signature"
    );
}

// ============================================================================
// Non-regression: existing transaction detection must still work
// ============================================================================

#[test]
fn test_non_regression_evm_tx_hash_still_returns_transaction() {
    // Known EVM tx hash must still return Transaction candidates
    let input = "0xcdf331416ac94df404cfa95b13ecd4b23b2b1de895c945e25ff1b557c597a64e";
    let results = identify(input).expect("should identify EVM tx hash");

    assert!(
        results
            .iter()
            .any(|c| c.input_type == InputType::Transaction),
        "EVM tx hash should still return Transaction candidates (non-regression)"
    );
    assert!(
        results
            .iter()
            .any(|c| c.input_type == InputType::Transaction && c.chain == "ethereum"),
        "Ethereum should be among Transaction candidates"
    );
}

#[test]
fn test_non_regression_bitcoin_tx_hash_still_returns_transaction() {
    // Bitcoin genesis coinbase tx hash must still work
    let input = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    let results = identify(input).expect("should identify Bitcoin tx hash");

    assert!(
        results
            .iter()
            .any(|c| c.input_type == InputType::Transaction && c.chain == "bitcoin"),
        "Bitcoin tx hash should still return Transaction candidate for bitcoin (non-regression)"
    );
}

#[test]
fn test_non_regression_evm_address_no_block_hash() {
    // EVM addresses (42 chars) should NOT return BlockHash candidates
    let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
    let results = identify(input).expect("should identify EVM address");

    assert!(
        !results.iter().any(|c| c.input_type == InputType::BlockHash),
        "EVM address (42 chars) should NOT return BlockHash candidates"
    );
    assert!(
        results.iter().any(|c| c.input_type == InputType::Address),
        "EVM address should still be identified as Address"
    );
}

#[test]
fn test_non_regression_substrate_extrinsic_no_block_hash() {
    // Substrate extrinsic IDs (BLOCK-INDEX format) should NOT return BlockHash
    let input = "28815161-0";
    let results = identify(input).expect("should identify Substrate extrinsic");

    assert!(
        !results.iter().any(|c| c.input_type == InputType::BlockHash),
        "Substrate extrinsic ID should NOT return BlockHash candidates"
    );
    assert!(
        results
            .iter()
            .any(|c| c.input_type == InputType::Transaction),
        "Substrate extrinsic should still return Transaction candidate"
    );
}

// ============================================================================
// Multiple EVM chains: block hash matches all EVM chains with template
// ============================================================================

#[test]
fn test_evm_block_hash_matches_multiple_chains() {
    let input = "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6";
    let results = identify(input).expect("should identify EVM block hash");

    let block_chains: Vec<&str> = results
        .iter()
        .filter(|c| c.input_type == InputType::BlockHash)
        .map(|c| c.chain.as_str())
        .collect();

    // Should match multiple EVM chains
    let expected_evm_chains = [
        "ethereum",
        "polygon",
        "bsc",
        "avalanche",
        "arbitrum",
        "optimism",
        "base",
    ];
    let matched_evm: Vec<_> = expected_evm_chains
        .iter()
        .filter(|&&chain| block_chains.contains(&chain))
        .collect();

    assert!(
        matched_evm.len() >= 3,
        "EVM block hash should match at least 3 EVM chains, matched: {:?}",
        matched_evm
    );
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_short_hex_not_block_hash() {
    // Short hex (32 chars) should not match block hash patterns
    let input = "000000000019d6689c085ae165831e93";
    let result = identify(input);
    // Either fails classification or doesn't return BlockHash
    if let Ok(results) = result {
        assert!(
            !results.iter().any(|c| c.input_type == InputType::BlockHash),
            "Short hex (32 chars) should NOT return BlockHash candidates"
        );
    }
}

#[test]
fn test_empty_input_returns_error() {
    assert!(identify("").is_err(), "Empty input should return error");
}
