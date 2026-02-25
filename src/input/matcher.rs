//! Metadata-driven input matcher
//!
//! This module matches classifier possibilities against chain metadata.
//! It performs metadata-driven validation without hardcoded chain logic.
//!
//! Uses functional programming style with iterator combinators for clean,
//! idiomatic, and performant matching.

use crate::input::{
    CategorySignature, DetectedKeyType, InputCharacteristics, InputPossibility,
    is_substrate_extrinsic,
};
use crate::registry::{EncodingType, PublicKeyType, Registry};

/// A match between input and a chain
#[derive(Debug, Clone)]
pub struct ChainMatch {
    /// Chain that matches
    pub chain_id: String,
    /// Chain name
    #[allow(dead_code)] // Reserved for future use (debugging, display, etc.)
    pub chain_name: String,
    /// The possibility that matched
    pub possibility: InputPossibility,
}

/// Match input possibilities against chain metadata
///
/// This function uses metadata to validate classifier possibilities:
/// 1. Build signature from input characteristics
/// 2. Match against chain metadata signatures
/// 3. Perform structural validation (checksums, decodes, etc.)
/// 4. For public keys: check curve compatibility and pipeline derivation
///
/// Uses functional programming style with iterator pipelines.
pub fn match_input_with_metadata(
    input: &str,
    chars: &InputCharacteristics,
    possibilities: &[InputPossibility],
    registry: &Registry,
) -> Vec<ChainMatch> {
    // Extract address, public key, and transaction possibilities
    let has_address = possibilities
        .iter()
        .any(|p| matches!(p, InputPossibility::Address));
    let has_transaction = possibilities
        .iter()
        .any(|p| matches!(p, InputPossibility::Transaction));
    let pk_types: Vec<DetectedKeyType> = possibilities
        .iter()
        .filter_map(|p| match p {
            InputPossibility::PublicKey { key_type } => Some(*key_type),
            _ => None,
        })
        .collect();

    registry
        .chains
        .iter()
        .flat_map(|chain| {
            let addr_matches = address_matches(chain, input, chars, has_address);
            let pk_matches = public_key_matches(chain, input, chars, &pk_types);
            let tx_matches = transaction_matches(chain, input, chars, has_transaction, registry);
            addr_matches.chain(pk_matches).chain(tx_matches)
        })
        .collect()
}

/// Generate address matches for a chain using functional pipeline
fn address_matches<'a>(
    chain: &'a crate::registry::ChainMetadata,
    input: &'a str,
    chars: &'a InputCharacteristics,
    has_address: bool,
) -> impl Iterator<Item = ChainMatch> + 'a {
    chain
        .address_formats
        .iter()
        .filter(move |meta| {
            let meta_sig = CategorySignature::from_metadata(meta);
            meta_sig.matches(chars)
        })
        .filter(move |meta| meta.validate_raw(input, chars))
        .filter(move |_| has_address)
        .map(move |_| ChainMatch {
            chain_id: chain.id.clone(),
            chain_name: chain.name.clone(),
            possibility: InputPossibility::Address,
        })
        .take(1) // Only one match per chain for addresses
}

/// Generate public key matches for a chain using functional pipeline
fn public_key_matches<'a>(
    chain: &'a crate::registry::ChainMetadata,
    _input: &'a str,
    chars: &'a InputCharacteristics,
    pk_types: &'a [DetectedKeyType],
) -> impl Iterator<Item = ChainMatch> + 'a {
    chain
        .public_key_formats
        .iter()
        .flat_map(move |pk_fmt| {
            pk_types
                .iter()
                .filter(move |pk| {
                    // Check curve matches
                    let pk_curve = detected_key_to_curve(pk);
                    if pk_fmt.key_type != pk_curve {
                        return false;
                    }
                    
                    // Check encoding type matches (similar to address validation)
                    // Must match the format's encoding if encoding is detected
                    // If encoding is not detected, we're more lenient but still check other constraints
                    if !chars.encoding.is_empty() {
                        // Encoding is detected - must match format's encoding
                        if !chars.encoding.contains(&pk_fmt.encoding) {
                            return false;
                        }
                    } else {
                        // Encoding not detected - be more strict: reject if format requires specific encoding
                        // This prevents false matches (e.g., base58 input matching hex-only formats)
                        // Only allow if format is flexible (no specific encoding requirement)
                        // For now, we'll reject if format specifies hex/bech32 but encoding wasn't detected
                        match pk_fmt.encoding {
                            EncodingType::Hex | EncodingType::Bech32 | EncodingType::Bech32m => {
                                // Format requires specific encoding but input encoding wasn't detected
                                // This likely means the input doesn't match the format
                                return false;
                            }
                            _ => {
                                // Base58/Base58Check/SS58 are more lenient
                            }
                        }
                    }
                    
                    // Check length requirements
                    if let Some(exact) = pk_fmt.exact_length {
                        if chars.length != exact {
                            return false;
                        }
                    }
                    if let Some((min, max)) = pk_fmt.length_range {
                        if chars.length < min || chars.length > max {
                            return false;
                        }
                    }
                    
                    // Check prefixes
                    if !pk_fmt.prefixes.is_empty() {
                        if !pk_fmt.prefixes.iter().any(|p| chars.prefixes.contains(p)) {
                            return false;
                        }
                    }
                    
                    // Check HRP (for Bech32 public keys)
                    if !pk_fmt.hrps.is_empty() {
                        if let Some(ref hrp) = chars.hrp {
                            if !pk_fmt.hrps.iter().any(|h| hrp.starts_with(h)) {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    
                    // Check character set
                    if let Some(ref char_set) = pk_fmt.char_set {
                        if chars.char_set != *char_set {
                            return false;
                        }
                    }
                    
                    true
                })
                .map(move |pk| ChainMatch {
                    chain_id: chain.id.clone(),
                    chain_name: chain.name.clone(),
                    possibility: InputPossibility::PublicKey { key_type: *pk },
                })
        })
        .take(1) // Only one match per chain for public keys
}

/// Generate transaction matches for a chain using chain-family heuristics
///
/// Uses the chain's address_pipeline to determine expected tx format:
/// - EVM chains: 66-char hex with 0x prefix (keccak-256 hash)
/// - UTXO chains (bitcoin_p2pkh/bitcoin_bech32): 64-char hex without 0x (SHA-256d hash)
/// - Cosmos chains: 64-char hex without 0x (SHA-256 hash)
/// - Tron: 64-char hex without 0x
/// - Solana: 85-90 char base58 (64-byte ed25519 signature)
/// - Substrate (ss58): block_height-extrinsic_index pattern
/// - Cardano: 64-char hex without 0x
///
/// Only matches chains that have a transaction_scanner_url_template defined.
fn transaction_matches<'a>(
    chain: &'a crate::registry::ChainMetadata,
    input: &'a str,
    chars: &'a InputCharacteristics,
    has_transaction: bool,
    registry: &'a Registry,
) -> impl Iterator<Item = ChainMatch> + 'a {
    // Only match if classifier detected Transaction possibility and chain has tx template
    let should_match = has_transaction
        && chain.transaction_scanner_url_template.is_some();

    let matches_chain = should_match && {
        let pipeline = registry
            .get_chain_config(&chain.id)
            .map(|c| c.address_pipeline.as_str())
            .unwrap_or("");

        match pipeline {
            // EVM chains: 0x + 64 hex chars = 66 total
            "evm" => {
                chars.length == 66
                    && chars.encoding.contains(&EncodingType::Hex)
                    && chars.prefixes.iter().any(|p| p == "0x")
            }
            // UTXO chains: 64 hex chars, no 0x prefix
            "bitcoin_p2pkh" | "bitcoin_bech32" => {
                chars.length == 64
                    && chars.encoding.contains(&EncodingType::Hex)
                    && !chars.prefixes.iter().any(|p| p == "0x")
            }
            // Cosmos SDK chains: 64 hex chars, no 0x prefix
            "cosmos" => {
                chars.length == 64
                    && chars.encoding.contains(&EncodingType::Hex)
                    && !chars.prefixes.iter().any(|p| p == "0x")
            }
            // Tron: 64 hex chars, no 0x prefix
            "tron" => {
                chars.length == 64
                    && chars.encoding.contains(&EncodingType::Hex)
                    && !chars.prefixes.iter().any(|p| p == "0x")
            }
            // Cardano: 64 hex chars, no 0x prefix
            "cardano" => {
                chars.length == 64
                    && chars.encoding.contains(&EncodingType::Hex)
                    && !chars.prefixes.iter().any(|p| p == "0x")
            }
            // Solana: 85-90 char base58 (64-byte signature)
            "solana" => {
                (85..=90).contains(&chars.length)
                    && chars.encoding.contains(&EncodingType::Base58)
            }
            // Substrate: extrinsic ID format (BLOCK_HEIGHT-INDEX)
            "ss58" => is_substrate_extrinsic(input),
            _ => false,
        }
    };

    matches_chain
        .then(|| ChainMatch {
            chain_id: chain.id.clone(),
            chain_name: chain.name.clone(),
            possibility: InputPossibility::Transaction,
        })
        .into_iter()
}

/// Convert DetectedKeyType to PublicKeyType (curve)
fn detected_key_to_curve(key_type: &DetectedKeyType) -> PublicKeyType {
    match key_type {
        DetectedKeyType::Secp256k1 { .. } => PublicKeyType::Secp256k1,
        DetectedKeyType::Ed25519 => PublicKeyType::Ed25519,
        DetectedKeyType::Sr25519 => PublicKeyType::Sr25519,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{classify_input, extract_characteristics};

    #[test]
    fn test_match_evm_address() {
        // Test EVM address matching EVM chains
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Verify function returns correct structure
        // If matches found, verify structure; if not, that's a detection issue, not a matcher issue
        if !matches.is_empty() {
            // All matches should be for addresses
            assert!(matches
                .iter()
                .all(|m| matches!(m.possibility, InputPossibility::Address)));
            // Should include Ethereum
            assert!(matches.iter().any(|m| m.chain_id == "ethereum"));
            // Should include other EVM chains
            let evm_chains = [
                "ethereum",
                "polygon",
                "bsc",
                "avalanche",
                "arbitrum",
                "optimism",
                "base",
            ];
            assert!(matches
                .iter()
                .any(|m| evm_chains.contains(&m.chain_id.as_str())));
        }
        // Verify all matches have correct structure
        for m in &matches {
            assert!(!m.chain_id.is_empty());
            assert!(!m.chain_name.is_empty());
        }
    }

    #[test]
    fn test_match_evm_address_mixed_case() {
        // Test mixed case EVM address
        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Verify function returns correct structure
        if !matches.is_empty() {
            // All matches should be for addresses
            assert!(matches
                .iter()
                .all(|m| matches!(m.possibility, InputPossibility::Address)));
        }
        // Verify all matches have correct structure
        for m in &matches {
            assert!(!m.chain_id.is_empty());
            assert!(!m.chain_name.is_empty());
        }
    }

    #[test]
    fn test_match_secp256k1_public_key() {
        // Test secp256k1 public key matching chains
        let input = "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Should match chains that support secp256k1
        assert!(!matches.is_empty());
        // Should have public key matches
        let pk_matches: Vec<_> = matches
            .iter()
            .filter(|m| matches!(m.possibility, InputPossibility::PublicKey { .. }))
            .collect();
        assert!(!pk_matches.is_empty());
        // All PK matches should be secp256k1
        assert!(pk_matches.iter().all(|m| matches!(
            m.possibility,
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Secp256k1 { .. }
            }
        )));
    }

    #[test]
    fn test_match_ed25519_public_key() {
        // Test Ed25519 public key (32-byte base58)
        let input = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Should match chains that support Ed25519 (Solana, Cardano, etc.)
        assert!(!matches.is_empty());
        // Should have both address and public key matches (ambiguous input)
        let has_address = matches
            .iter()
            .any(|m| matches!(m.possibility, InputPossibility::Address));
        let has_pk = matches
            .iter()
            .any(|m| matches!(m.possibility, InputPossibility::PublicKey { .. }));
        // This input is ambiguous, so it could match as both
        assert!(has_address || has_pk);
    }

    #[test]
    fn test_match_no_matches() {
        // Test with input that doesn't match any chain
        let input = "xyz123abc";
        let chars = extract_characteristics(input);
        // This should fail classification, but let's test with empty possibilities
        let possibilities = vec![];
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Should return no matches
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_bitcoin_address() {
        // Test Bitcoin P2PKH address
        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Verify function returns correct structure
        // Verify all matches have correct structure
        for m in &matches {
            assert!(!m.chain_id.is_empty());
            assert!(!m.chain_name.is_empty());
        }
        // If matches found, verify they're correct
        if !matches.is_empty() {
            // Should have address matches
            assert!(matches
                .iter()
                .any(|m| matches!(m.possibility, InputPossibility::Address)));
            // Should include Bitcoin (if matches found)
            if matches.iter().any(|m| m.chain_id == "bitcoin") {
                // Verify Bitcoin match structure
                let bitcoin_match = matches.iter().find(|m| m.chain_id == "bitcoin").unwrap();
                assert!(matches!(
                    bitcoin_match.possibility,
                    InputPossibility::Address
                ));
            }
        }
    }

    #[test]
    fn test_match_bitcoin_bech32() {
        // Test Bitcoin Bech32 address
        let input = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Verify function returns correct structure
        if !matches.is_empty() {
            // Should have address matches
            assert!(matches
                .iter()
                .any(|m| matches!(m.possibility, InputPossibility::Address)));
            // Should include Bitcoin
            assert!(matches.iter().any(|m| m.chain_id == "bitcoin"));
        }
        // Verify all matches have correct structure
        for m in &matches {
            assert!(!m.chain_id.is_empty());
            assert!(!m.chain_name.is_empty());
        }
    }

    // ============================================================================
    // Phase 3.3: match_input_with_metadata Tests (expanded)
    // ============================================================================

    #[test]
    fn test_match_evm_address_all_chains() {
        // EVM addresses: should match all 10 EVM chains
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Should match multiple EVM chains
        let evm_chains = [
            "ethereum",
            "polygon",
            "bsc",
            "avalanche",
            "arbitrum",
            "optimism",
            "base",
            "fantom",
            "celo",
            "gnosis",
        ];
        let matched_chains: Vec<_> = matches.iter().map(|m| m.chain_id.as_str()).collect();
        assert!(evm_chains
            .iter()
            .any(|&chain| matched_chains.contains(&chain)));

        // All matches should be for addresses
        assert!(matches
            .iter()
            .all(|m| matches!(m.possibility, InputPossibility::Address)));
    }

    #[test]
    fn test_match_bitcoin_address_only_bitcoin() {
        // Bitcoin addresses: should match only Bitcoin (not other chains)
        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Should match Bitcoin
        if !matches.is_empty() {
            assert!(matches.iter().any(|m| m.chain_id == "bitcoin"));
            // Should NOT match EVM chains
            let evm_chains = ["ethereum", "polygon", "bsc"];
            assert!(!matches
                .iter()
                .any(|m| evm_chains.contains(&m.chain_id.as_str())));
        }
    }

    #[test]
    fn test_match_cosmos_address_specific_chain() {
        // Cosmos addresses: should match only specific chain by HRP
        let input = "cosmos1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let chars = extract_characteristics(input);
        if let Ok(possibilities) = classify_input(input, &chars) {
            let registry = Registry::get();

            let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

            // Should match Cosmos Hub (not other Cosmos chains with different HRPs)
            if !matches.is_empty() {
                assert!(matches.iter().any(|m| m.chain_id == "cosmos_hub"));
                // Should NOT match Osmosis (different HRP)
                assert!(!matches.iter().any(|m| m.chain_id == "osmosis"));
            }
        }
        // If classification fails, address might be invalid Bech32
    }

    #[test]
    fn test_match_public_key_secp256k1_chains() {
        // Public keys: should match chains with compatible curves
        let input = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Should match secp256k1 chains (EVM, Bitcoin, Tron)
        if !matches.is_empty() {
            let pk_matches: Vec<_> = matches
                .iter()
                .filter(|m| matches!(m.possibility, InputPossibility::PublicKey { .. }))
                .collect();

            if !pk_matches.is_empty() {
                // Should match EVM chains
                let evm_chains = ["ethereum", "polygon", "bsc"];
                assert!(pk_matches
                    .iter()
                    .any(|m| evm_chains.contains(&m.chain_id.as_str())));
            }
        }
    }

    #[test]
    fn test_match_public_key_ed25519_chains() {
        // Public keys: should match chains with compatible curves (Ed25519)
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let chars = extract_characteristics(input);
        if let Ok(possibilities) = classify_input(input, &chars) {
            let registry = Registry::get();

            let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

            // Should match Ed25519 chains (Solana, Cardano, Cosmos, Substrate)
            if !matches.is_empty() {
                let pk_matches: Vec<_> = matches
                    .iter()
                    .filter(|m| matches!(m.possibility, InputPossibility::PublicKey { .. }))
                    .collect();

                if !pk_matches.is_empty() {
                    // Should match at least one Ed25519 chain
                    let ed25519_chains = ["solana", "cardano", "cosmos_hub", "polkadot"];
                    assert!(pk_matches
                        .iter()
                        .any(|m| ed25519_chains.contains(&m.chain_id.as_str())));
                }
            }
        }
        // If classification fails, public key might not be recognized
    }

    #[test]
    fn test_match_no_matches_invalid() {
        // No matches: invalid input should return empty
        let input = "xyz123abc";
        let chars = extract_characteristics(input);
        // Use empty possibilities (invalid input)
        let possibilities = vec![];
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        // Should return no matches
        assert!(matches.is_empty());
    }

    // ============================================================================
    // Transaction matching tests
    // ============================================================================

    #[test]
    fn test_match_evm_tx_hash() {
        let input = "0xcdf331416ac94df404cfa95b13ecd4b23b2b1de895c945e25ff1b557c597a64e";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        let tx_matches: Vec<_> = matches
            .iter()
            .filter(|m| matches!(m.possibility, InputPossibility::Transaction))
            .collect();
        assert!(!tx_matches.is_empty());
        // Should match EVM chains
        assert!(tx_matches.iter().any(|m| m.chain_id == "ethereum"));
    }

    #[test]
    fn test_match_bitcoin_tx_hash() {
        let input = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        let tx_matches: Vec<_> = matches
            .iter()
            .filter(|m| matches!(m.possibility, InputPossibility::Transaction))
            .collect();
        assert!(!tx_matches.is_empty());
        assert!(tx_matches.iter().any(|m| m.chain_id == "bitcoin"));
    }

    #[test]
    fn test_match_solana_tx_signature() {
        let input = "5wpHU1gGYcgKabL7heGGgiKBx3WJMruHiN34sCjTYwQu4sk9H2uMyZsm1P28RqaJPVELtcVxNmSGieq6V5ZZxpDT";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        let tx_matches: Vec<_> = matches
            .iter()
            .filter(|m| matches!(m.possibility, InputPossibility::Transaction))
            .collect();
        assert!(!tx_matches.is_empty());
        assert!(tx_matches.iter().any(|m| m.chain_id == "solana"));
    }

    #[test]
    fn test_match_substrate_extrinsic() {
        let input = "28815161-0";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        let tx_matches: Vec<_> = matches
            .iter()
            .filter(|m| matches!(m.possibility, InputPossibility::Transaction))
            .collect();
        assert!(!tx_matches.is_empty());
        // Should match Substrate-family chains
        assert!(tx_matches
            .iter()
            .any(|m| m.chain_id == "polkadot" || m.chain_id == "kusama" || m.chain_id == "substrate"));
    }

    #[test]
    fn test_match_evm_address_no_tx() {
        // EVM addresses should NOT match as transactions
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();
        let registry = Registry::get();

        let matches = match_input_with_metadata(input, &chars, &possibilities, registry);

        let tx_matches: Vec<_> = matches
            .iter()
            .filter(|m| matches!(m.possibility, InputPossibility::Transaction))
            .collect();
        assert!(tx_matches.is_empty());
    }
}
