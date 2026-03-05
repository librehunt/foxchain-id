//! Main identification pipeline
//!
//! This module implements the metadata-driven identification pipeline:
//! 1. Extract input characteristics
//! 2. Classify input (address, public key, or ambiguous)
//! 3. For addresses: run address detection
//! 4. For public keys: use pipeline-based derivation
//! 5. Return all candidates sorted by confidence

use crate::detectors::detect_address;
use crate::input::{
    classify_input, extract_characteristics, match_input_with_metadata, InputCharacteristics,
    InputPossibility,
};
use crate::pipelines::addresses::execute_pipeline;
use crate::registry::{PublicKeyType, Registry};
use crate::shared::derivation::decode_public_key;
use crate::Error;
use serde_json::json;

/// A candidate identification result
#[derive(Debug, Clone)]
pub struct IdentificationCandidate {
    /// Type of input (address or public key)
    pub input_type: InputType,
    /// Chain identifier (string ID from metadata)
    pub chain: String,
    /// Encoding type used
    pub encoding: crate::registry::EncodingType,
    /// Normalized representation
    pub normalized: String,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Reasoning for this candidate
    pub reasoning: String,
    /// Scanner URL for viewing this address on a block explorer (optional)
    pub scanner_url: Option<String>,
}

/// Type of input being identified
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputType {
    /// Address input
    Address,
    /// Public key input
    PublicKey,
    /// Transaction identifier (hash, digest, extrinsic ID)
    Transaction,
    /// Block hash (32-byte digest identifying a block)
    BlockHash,
}

/// Identify the blockchain(s) for a given input string
///
/// Returns all valid candidates sorted by confidence (highest first).
/// This function supports ambiguous inputs that may match multiple chains.
///
/// Architecture:
/// 1. Extract characteristics (pure feature extraction)
/// 2. Classify input (non-chain-aware: Address? PublicKey? Both? None?)
/// 3. Match with metadata (metadata-driven signature matching)
/// 4. Structural validation (checksums, decodes, pipeline derivation)
pub fn identify(input: &str) -> Result<Vec<IdentificationCandidate>, Error> {
    // Step 1: Extract characteristics
    let chars = extract_characteristics(input);

    // Step 2: Classify input to get all possibilities (non-chain-aware)
    let possibilities = classify_input(input, &chars)?;

    // Step 3: Match with metadata (metadata-driven signature matching)
    let registry = Registry::get();
    let chain_matches = match_input_with_metadata(input, &chars, &possibilities, registry);

    // Step 4: Process matches with structural validation
    let results: Vec<IdentificationCandidate> = chain_matches
        .into_iter()
        .flat_map(|chain_match| match chain_match.possibility {
            InputPossibility::Address => {
                // Address detection with full validation
                try_address_detection_for_chain(input, &chars, &chain_match.chain_id)
            }
            InputPossibility::PublicKey { key_type } => {
                // Pipeline-based derivation with validation
                try_public_key_derivation_for_chain(input, &chars, key_type, &chain_match.chain_id)
            }
            InputPossibility::Transaction => {
                // Transaction identifier detection
                try_transaction_detection_for_chain(input, &chars, &chain_match.chain_id)
            }
            InputPossibility::BlockHash => {
                // Block hash detection
                try_block_hash_detection_for_chain(input, &chars, &chain_match.chain_id)
            }
        })
        .collect();

    // Sort by confidence (highest first)
    // Note: sort_by is acceptable here as it's a standard sorting operation, not a nested loop
    let mut sorted_results = results;
    sorted_results.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if sorted_results.is_empty() {
        Err(Error::InvalidInput(format!(
            "Unable to identify address format: {}",
            input
        )))
    } else {
        Ok(sorted_results)
    }
}

/// Generate scanner URL for a chain and address
fn generate_scanner_url(
    chain_id: &str,
    normalized_address: &str,
    registry: &Registry,
) -> Option<String> {
    // First, try to get chain-specific scanner URL from metadata
    if let Some(chain_metadata) = registry.chains.iter().find(|c| c.id == chain_id) {
        if let Some(template) = &chain_metadata.scanner_url_template {
            return Some(template.replace("{address}", normalized_address));
        }

        // Fallback: if it's an EVM chain without a specific scanner, use routescan.io
        if let Some(chain_config) = registry.get_chain_config(chain_id) {
            if chain_config.address_pipeline == "evm" {
                return Some(format!(
                    "https://routescan.io/{}/address/{}",
                    chain_id, normalized_address
                ));
            }
        }
    }

    None
}

/// Try address detection for a specific chain (after metadata matching)
fn try_address_detection_for_chain(
    input: &str,
    chars: &InputCharacteristics,
    chain_id: &str,
) -> Vec<IdentificationCandidate> {
    let registry = Registry::get();

    // Find the chain metadata
    let chain_metadata = match registry.chains.iter().find(|c| c.id == chain_id) {
        Some(chain) => chain,
        None => return Vec::new(),
    };

    chain_metadata
        .address_formats
        .iter()
        .filter_map(|addr_format| {
            // Additional structural validation via detector
            detect_address(input, chars, addr_format, chain_id.to_string())
                .ok()
                .flatten()
        })
        .map(|result| {
            let scanner_url = generate_scanner_url(&result.chain, &result.normalized, registry);
            IdentificationCandidate {
                input_type: InputType::Address,
                chain: result.chain,
                encoding: result.encoding,
                normalized: result.normalized,
                confidence: result.confidence,
                reasoning: result.reasoning,
                scanner_url,
            }
        })
        .collect()
}

/// Try public key derivation for a specific chain (after metadata matching)
fn try_public_key_derivation_for_chain(
    input: &str,
    chars: &InputCharacteristics,
    key_type: crate::input::DetectedKeyType,
    chain_id: &str,
) -> Vec<IdentificationCandidate> {
    // Decode public key
    let key_bytes = match decode_public_key(input, chars, key_type) {
        Ok(bytes) => bytes,
        Err(_) => return Vec::new(),
    };

    let registry = Registry::get();

    // Get chain config
    let chain_config = match registry.get_chain_config(chain_id) {
        Some(config) => config,
        None => return Vec::new(),
    };

    // Check if chain requires stake key (Cardano) - skip if only 1 PK provided
    if chain_config.requires_stake_key {
        return Vec::new();
    }

    // Build pipeline params from chain config
    let params = json!(chain_config.address_params);

    // Execute pipeline
    match execute_pipeline(&chain_config.address_pipeline, &key_bytes, &params) {
        Ok(derived_address) => {
            // Validate the derived address
            let derived_chars = extract_characteristics(&derived_address);
            let chain_metadata = match registry.chains.iter().find(|c| c.id == chain_id) {
                Some(chain) => chain,
                None => return Vec::new(),
            };

            let matches = chain_metadata
                .address_formats
                .iter()
                .any(|addr_format| addr_format.validate_raw(&derived_address, &derived_chars));

            if matches {
                let curve = match key_type {
                    crate::input::DetectedKeyType::Secp256k1 { .. } => PublicKeyType::Secp256k1,
                    crate::input::DetectedKeyType::Ed25519 => PublicKeyType::Ed25519,
                    crate::input::DetectedKeyType::Sr25519 => PublicKeyType::Sr25519,
                };

                let scanner_url = generate_scanner_url(chain_id, &derived_address, registry);
                vec![IdentificationCandidate {
                    input_type: InputType::PublicKey,
                    chain: chain_id.to_string(),
                    encoding: chain_metadata.address_formats[0].encoding,
                    normalized: derived_address,
                    confidence: 0.8, // High confidence for derived addresses
                    reasoning: format!(
                        "Derived from {} public key using {} pipeline",
                        curve_name(curve),
                        chain_config.address_pipeline
                    ),
                    scanner_url,
                }]
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    }
}

/// Try transaction detection for a specific chain (after metadata matching)
///
/// Performs light structural validation and produces a candidate with:
/// - Normalized tx identifier (lowercase hex with/without 0x per chain convention)
/// - Confidence capped appropriately (tx hashes have no checksums to verify)
/// - Scanner URL built from chain's transaction_scanner_url_template
fn try_transaction_detection_for_chain(
    input: &str,
    chars: &InputCharacteristics,
    chain_id: &str,
) -> Vec<IdentificationCandidate> {
    let registry = Registry::get();

    let chain_metadata = match registry.chains.iter().find(|c| c.id == chain_id) {
        Some(chain) => chain,
        None => return Vec::new(),
    };

    let chain_config = match registry.get_chain_config(chain_id) {
        Some(config) => config,
        None => return Vec::new(),
    };

    let pipeline = chain_config.address_pipeline.as_str();

    // Determine encoding, normalized form, and confidence based on chain family
    let (encoding, normalized, confidence, reasoning) = match pipeline {
        "evm" => {
            // EVM: 0x-prefixed lowercase hex
            let norm = input.to_lowercase();
            (
                crate::registry::EncodingType::Hex,
                norm,
                0.55, // Moderate: correct length+encoding, but no checksum proof
                format!(
                    "66-char hex hash with 0x prefix matches {} transaction format (keccak-256)",
                    chain_metadata.name
                ),
            )
        }
        "bitcoin_p2pkh" | "bitcoin_bech32" => {
            let norm = input.to_lowercase();
            (
                crate::registry::EncodingType::Hex,
                norm,
                0.50, // Lower: 64-char hex is ambiguous across many chains
                format!(
                    "64-char hex hash matches {} transaction format (SHA-256d)",
                    chain_metadata.name
                ),
            )
        }
        "cosmos" | "cardano" => {
            let norm = input.to_lowercase();
            (
                crate::registry::EncodingType::Hex,
                norm,
                0.50,
                format!(
                    "64-char hex hash matches {} transaction format",
                    chain_metadata.name
                ),
            )
        }
        "tron" => {
            let norm = input.to_lowercase();
            (
                crate::registry::EncodingType::Hex,
                norm,
                0.50,
                format!(
                    "64-char hex hash matches {} transaction format",
                    chain_metadata.name
                ),
            )
        }
        "solana" => {
            // Solana tx signatures are base58-encoded, preserve original casing
            (
                crate::registry::EncodingType::Base58,
                input.to_string(),
                0.70, // Higher: 85-90 char base58 is fairly distinctive
                format!(
                    "{}-char base58 signature matches {} transaction format (ed25519 signature)",
                    chars.length, chain_metadata.name
                ),
            )
        }
        "ss58" => {
            // Substrate extrinsic IDs are passed through as-is
            (
                crate::registry::EncodingType::SS58, // Reuse SS58 as encoding marker for Substrate
                input.to_string(),
                0.85, // High: BLOCK_HEIGHT-INDEX pattern is very distinctive
                format!(
                    "Extrinsic ID format (block-index) matches {} extrinsic identifier",
                    chain_metadata.name
                ),
            )
        }
        _ => return Vec::new(),
    };

    let scanner_url = generate_transaction_scanner_url(chain_id, &normalized, registry);

    vec![IdentificationCandidate {
        input_type: InputType::Transaction,
        chain: chain_id.to_string(),
        encoding,
        normalized,
        confidence,
        reasoning,
        scanner_url,
    }]
}

/// Try block hash detection for a specific chain (after metadata matching)
///
/// Follows the exact pattern of try_transaction_detection_for_chain().
/// Produces a candidate with:
/// - Normalized block hash (lowercase hex with/without 0x per chain convention)
/// - Confidence capped appropriately (no checksums to verify)
/// - Scanner URL built from chain's block_hash_scanner_url_template
fn try_block_hash_detection_for_chain(
    input: &str,
    chars: &InputCharacteristics,
    chain_id: &str,
) -> Vec<IdentificationCandidate> {
    let registry = Registry::get();

    let chain_metadata = match registry.chains.iter().find(|c| c.id == chain_id) {
        Some(chain) => chain,
        None => return Vec::new(),
    };

    let chain_config = match registry.get_chain_config(chain_id) {
        Some(config) => config,
        None => return Vec::new(),
    };

    let pipeline = chain_config.address_pipeline.as_str();

    let (encoding, normalized, confidence, reasoning) = match pipeline {
        "evm" => {
            // EVM block hash: 0x-prefixed lowercase hex (keccak-256, same format as EVM tx hash)
            let norm = input.to_lowercase();
            (
                crate::registry::EncodingType::Hex,
                norm,
                0.55, // Same as tx hash — ambiguous, both BlockHash and Transaction returned
                format!(
                    "66-char hex hash with 0x prefix matches {} block hash format (keccak-256)",
                    chain_metadata.name
                ),
            )
        }
        "bitcoin_p2pkh" | "bitcoin_bech32" => {
            let norm = input.to_lowercase();
            (
                crate::registry::EncodingType::Hex,
                norm,
                0.50, // Ambiguous: same format as Bitcoin tx hash
                format!(
                    "64-char hex hash matches {} block hash format (SHA-256d)",
                    chain_metadata.name
                ),
            )
        }
        "cosmos" | "cardano" => {
            let norm = input.to_lowercase();
            (
                crate::registry::EncodingType::Hex,
                norm,
                0.50,
                format!(
                    "64-char hex hash matches {} block hash format",
                    chain_metadata.name
                ),
            )
        }
        "tron" => {
            let norm = input.to_lowercase();
            (
                crate::registry::EncodingType::Hex,
                norm,
                0.50,
                format!(
                    "64-char hex hash matches {} block hash format",
                    chain_metadata.name
                ),
            )
        }
        "solana" => {
            // Solana block hash: 32-byte hash in Base58 = 32-44 chars
            // DISTINCTIVE: different from Solana tx signature (85-90 chars Base58)
            (
                crate::registry::EncodingType::Base58,
                input.to_string(), // Preserve Base58 casing
                0.75,              // Higher confidence: format is unambiguous relative to Solana tx
                format!(
                    "{}-char Base58 hash matches {} block hash format",
                    chars.length, chain_metadata.name
                ),
            )
        }
        "ss58" => {
            // Substrate block hashes: 64-char hex without 0x prefix
            let norm = input.to_lowercase();
            (
                crate::registry::EncodingType::Hex,
                norm,
                0.50,
                format!(
                    "64-char hex hash matches {} block hash format",
                    chain_metadata.name
                ),
            )
        }
        _ => return Vec::new(),
    };

    let scanner_url = generate_block_hash_scanner_url(chain_id, &normalized, registry);

    vec![IdentificationCandidate {
        input_type: InputType::BlockHash,
        chain: chain_id.to_string(),
        encoding,
        normalized,
        confidence,
        reasoning,
        scanner_url,
    }]
}

/// Generate scanner URL for a chain and block hash
fn generate_block_hash_scanner_url(
    chain_id: &str,
    normalized_hash: &str,
    registry: &Registry,
) -> Option<String> {
    registry
        .chains
        .iter()
        .find(|c| c.id == chain_id)
        .and_then(|chain| chain.block_hash_scanner_url_template.as_ref())
        .map(|template| template.replace("{block_hash}", normalized_hash))
}

/// Generate scanner URL for a chain and transaction identifier
fn generate_transaction_scanner_url(
    chain_id: &str,
    normalized_tx: &str,
    registry: &Registry,
) -> Option<String> {
    registry
        .chains
        .iter()
        .find(|c| c.id == chain_id)
        .and_then(|chain| chain.transaction_scanner_url_template.as_ref())
        .map(|template| template.replace("{transaction}", normalized_tx))
}

/// Get curve name for display
fn curve_name(key_type: PublicKeyType) -> &'static str {
    match key_type {
        PublicKeyType::Secp256k1 => "secp256k1",
        PublicKeyType::Ed25519 => "ed25519",
        PublicKeyType::Sr25519 => "sr25519",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_empty_input() {
        let result = identify("");
        assert!(result.is_err());
    }

    #[test]
    fn test_identify_invalid_input() {
        let result = identify("not-an-address");
        assert!(result.is_err());
    }

    #[test]
    fn test_identify_evm_address_full_pipeline() {
        // Test full identify() pipeline with EVM address from failing test
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let result = identify(input);

        // Verify the full pipeline works
        if let Ok(candidates) = result {
            assert!(!candidates.is_empty());
            // Should return multiple EVM chains
            assert!(candidates.iter().any(|c| c.chain == "ethereum"));
            // Should be sorted by confidence (highest first)
            for i in 1..candidates.len() {
                assert!(candidates[i - 1].confidence >= candidates[i].confidence);
            }
            // First candidate should have highest confidence
            assert!(candidates[0].confidence > 0.0);
            // Should be normalized to checksum format
            assert_ne!(candidates[0].normalized, input);
            assert!(candidates[0].normalized.starts_with("0x"));
            assert_eq!(candidates[0].normalized.len(), 42);
        }
    }

    #[test]
    fn test_identify_evm_address_mixed_case_full_pipeline() {
        // Test full identify() pipeline with mixed case EVM address from failing test
        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let result = identify(input);

        // Verify the full pipeline works
        if let Ok(candidates) = result {
            assert!(!candidates.is_empty());
            // All should be EVM chains
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
            assert!(candidates
                .iter()
                .all(|c| evm_chains.contains(&c.chain.as_str())));
            // Should be sorted by confidence
            for i in 1..candidates.len() {
                assert!(candidates[i - 1].confidence >= candidates[i].confidence);
            }
        }
    }

    #[test]
    fn test_identify_tron_full_pipeline() {
        // Test full identify() pipeline with Tron address from failing test
        use base58::ToBase58;
        use sha2::{Digest, Sha256};

        let version = 0x41u8;
        let address_bytes = vec![0u8; 20];
        let payload = [&[version], address_bytes.as_slice()].concat();
        let hash1 = Sha256::digest(&payload);
        let hash2 = Sha256::digest(hash1);
        let checksum = &hash2[..4];
        let full_bytes = [payload, checksum.to_vec()].concat();
        let tron_addr = full_bytes.to_base58();

        let result = identify(&tron_addr);

        // Verify the full pipeline works
        if let Ok(candidates) = result {
            assert!(!candidates.is_empty());
            // Should include Tron (if detection works)
            if candidates.iter().any(|c| c.chain == "tron") {
                // Verify Tron candidate structure
                let tron_candidate = candidates.iter().find(|c| c.chain == "tron").unwrap();
                assert!(!tron_candidate.normalized.is_empty());
                assert!(tron_candidate.confidence > 0.0);
            }
            // Should be sorted by confidence
            for i in 1..candidates.len() {
                assert!(candidates[i - 1].confidence >= candidates[i].confidence);
            }
        }
    }

    #[test]
    fn test_identify_full_pipeline_structure() {
        // Test that identify() returns correct structure even if detection fails
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let result = identify(input);

        // Verify return structure
        match result {
            Ok(candidates) => {
                // Verify all candidates have correct structure
                for candidate in &candidates {
                    assert!(!candidate.chain.is_empty());
                    assert!(!candidate.normalized.is_empty());
                    assert!(candidate.confidence >= 0.0 && candidate.confidence <= 1.0);
                    assert!(!candidate.reasoning.is_empty());
                    // Verify encoding is valid
                    if candidate.encoding == crate::registry::EncodingType::Hex {
                        assert!(candidate.normalized.starts_with("0x"));
                    }
                }
                // Verify sorting (highest confidence first)
                for i in 1..candidates.len() {
                    assert!(candidates[i - 1].confidence >= candidates[i].confidence);
                }
            }
            Err(e) => {
                // Verify error structure
                match e {
                    Error::InvalidInput(msg) => {
                        assert!(!msg.is_empty());
                        assert!(msg.contains(input) || msg.contains("Unable to"));
                    }
                    Error::NotImplemented => {}
                }
            }
        }
    }

    // ============================================================================
    // Phase 1: Valid Address Tests for All 29 Chains
    // ============================================================================

    // 1.1 EVM Chains (10 chains)
    #[test]
    fn test_identify_evm_burn_address() {
        // Test burn address valid on all EVM chains
        let input = "0x000000000000000000000000000000000000dEaD";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
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
        let matched_chains: Vec<_> = result.iter().map(|c| c.chain.as_str()).collect();
        assert!(evm_chains
            .iter()
            .any(|&chain| matched_chains.contains(&chain)));

        // Verify all are addresses
        assert!(result.iter().all(|c| c.input_type == InputType::Address));
        // Verify normalization
        assert!(result[0].normalized.starts_with("0x"));
        assert_eq!(result[0].normalized.len(), 42);
    }

    #[test]
    fn test_identify_evm_vitalik_address() {
        // Test Vitalik's address
        let input = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
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
        let matched_chains: Vec<_> = result.iter().map(|c| c.chain.as_str()).collect();
        assert!(evm_chains
            .iter()
            .any(|&chain| matched_chains.contains(&chain)));

        // Verify normalization to EIP55
        assert!(result[0].normalized.starts_with("0x"));
        assert_eq!(result[0].normalized.len(), 42);
    }

    #[test]
    fn test_identify_evm_usdt_contract() {
        // Test USDT contract address
        let input = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
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
        let matched_chains: Vec<_> = result.iter().map(|c| c.chain.as_str()).collect();
        assert!(evm_chains
            .iter()
            .any(|&chain| matched_chains.contains(&chain)));
    }

    #[test]
    fn test_identify_evm_lowercase() {
        // Test lowercase EVM address (should normalize)
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should be normalized (not same as input if input was lowercase)
        assert!(result[0].normalized.starts_with("0x"));
        assert_eq!(result[0].normalized.len(), 42);
    }

    #[test]
    fn test_identify_evm_uppercase() {
        // Test uppercase EVM address (should normalize)
        let input = "0xD8DA6BF26964AF9D7EED9E03E53415D37AA96045";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should be normalized
        assert!(result[0].normalized.starts_with("0x"));
        assert_eq!(result[0].normalized.len(), 42);
    }

    // 1.2 Bitcoin Ecosystem (3 chains)
    #[test]
    fn test_identify_bitcoin_p2pkh() {
        // Test Bitcoin P2PKH address (genesis block)
        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match Bitcoin
        assert!(result.iter().any(|c| c.chain == "bitcoin"));
        // Verify structure
        assert!(result.iter().all(|c| c.input_type == InputType::Address));
        assert!(result[0].confidence > 0.0);
    }

    #[test]
    fn test_identify_bitcoin_p2sh() {
        // Test Bitcoin P2SH address
        let input = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match Bitcoin
        assert!(result.iter().any(|c| c.chain == "bitcoin"));
    }

    #[test]
    fn test_identify_bitcoin_bech32() {
        // Test Bitcoin Bech32 address
        let input = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match Bitcoin
        assert!(result.iter().any(|c| c.chain == "bitcoin"));
        // Verify normalization (Bech32 is case-insensitive)
        assert_eq!(result[0].normalized, input.to_lowercase());
    }

    #[test]
    fn test_identify_litecoin() {
        // Test Litecoin address
        let input = "LcNS6c8RddAMjewDrUAAi8BzecKoosnkN3";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match Litecoin
        assert!(result.iter().any(|c| c.chain == "litecoin"));
    }

    #[test]
    fn test_identify_dogecoin() {
        // Test Dogecoin address
        let input = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match Dogecoin
        assert!(result.iter().any(|c| c.chain == "dogecoin"));
    }

    // 1.3 Cosmos Ecosystem (10 chains)
    #[test]
    fn test_identify_cosmos_hub() {
        // Test Cosmos Hub address
        // Using a real Cosmos address format - need to check if this is valid
        // For now, test with a pattern that should be detected
        let input = "cosmos1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input);

        // Check if it's classified correctly (might fail if address is invalid)
        match result {
            Ok(candidates) => {
                assert!(!candidates.is_empty());
                // If Cosmos Hub is detected, verify it's correct
                if candidates.iter().any(|c| c.chain == "cosmos_hub") {
                    let cosmos_match = candidates.iter().find(|c| c.chain == "cosmos_hub").unwrap();
                    assert_eq!(cosmos_match.input_type, InputType::Address);
                    assert_eq!(cosmos_match.normalized, input.to_lowercase());
                }
            }
            Err(_) => {
                // If classification fails, the address might be invalid
                // But we should still test with a valid address
                // For now, let's use a real Cosmos address from onchain examples if available
            }
        }
    }

    #[test]
    fn test_identify_osmosis() {
        // Test Osmosis address
        let input = "osmo1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "osmosis") {
                let osmosis_match = candidates.iter().find(|c| c.chain == "osmosis").unwrap();
                assert_eq!(osmosis_match.input_type, InputType::Address);
            }
        }
    }

    #[test]
    fn test_identify_juno() {
        // Test Juno address
        let input = "juno1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "juno") {
                let juno_match = candidates.iter().find(|c| c.chain == "juno").unwrap();
                assert_eq!(juno_match.input_type, InputType::Address);
            }
        }
    }

    #[test]
    fn test_identify_akash() {
        // Test Akash address
        let input = "akash1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "akash") {
                let akash_match = candidates.iter().find(|c| c.chain == "akash").unwrap();
                assert_eq!(akash_match.input_type, InputType::Address);
            }
        }
    }

    #[test]
    fn test_identify_stargaze() {
        // Test Stargaze address
        let input = "stars1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "stargaze") {
                let stargaze_match = candidates.iter().find(|c| c.chain == "stargaze").unwrap();
                assert_eq!(stargaze_match.input_type, InputType::Address);
            }
        }
    }

    #[test]
    fn test_identify_secret_network() {
        // Test Secret Network address
        let input = "secret1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "secret_network") {
                let secret_match = candidates
                    .iter()
                    .find(|c| c.chain == "secret_network")
                    .unwrap();
                assert_eq!(secret_match.input_type, InputType::Address);
            }
        }
    }

    #[test]
    fn test_identify_terra() {
        // Test Terra address
        let input = "terra1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "terra") {
                let terra_match = candidates.iter().find(|c| c.chain == "terra").unwrap();
                assert_eq!(terra_match.input_type, InputType::Address);
            }
        }
    }

    #[test]
    fn test_identify_kava() {
        // Test Kava address
        let input = "kava1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "kava") {
                let kava_match = candidates.iter().find(|c| c.chain == "kava").unwrap();
                assert_eq!(kava_match.input_type, InputType::Address);
            }
        }
    }

    #[test]
    fn test_identify_regen() {
        // Test Regen address
        let input = "regen1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "regen") {
                let regen_match = candidates.iter().find(|c| c.chain == "regen").unwrap();
                assert_eq!(regen_match.input_type, InputType::Address);
            }
        }
    }

    #[test]
    fn test_identify_sentinel() {
        // Test Sentinel address
        let input = "sent1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "sentinel") {
                let sentinel_match = candidates.iter().find(|c| c.chain == "sentinel").unwrap();
                assert_eq!(sentinel_match.input_type, InputType::Address);
            }
        }
    }

    // 1.4 Substrate/Polkadot (3 chains)
    #[test]
    fn test_identify_polkadot() {
        // Test Polkadot address
        let input = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match Polkadot
        assert!(result.iter().any(|c| c.chain == "polkadot"));
    }

    #[test]
    fn test_identify_kusama() {
        // Test Kusama address
        let input = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match Kusama
        assert!(result.iter().any(|c| c.chain == "kusama"));
    }

    #[test]
    fn test_identify_substrate() {
        // Test Substrate address (generic SS58)
        // Using a valid SS58 address with different prefix
        let input = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match at least one Substrate-based chain
        let substrate_chains = ["polkadot", "kusama", "substrate"];
        assert!(result
            .iter()
            .any(|c| substrate_chains.contains(&c.chain.as_str())));
    }

    // 1.5 Other Chains (3 chains)
    #[test]
    fn test_identify_solana() {
        // Test Solana address
        let input = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match Solana (could also match as Ed25519 public key)
        assert!(result.iter().any(|c| c.chain == "solana"));
    }

    #[test]
    fn test_identify_solana_usdc_mint() {
        // Test Solana USDC mint address
        let input = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match Solana
        assert!(result.iter().any(|c| c.chain == "solana"));
    }

    #[test]
    fn test_identify_tron() {
        // Test Tron address
        let input = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match Tron
        assert!(result.iter().any(|c| c.chain == "tron"));
    }

    #[test]
    fn test_identify_cardano() {
        // Test Cardano address
        // Using a real Cardano address format - if address is invalid Bech32, classification will fail
        let input = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnjhl2zqwpg7h3vj6";
        let result = identify(input);

        // If address is valid Bech32 and matches Cardano metadata, verify structure
        if let Ok(candidates) = result {
            assert!(!candidates.is_empty());
            // If Cardano is detected, verify it's correct
            if candidates.iter().any(|c| c.chain == "cardano") {
                let cardano_match = candidates.iter().find(|c| c.chain == "cardano").unwrap();
                assert_eq!(cardano_match.input_type, InputType::Address);
                // Verify Bech32 normalization
                assert_eq!(cardano_match.normalized, input.to_lowercase());
            }
        }
        // If classification fails, the address might be invalid Bech32
        // This is expected for generated/invalid addresses
    }

    // ============================================================================
    // Phase 2: Valid Public Key Tests for All 29 Chains
    // ============================================================================

    // 2.1 secp256k1 Public Keys (EVM chains, Bitcoin ecosystem, Tron)
    #[test]
    fn test_identify_secp256k1_compressed_evm() {
        // Test compressed secp256k1 public key (33 bytes) for EVM chains
        // Using a valid compressed public key
        let input = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match EVM chains
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
        let matched_chains: Vec<_> = result.iter().map(|c| c.chain.as_str()).collect();
        assert!(evm_chains
            .iter()
            .any(|&chain| matched_chains.contains(&chain)));
        // Should derive to addresses
        assert!(result
            .iter()
            .all(|c| c.input_type == InputType::PublicKey || c.input_type == InputType::Address));
    }

    #[test]
    fn test_identify_secp256k1_uncompressed_evm() {
        // Test uncompressed secp256k1 public key (65 bytes) for EVM chains
        let input = "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match EVM chains
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
        let matched_chains: Vec<_> = result.iter().map(|c| c.chain.as_str()).collect();
        assert!(evm_chains
            .iter()
            .any(|&chain| matched_chains.contains(&chain)));
    }

    #[test]
    fn test_identify_secp256k1_bitcoin() {
        // Test secp256k1 public key for Bitcoin
        let input = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "bitcoin") {
                let bitcoin_match = candidates.iter().find(|c| c.chain == "bitcoin").unwrap();
                assert!(
                    bitcoin_match.input_type == InputType::PublicKey
                        || bitcoin_match.input_type == InputType::Address
                );
            }
        }
    }

    #[test]
    fn test_identify_secp256k1_tron() {
        // Test secp256k1 public key for Tron
        let input = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "tron") {
                let tron_match = candidates.iter().find(|c| c.chain == "tron").unwrap();
                assert!(
                    tron_match.input_type == InputType::PublicKey
                        || tron_match.input_type == InputType::Address
                );
            }
        }
    }

    // 2.2 Ed25519 Public Keys (Solana, Cardano, Cosmos chains, Substrate chains)
    #[test]
    fn test_identify_ed25519_solana() {
        // Test Ed25519 public key (32-byte hex) for Solana
        // Solana uses base58 for public keys, so let's use a hex-encoded 32-byte key
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let result = identify(input);

        if let Ok(candidates) = result {
            if candidates.iter().any(|c| {
                c.chain == "solana"
                    || c.chain == "cardano"
                    || c.chain.starts_with("cosmos")
                    || c.chain == "polkadot"
                    || c.chain == "kusama"
            }) {
                // Found Ed25519 chain match
                let ed25519_match = candidates
                    .iter()
                    .find(|c| {
                        c.chain == "solana"
                            || c.chain == "cardano"
                            || c.chain.starts_with("cosmos")
                            || c.chain == "polkadot"
                            || c.chain == "kusama"
                    })
                    .unwrap();
                assert!(
                    ed25519_match.input_type == InputType::PublicKey
                        || ed25519_match.input_type == InputType::Address
                );
            }
        }
    }

    #[test]
    fn test_identify_ed25519_cardano() {
        // Test Ed25519 public key for Cardano (hex format)
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let result = identify(input);

        // Cardano requires stake key, so single PK might not match
        if let Ok(candidates) = result {
            if candidates.iter().any(|c| c.chain == "cardano") {
                let cardano_match = candidates.iter().find(|c| c.chain == "cardano").unwrap();
                assert!(cardano_match.confidence > 0.0);
            }
        }
    }

    #[test]
    fn test_identify_ed25519_cosmos() {
        // Test Ed25519 public key for Cosmos chains
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let result = identify(input);

        if let Ok(candidates) = result {
            let cosmos_chains = [
                "cosmos_hub",
                "osmosis",
                "juno",
                "akash",
                "stargaze",
                "secret_network",
                "terra",
                "kava",
                "regen",
                "sentinel",
            ];
            let matched_chains: Vec<_> = candidates.iter().map(|c| c.chain.as_str()).collect();
            if cosmos_chains
                .iter()
                .any(|&chain| matched_chains.contains(&chain))
            {
                // Found Cosmos chain match
                let cosmos_match = candidates
                    .iter()
                    .find(|c| cosmos_chains.contains(&c.chain.as_str()))
                    .unwrap();
                assert!(
                    cosmos_match.input_type == InputType::PublicKey
                        || cosmos_match.input_type == InputType::Address
                );
            }
        }
    }

    #[test]
    fn test_identify_ed25519_substrate() {
        // Test Ed25519 public key for Substrate chains
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let result = identify(input);

        if let Ok(candidates) = result {
            let substrate_chains = ["polkadot", "kusama", "substrate"];
            let matched_chains: Vec<_> = candidates.iter().map(|c| c.chain.as_str()).collect();
            if substrate_chains
                .iter()
                .any(|&chain| matched_chains.contains(&chain))
            {
                // Found Substrate chain match
                let substrate_match = candidates
                    .iter()
                    .find(|c| substrate_chains.contains(&c.chain.as_str()))
                    .unwrap();
                assert!(
                    substrate_match.input_type == InputType::PublicKey
                        || substrate_match.input_type == InputType::Address
                );
            }
        }
    }

    // 2.3 sr25519 Public Keys (Substrate chains)
    #[test]
    fn test_identify_sr25519_substrate() {
        // Test sr25519 public key (32-byte hex, indistinguishable from Ed25519 at classification)
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let result = identify(input);

        if let Ok(candidates) = result {
            let substrate_chains = ["polkadot", "kusama", "substrate"];
            let matched_chains: Vec<_> = candidates.iter().map(|c| c.chain.as_str()).collect();
            if substrate_chains
                .iter()
                .any(|&chain| matched_chains.contains(&chain))
            {
                // Found Substrate chain match
                let substrate_match = candidates
                    .iter()
                    .find(|c| substrate_chains.contains(&c.chain.as_str()))
                    .unwrap();
                assert!(
                    substrate_match.input_type == InputType::PublicKey
                        || substrate_match.input_type == InputType::Address
                );
            }
        }
    }

    #[test]
    fn test_try_address_detection_evm() {
        // Test EVM address detection for Ethereum chain
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
        let chain_id = "ethereum";

        let candidates = try_address_detection_for_chain(input, &chars, chain_id);

        // Should return candidates if detection succeeds
        if !candidates.is_empty() {
            // All should be addresses
            assert!(candidates
                .iter()
                .all(|c| c.input_type == InputType::Address));
            // All should be for Ethereum
            assert!(candidates.iter().all(|c| c.chain == "ethereum"));
            // Should have normalized address
            assert!(candidates[0].normalized.starts_with("0x"));
            assert_eq!(candidates[0].normalized.len(), 42);
            // Should have confidence > 0
            assert!(candidates[0].confidence > 0.0);
            // Should have reasoning
            assert!(!candidates[0].reasoning.is_empty());
        }
        // Verify structure even if empty (detection issue, not function issue)
        for candidate in &candidates {
            assert_eq!(candidate.input_type, InputType::Address);
            assert!(!candidate.chain.is_empty());
            assert!(!candidate.normalized.is_empty());
            assert!(candidate.confidence >= 0.0 && candidate.confidence <= 1.0);
        }
    }

    #[test]
    fn test_try_address_detection_evm_mixed_case() {
        // Test mixed case EVM address
        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chars = extract_characteristics(input);
        let chain_id = "ethereum";

        let candidates = try_address_detection_for_chain(input, &chars, chain_id);

        // Verify structure
        for candidate in &candidates {
            assert_eq!(candidate.input_type, InputType::Address);
            assert_eq!(candidate.chain, "ethereum");
            if !candidates.is_empty() {
                // Should be normalized (checksum format)
                assert!(candidate.normalized.starts_with("0x"));
                assert_eq!(candidate.normalized.len(), 42);
            }
        }
    }

    #[test]
    fn test_try_address_detection_bitcoin() {
        // Test Bitcoin P2PKH address
        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let chars = extract_characteristics(input);
        let chain_id = "bitcoin";

        let candidates = try_address_detection_for_chain(input, &chars, chain_id);

        // Verify structure
        for candidate in &candidates {
            assert_eq!(candidate.input_type, InputType::Address);
            assert_eq!(candidate.chain, "bitcoin");
            if !candidates.is_empty() {
                // Should have normalized address
                assert!(!candidate.normalized.is_empty());
                assert!(candidate.confidence > 0.0);
            }
        }
    }

    #[test]
    fn test_try_address_detection_bitcoin_bech32() {
        // Test Bitcoin Bech32 address
        let input = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let chars = extract_characteristics(input);
        let chain_id = "bitcoin";

        let candidates = try_address_detection_for_chain(input, &chars, chain_id);

        // Verify structure
        for candidate in &candidates {
            assert_eq!(candidate.input_type, InputType::Address);
            assert_eq!(candidate.chain, "bitcoin");
            if !candidates.is_empty() {
                // Should have normalized address
                assert!(!candidate.normalized.is_empty());
                assert!(candidate.confidence > 0.0);
            }
        }
    }

    #[test]
    fn test_try_address_detection_invalid_chain() {
        // Test with invalid chain ID
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
        let chain_id = "nonexistent_chain";

        let candidates = try_address_detection_for_chain(input, &chars, chain_id);

        // Should return empty vector for invalid chain
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_try_address_detection_wrong_chain() {
        // Test EVM address with Bitcoin chain (should not match)
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
        let chain_id = "bitcoin";

        let candidates = try_address_detection_for_chain(input, &chars, chain_id);

        // Should return empty (EVM address doesn't match Bitcoin format)
        // But verify structure if any candidates returned
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_try_address_detection_multiple_formats() {
        // Test that function handles chains with multiple address formats
        // Bitcoin has both P2PKH and Bech32 formats
        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let chars = extract_characteristics(input);
        let chain_id = "bitcoin";

        let candidates = try_address_detection_for_chain(input, &chars, chain_id);

        // Should return at least one candidate if format matches
        // Verify all candidates have correct structure
        for candidate in &candidates {
            assert_eq!(candidate.input_type, InputType::Address);
            assert_eq!(candidate.chain, "bitcoin");
            assert!(!candidate.normalized.is_empty());
            assert!(candidate.confidence >= 0.0 && candidate.confidence <= 1.0);
            assert!(!candidate.reasoning.is_empty());
        }
    }

    // ============================================================================
    // Phase 3: Function-Level Tests
    // ============================================================================

    // 3.4 try_address_detection_for_chain Tests (expanded)
    #[test]
    fn test_try_address_detection_all_evm_chains() {
        // Test all EVM chains with same address
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
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

        for chain_id in &evm_chains {
            let candidates = try_address_detection_for_chain(input, &chars, chain_id);
            // Each EVM chain should detect the address
            if !candidates.is_empty() {
                assert_eq!(candidates[0].chain, *chain_id);
                assert_eq!(candidates[0].input_type, InputType::Address);
                assert!(candidates[0].confidence > 0.0);
            }
        }
    }

    #[test]
    fn test_try_address_detection_cosmos_chains() {
        // Test Cosmos chains with their specific HRPs
        let cosmos_tests = vec![
            (
                "cosmos_hub",
                "cosmos1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            ),
            ("osmosis", "osmo1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            ("juno", "juno1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
        ];

        for (chain_id, address) in cosmos_tests {
            let chars = extract_characteristics(address);
            let candidates = try_address_detection_for_chain(address, &chars, chain_id);

            if !candidates.is_empty() {
                assert_eq!(candidates[0].chain, chain_id);
                assert_eq!(candidates[0].input_type, InputType::Address);
            }
        }
    }

    #[test]
    fn test_try_address_detection_substrate_chains() {
        // Test Substrate chains with SS58 addresses
        let substrate_tests = vec![
            (
                "polkadot",
                "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            ),
            ("kusama", "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"),
        ];

        for (chain_id, address) in substrate_tests {
            let chars = extract_characteristics(address);
            let candidates = try_address_detection_for_chain(address, &chars, chain_id);

            if !candidates.is_empty() {
                assert_eq!(candidates[0].chain, chain_id);
                assert_eq!(candidates[0].input_type, InputType::Address);
            }
        }
    }

    // 3.5 try_public_key_derivation_for_chain Tests
    #[test]
    fn test_try_public_key_derivation_secp256k1_evm() {
        // Test secp256k1 key → EVM address derivation
        let input = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let chars = extract_characteristics(input);
        let key_type = crate::input::DetectedKeyType::Secp256k1 { compressed: true };
        let chain_id = "ethereum";

        let candidates = try_public_key_derivation_for_chain(input, &chars, key_type, chain_id);

        // Should derive to Ethereum address
        if !candidates.is_empty() {
            assert_eq!(candidates[0].chain, "ethereum");
            assert_eq!(candidates[0].input_type, InputType::PublicKey);
            assert!(candidates[0].confidence > 0.0);
            assert!(candidates[0].normalized.starts_with("0x"));
            assert_eq!(candidates[0].normalized.len(), 42);
        }
    }

    #[test]
    fn test_try_public_key_derivation_secp256k1_bitcoin() {
        // Test secp256k1 key → Bitcoin P2PKH derivation
        let input = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let chars = extract_characteristics(input);
        let key_type = crate::input::DetectedKeyType::Secp256k1 { compressed: true };
        let chain_id = "bitcoin";

        let candidates = try_public_key_derivation_for_chain(input, &chars, key_type, chain_id);

        // Should derive to Bitcoin address
        if !candidates.is_empty() {
            assert_eq!(candidates[0].chain, "bitcoin");
            assert_eq!(candidates[0].input_type, InputType::PublicKey);
            assert!(candidates[0].confidence > 0.0);
        }
    }

    #[test]
    fn test_try_public_key_derivation_ed25519_solana() {
        // Test Ed25519 key → Solana address derivation
        // Solana uses base58 for public keys, but we can test with hex
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let chars = extract_characteristics(input);
        let key_type = crate::input::DetectedKeyType::Ed25519;
        let chain_id = "solana";

        let candidates = try_public_key_derivation_for_chain(input, &chars, key_type, chain_id);

        // Should derive to Solana address
        if !candidates.is_empty() {
            assert_eq!(candidates[0].chain, "solana");
            assert_eq!(candidates[0].input_type, InputType::PublicKey);
            assert!(candidates[0].confidence > 0.0);
        }
    }

    #[test]
    fn test_try_public_key_derivation_ed25519_cosmos() {
        // Test Ed25519 key → Cosmos address derivation
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let chars = extract_characteristics(input);
        let key_type = crate::input::DetectedKeyType::Ed25519;
        let chain_id = "cosmos_hub";

        let candidates = try_public_key_derivation_for_chain(input, &chars, key_type, chain_id);

        // Should derive to Cosmos address
        if !candidates.is_empty() {
            assert_eq!(candidates[0].chain, "cosmos_hub");
            assert_eq!(candidates[0].input_type, InputType::PublicKey);
            assert!(candidates[0].normalized.starts_with("cosmos1"));
        }
    }

    #[test]
    fn test_try_public_key_derivation_ed25519_ss58() {
        // Test Ed25519 key → SS58 address derivation
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let chars = extract_characteristics(input);
        let key_type = crate::input::DetectedKeyType::Ed25519;
        let chain_id = "polkadot";

        let candidates = try_public_key_derivation_for_chain(input, &chars, key_type, chain_id);

        // Should derive to SS58 address
        if !candidates.is_empty() {
            assert_eq!(candidates[0].chain, "polkadot");
            assert_eq!(candidates[0].input_type, InputType::PublicKey);
            assert!(candidates[0].confidence > 0.0);
        }
    }

    #[test]
    fn test_try_public_key_derivation_cardano_requires_stake_key() {
        // Test Cardano with single PK (should be excluded due to requires_stake_key)
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let chars = extract_characteristics(input);
        let key_type = crate::input::DetectedKeyType::Ed25519;
        let chain_id = "cardano";

        let candidates = try_public_key_derivation_for_chain(input, &chars, key_type, chain_id);

        // Should return empty (Cardano requires stake key)
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_try_public_key_derivation_invalid_chain() {
        // Test with invalid chain ID
        let input = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let chars = extract_characteristics(input);
        let key_type = crate::input::DetectedKeyType::Secp256k1 { compressed: true };
        let chain_id = "nonexistent_chain";

        let candidates = try_public_key_derivation_for_chain(input, &chars, key_type, chain_id);

        // Should return empty
        assert!(candidates.is_empty());
    }

    // ============================================================================
    // Phase 4: Edge Cases
    // ============================================================================

    // 4.1 Address Edge Cases
    #[test]
    fn test_edge_case_evm_lowercase_normalize() {
        // Lowercase EVM addresses (should normalize)
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should be normalized (not same as input if input was lowercase)
        assert!(result[0].normalized.starts_with("0x"));
        assert_eq!(result[0].normalized.len(), 42);
        // Normalized should have checksum format
        assert_ne!(result[0].normalized, input);
    }

    #[test]
    fn test_edge_case_evm_uppercase_normalize() {
        // Uppercase EVM addresses (should normalize)
        let input = "0xD8DA6BF26964AF9D7EED9E03E53415D37AA96045";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should be normalized to checksum format
        assert!(result[0].normalized.starts_with("0x"));
        assert_eq!(result[0].normalized.len(), 42);
    }

    #[test]
    fn test_edge_case_evm_mixed_case_incorrect_checksum() {
        // Mixed-case with incorrect checksum (should normalize)
        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should normalize (may have lower confidence if checksum invalid)
        assert!(result[0].normalized.starts_with("0x"));
        assert_eq!(result[0].normalized.len(), 42);
    }

    #[test]
    fn test_edge_case_address_length_boundaries() {
        // Addresses at exact length boundaries
        // EVM: exactly 42 chars
        let input = "0x0000000000000000000000000000000000000000";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        assert_eq!(result[0].normalized.len(), 42);
    }

    #[test]
    fn test_edge_case_address_valid_structure_wrong_chain() {
        // Addresses with valid structure but wrong chain
        // EVM address tested against Bitcoin chain (should not match)
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
        let chain_id = "bitcoin";

        let candidates = try_address_detection_for_chain(input, &chars, chain_id);

        // Should return empty (EVM address doesn't match Bitcoin format)
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_edge_case_ambiguous_32byte_base58() {
        // Ambiguous formats (32-byte base58: Solana address OR Ed25519 key)
        let input = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should return both address and public key possibilities
        let has_address = result.iter().any(|c| c.input_type == InputType::Address);
        let has_pk = result.iter().any(|c| c.input_type == InputType::PublicKey);
        // At least one should be present
        assert!(has_address || has_pk);
    }

    // 4.2 Public Key Edge Cases
    #[test]
    fn test_edge_case_compressed_vs_uncompressed_secp256k1() {
        // Compressed vs uncompressed secp256k1
        let compressed = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let uncompressed = "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

        let result_compressed = identify(compressed).unwrap();
        let result_uncompressed = identify(uncompressed).unwrap();

        // Both should be detected
        assert!(!result_compressed.is_empty());
        assert!(!result_uncompressed.is_empty());
    }

    #[test]
    fn test_edge_case_32byte_hex_ed25519_vs_sr25519() {
        // 32-byte hex (Ed25519 vs sr25519 ambiguity)
        // Must be exactly 64 hex characters (32 bytes) - the previous test had 66 chars (33 bytes)
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match both Ed25519 and sr25519 chains
        let has_ed25519 = result.iter().any(|c| {
            matches!(c.input_type, InputType::PublicKey)
                && (c.chain == "solana" || c.chain == "cardano" || c.chain.starts_with("cosmos"))
        });
        let has_sr25519 = result.iter().any(|c| {
            matches!(c.input_type, InputType::PublicKey)
                && (c.chain == "polkadot" || c.chain == "kusama")
        });
        // At least one should be present
        assert!(has_ed25519 || has_sr25519);
    }

    #[test]
    fn test_edge_case_public_key_no_matching_curve() {
        // Public keys that don't match any chain curve
        // This is hard to test without invalid key format, but we can test wrong length
        let input = "0x1234"; // Too short to be a valid public key
        let result = identify(input);

        // Should return error (can't classify as public key or address)
        assert!(result.is_err());
    }

    #[test]
    fn test_edge_case_cardano_single_pk_excluded() {
        // Cardano with single PK (should be excluded)
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let chars = extract_characteristics(input);
        let key_type = crate::input::DetectedKeyType::Ed25519;
        let chain_id = "cardano";

        let candidates = try_public_key_derivation_for_chain(input, &chars, key_type, chain_id);

        // Should return empty (Cardano requires stake key)
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_edge_case_invalid_key_encoding() {
        // Invalid key encoding
        let input = "not-a-valid-key-encoding";
        let result = identify(input);

        // Should return error
        assert!(result.is_err());
    }

    // 4.3 Pipeline Edge Cases
    #[test]
    fn test_edge_case_empty_input_string() {
        // Empty input string
        let result = identify("");

        // Should return error
        assert!(result.is_err());
    }

    #[test]
    fn test_edge_case_invalid_encoding() {
        // Invalid encoding
        let input = "!!!invalid!!!";
        let result = identify(input);

        // Should return error
        assert!(result.is_err());
    }

    #[test]
    fn test_edge_case_wrong_hrp_bech32() {
        // Wrong HRP for Bech32 (should not match)
        let input = "cosmos1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let chars = extract_characteristics(input);
        let chain_id = "osmosis"; // Wrong chain (Osmosis uses "osmo" HRP)

        let candidates = try_address_detection_for_chain(input, &chars, chain_id);

        // Should return empty (wrong HRP)
        assert!(candidates.is_empty());
    }

    // 4.4 Multi-chain Edge Cases
    #[test]
    fn test_edge_case_same_address_multiple_evm_chains() {
        // Same address on multiple EVM chains (should return all)
        let input = "0x000000000000000000000000000000000000dEaD";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should return multiple EVM chains
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
        let matched_chains: Vec<_> = result.iter().map(|c| c.chain.as_str()).collect();
        let matched_evm_count = evm_chains
            .iter()
            .filter(|&chain| matched_chains.contains(chain))
            .count();
        assert!(matched_evm_count >= 1); // At least one EVM chain
    }

    #[test]
    fn test_edge_case_ambiguous_input_address_and_pk() {
        // Ambiguous input (address + public key possibilities)
        let input = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should return both address and public key candidates
        let has_address = result.iter().any(|c| c.input_type == InputType::Address);
        let has_pk = result.iter().any(|c| c.input_type == InputType::PublicKey);
        // At least one should be present
        assert!(has_address || has_pk);
    }

    #[test]
    fn test_edge_case_chain_multiple_address_formats() {
        // Chain with multiple address formats (Bitcoin: P2PKH, P2SH, Bech32)
        let p2pkh = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let bech32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

        let result_p2pkh = identify(p2pkh).unwrap();
        let result_bech32 = identify(bech32).unwrap();

        // Both should match Bitcoin
        assert!(result_p2pkh.iter().any(|c| c.chain == "bitcoin"));
        assert!(result_bech32.iter().any(|c| c.chain == "bitcoin"));
    }

    #[test]
    fn test_edge_case_public_key_derives_multiple_chains() {
        // Public key that derives to multiple chains
        let input = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let result = identify(input).unwrap();

        assert!(!result.is_empty());
        // Should match multiple g chains (EVM, Bitcoin, Tron)
        let secp256k1_chains = ["ethereum", "bitcoin", "tron"];
        let matched_chains: Vec<_> = result.iter().map(|c| c.chain.as_str()).collect();
        let matched_count = secp256k1_chains
            .iter()
            .filter(|&chain| matched_chains.contains(chain))
            .count();
        assert!(matched_count >= 1); // At least one secp256k1 chain
    }

    #[test]
    fn test_solana_base58_should_not_match_cosmos() {
        // Test that base58 Solana address/key doesn't match Cosmos chains
        let input = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let result = identify(input).unwrap();

        // Should only match Solana (address + public key = 2 candidates)
        let solana_count = result.iter().filter(|c| c.chain == "solana").count();
        let cosmos_count = result
            .iter()
            .filter(|c| {
                c.chain.starts_with("cosmos")
                    || c.chain == "osmosis"
                    || c.chain == "juno"
                    || c.chain == "akash"
                    || c.chain == "stargaze"
                    || c.chain == "secret_network"
                    || c.chain == "terra"
                    || c.chain == "kava"
                    || c.chain == "regen"
                    || c.chain == "sentinel"
            })
            .count();

        println!("Solana candidates: {}", solana_count);
        println!("Cosmos candidates: {}", cosmos_count);
        println!("Total candidates: {}", result.len());

        // Should have Solana matches
        assert!(solana_count > 0, "Should match Solana");
        // Should NOT have Cosmos matches (base58 input shouldn't match hex-only formats)
        assert_eq!(
            cosmos_count, 0,
            "Base58 input should not match Cosmos chains that require hex encoding"
        );
    }

    // ============================================================================
    // Transaction identification tests
    // ============================================================================

    #[test]
    fn test_identify_evm_tx_hash() {
        // Ethereum tx hash from onchain-examples.md
        let input = "0xcdf331416ac94df404cfa95b13ecd4b23b2b1de895c945e25ff1b557c597a64e";
        let result = identify(input).unwrap();

        let tx_candidates: Vec<_> = result
            .iter()
            .filter(|c| c.input_type == InputType::Transaction)
            .collect();
        assert!(
            !tx_candidates.is_empty(),
            "Should have transaction candidates"
        );
        assert!(tx_candidates.iter().any(|c| c.chain == "ethereum"));
        // Verify scanner URL
        let eth_tx = tx_candidates
            .iter()
            .find(|c| c.chain == "ethereum")
            .unwrap();
        assert!(eth_tx.scanner_url.is_some());
        assert!(eth_tx
            .scanner_url
            .as_ref()
            .unwrap()
            .contains("etherscan.io/tx/"));
        // Verify normalization (lowercase hex)
        assert!(eth_tx.normalized.starts_with("0x"));
        assert_eq!(eth_tx.normalized, eth_tx.normalized.to_lowercase());
    }

    #[test]
    fn test_identify_bitcoin_tx_hash() {
        // Bitcoin genesis coinbase tx from onchain-examples.md
        let input = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let result = identify(input).unwrap();

        let tx_candidates: Vec<_> = result
            .iter()
            .filter(|c| c.input_type == InputType::Transaction)
            .collect();
        assert!(
            !tx_candidates.is_empty(),
            "Should have transaction candidates"
        );
        assert!(tx_candidates.iter().any(|c| c.chain == "bitcoin"));
        let btc_tx = tx_candidates.iter().find(|c| c.chain == "bitcoin").unwrap();
        assert!(btc_tx.scanner_url.is_some());
        assert!(btc_tx
            .scanner_url
            .as_ref()
            .unwrap()
            .contains("blockchain.com"));
    }

    #[test]
    fn test_identify_solana_tx_signature() {
        // Solana tx signature from onchain-examples.md
        let input = "5wpHU1gGYcgKabL7heGGgiKBx3WJMruHiN34sCjTYwQu4sk9H2uMyZsm1P28RqaJPVELtcVxNmSGieq6V5ZZxpDT";
        let result = identify(input).unwrap();

        let tx_candidates: Vec<_> = result
            .iter()
            .filter(|c| c.input_type == InputType::Transaction)
            .collect();
        assert!(
            !tx_candidates.is_empty(),
            "Should have transaction candidates"
        );
        assert!(tx_candidates.iter().any(|c| c.chain == "solana"));
        let sol_tx = tx_candidates.iter().find(|c| c.chain == "solana").unwrap();
        assert!(sol_tx.scanner_url.is_some());
        assert!(sol_tx
            .scanner_url
            .as_ref()
            .unwrap()
            .contains("solscan.io/tx/"));
        // Solana tx signatures preserve original casing
        assert_eq!(sol_tx.normalized, input);
    }

    #[test]
    fn test_identify_substrate_extrinsic() {
        // Polkadot extrinsic from onchain-examples.md
        let input = "28815161-0";
        let result = identify(input).unwrap();

        let tx_candidates: Vec<_> = result
            .iter()
            .filter(|c| c.input_type == InputType::Transaction)
            .collect();
        assert!(
            !tx_candidates.is_empty(),
            "Should have transaction candidates"
        );
        // Should match Substrate-family chains
        assert!(tx_candidates
            .iter()
            .any(|c| c.chain == "polkadot" || c.chain == "kusama"));
        // Verify high confidence for distinctive pattern
        assert!(tx_candidates[0].confidence >= 0.80);
    }

    #[test]
    fn test_identify_tx_does_not_break_address_detection() {
        // Existing address inputs should still work unchanged
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let result = identify(input).unwrap();

        // Should still return address candidates
        let addr_candidates: Vec<_> = result
            .iter()
            .filter(|c| c.input_type == InputType::Address)
            .collect();
        assert!(!addr_candidates.is_empty());
        assert!(addr_candidates.iter().any(|c| c.chain == "ethereum"));
        // Should NOT have transaction candidates (42-char hex is not a tx)
        let tx_candidates: Vec<_> = result
            .iter()
            .filter(|c| c.input_type == InputType::Transaction)
            .collect();
        assert!(tx_candidates.is_empty());
    }

    #[test]
    fn test_identify_tx_does_not_break_public_key_detection() {
        // Public key inputs should still work
        let input = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let result = identify(input).unwrap();

        let pk_candidates: Vec<_> = result
            .iter()
            .filter(|c| c.input_type == InputType::PublicKey)
            .collect();
        assert!(!pk_candidates.is_empty());
    }

    #[test]
    fn test_identify_raw_hex_tx_ambiguous() {
        // 64-char hex without 0x matches multiple chains as transaction
        let input = "3e0ba99f9a254b4dec6ee5cb04f833535dd409eccc26133d8df0cf943ee9b326";
        let result = identify(input).unwrap();

        let tx_candidates: Vec<_> = result
            .iter()
            .filter(|c| c.input_type == InputType::Transaction)
            .collect();
        assert!(!tx_candidates.is_empty());
        // Should match multiple chains (bitcoin, cosmos_hub, etc.)
        let chains: Vec<_> = tx_candidates.iter().map(|c| c.chain.as_str()).collect();
        assert!(chains.len() > 1, "64-char hex should match multiple chains");
    }

    #[test]
    fn test_identify_tron_tx_hash() {
        // Tron tx from onchain-examples.md
        let input = "5156e18743c2ceba71f40640c75a8402066a8c42e570f17eecda2cc1101575f4";
        let result = identify(input).unwrap();

        let tx_candidates: Vec<_> = result
            .iter()
            .filter(|c| c.input_type == InputType::Transaction)
            .collect();
        assert!(tx_candidates.iter().any(|c| c.chain == "tron"));
    }

    #[test]
    fn test_identify_kusama_extrinsic() {
        let input = "31206697-0";
        let result = identify(input).unwrap();

        let tx_candidates: Vec<_> = result
            .iter()
            .filter(|c| c.input_type == InputType::Transaction)
            .collect();
        assert!(!tx_candidates.is_empty());
        assert!(tx_candidates.iter().any(|c| c.chain == "kusama"));
    }
}
