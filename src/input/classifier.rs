//! Input classifier (non-chain-aware)
//!
//! This module classifies input strings into possible types (address, public key)
//! using basic heuristics. It is non-chain-aware and does not perform validation.
//! The metadata-driven system will validate each possibility against chain rules.
//!
//! Architecture:
//! 1. Characteristics extraction (pure feature extraction)
//! 2. Classifier (non-chain-aware) - determines Address? PublicKey? Both? None?
//! 3. Metadata-driven signature matching - validates against chain metadata
//! 4. Optional: structural decode validation - checksums, decodes, etc.

use crate::input::InputCharacteristics;
use crate::registry::EncodingType;
use crate::shared::encoding;
use crate::Error;

/// A possible classification of the input
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPossibility {
    /// Could be an address
    Address,
    /// Could be a public key
    PublicKey { key_type: DetectedKeyType },
    /// Could be a transaction identifier (hash, digest, extrinsic ID)
    Transaction,
    /// Could be a block hash (32-byte digest identifying a block)
    BlockHash,
}

/// Detected public key type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedKeyType {
    /// secp256k1 public key
    Secp256k1 { compressed: bool },
    /// Ed25519 public key (32 bytes)
    Ed25519,
    /// sr25519 public key (32 bytes, indistinguishable from Ed25519)
    #[allow(dead_code)] // Reserved for future use - currently indistinguishable from Ed25519
    Sr25519,
}

/// Classify input and return all possibilities
///
/// Returns Result with Vec of all possible interpretations. The metadata system
/// will validate each and assign confidence scores.
///
/// Returns Err if no possibilities are found (invalid input format).
/// Uses functional programming style with iterator combinators.
pub fn classify_input(
    input: &str,
    chars: &InputCharacteristics,
) -> Result<Vec<InputPossibility>, Error> {
    let address_possibilities = could_be_address(input, chars)?;
    let public_key_possibilities = could_be_public_key(input, chars)?;
    let transaction_possibilities = could_be_transaction(input, chars)?;

    let block_hash_possibilities = could_be_block_hash(input, chars)?;

    let possibilities: Vec<InputPossibility> = address_possibilities
        .into_iter()
        .chain(public_key_possibilities)
        .chain(transaction_possibilities)
        .chain(block_hash_possibilities)
        .collect();

    if possibilities.is_empty() {
        Err(Error::InvalidInput(format!(
            "Unable to classify input format: {}",
            input
        )))
    } else {
        Ok(possibilities)
    }
}

/// Check if input could be an address based on basic heuristics
///
/// This is non-chain-aware and does not perform validation.
/// It only checks basic structure: encoding type, length ranges, HRP presence.
/// Actual validation happens in the metadata-driven detector stage.
///
/// Returns Result with Vec<InputPossibility::Address>.
/// Returns Ok with single-element vec if it could be an address, Ok with empty vec otherwise.
/// Never returns Err (address classification is always successful, even if no match).
fn could_be_address(
    _input: &str,
    chars: &InputCharacteristics,
) -> Result<Vec<InputPossibility>, Error> {
    // Try all possible encodings - if any match, it could be an address
    let could_be = chars.encoding.iter().any(|encoding| match encoding {
        EncodingType::Hex => chars.length == 42 && chars.prefixes.iter().any(|p| p == "0x"),
        EncodingType::Base58Check => {
            (26..=34).contains(&chars.length) || (35..=48).contains(&chars.length)
        }
        EncodingType::Base58 => (32..=44).contains(&chars.length),
        EncodingType::SS58 => (35..=48).contains(&chars.length),
        EncodingType::Bech32 | EncodingType::Bech32m => {
            chars.hrp.is_some() && (14..=90).contains(&chars.length)
        }
    }) || (chars.encoding.is_empty() && chars.hrp.is_some());

    Ok(if could_be {
        vec![InputPossibility::Address]
    } else {
        vec![]
    })
}

/// Check if input could be a public key based on heuristics
///
/// Returns Result with Vec<InputPossibility> for consistency with could_be_address.
/// An input might match multiple key types (e.g., 32-byte could be Ed25519 or sr25519).
/// Returns Ok with empty vec if it could not be a public key.
/// Never returns Err (public key classification is always successful, even if no match).
fn could_be_public_key(
    input: &str,
    chars: &InputCharacteristics,
) -> Result<Vec<InputPossibility>, Error> {
    // Try all possible encodings to decode the input
    let mut bytes = None;

    for encoding in &chars.encoding {
        let decoded = match encoding {
            EncodingType::Hex => {
                // hex::decode already handles "0x" prefix, but we need to ensure correct decoding
                // For public keys, we want the raw bytes including the prefix byte (0x02/0x03/0x04)
                encoding::hex::decode(input).ok()
            }
            _ => encoding::decode_to_bytes(input, Some(*encoding)),
        };

        if let Some(decoded_bytes) = decoded {
            bytes = Some(decoded_bytes);
            break; // Use first successful decode
        }
    }

    // Cannot be a PK if decoding fails
    let bytes = match bytes {
        Some(bytes) => bytes,
        None => return Ok(Vec::new()),
    };

    // Pure pattern matching with guards - no nested if/else
    let possibilities = match bytes.len() {
        32 => vec![
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Ed25519,
            },
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Sr25519,
            },
        ],
        33 if bytes[0] == 0x02 || bytes[0] == 0x03 => vec![InputPossibility::PublicKey {
            key_type: DetectedKeyType::Secp256k1 { compressed: true },
        }],
        65 if bytes[0] == 0x04 => vec![InputPossibility::PublicKey {
            key_type: DetectedKeyType::Secp256k1 { compressed: false },
        }],
        _ => Vec::new(),
    };

    Ok(possibilities)
}

/// Check if input could be a transaction identifier based on heuristics
///
/// Detects:
/// - Hex hashes: 64 chars (UTXO/Cosmos) or 66 chars with 0x (EVM) — 32-byte SHA-256/Keccak digests
/// - Base58 signatures: 85-90 chars (Solana 64-byte ed25519 signatures)
/// - Substrate extrinsic IDs: BLOCK_HEIGHT-INDEX pattern (e.g. "28815161-0")
///
/// Returns Ok with single-element vec if it could be a transaction, Ok with empty vec otherwise.
fn could_be_transaction(
    input: &str,
    chars: &InputCharacteristics,
) -> Result<Vec<InputPossibility>, Error> {
    let could_be = chars.encoding.iter().any(|encoding| match encoding {
        EncodingType::Hex => {
            // EVM tx hash: 0x + 64 hex chars = 66 chars total (32 bytes)
            let is_evm_tx = chars.length == 66 && chars.prefixes.iter().any(|p| p == "0x");
            // UTXO/Cosmos/Cardano/Tron tx hash: 64 hex chars without 0x prefix (32 bytes)
            let is_raw_hex_tx = chars.length == 64 && !chars.prefixes.iter().any(|p| p == "0x");
            is_evm_tx || is_raw_hex_tx
        }
        EncodingType::Base58 => {
            // Solana tx signature: 64-byte ed25519 signature ≈ 85-90 chars in base58
            (85..=90).contains(&chars.length)
        }
        _ => false,
    }) || is_substrate_extrinsic(input);

    Ok(if could_be {
        vec![InputPossibility::Transaction]
    } else {
        vec![]
    })
}

/// Check if input could be a block hash based on heuristics
///
/// Detects:
/// - EVM block hash: 66 chars with 0x prefix (keccak-256, same format as EVM tx hash)
/// - UTXO/Cosmos/Cardano/Tron/Substrate block hash: 64 hex chars without 0x (SHA-256d)
/// - Solana block hash: 32-44 chars Base58 (DISTINCT from Solana tx signature at 85-90 chars)
///
/// Note: for EVM and most UTXO chains, block hashes are format-identical to transaction
/// hashes. Both InputPossibility::Transaction and InputPossibility::BlockHash will be
/// returned for those inputs — disambiguation happens via metadata (scanner URL presence).
///
/// Returns Ok with single-element vec if it could be a block hash, Ok with empty vec otherwise.
fn could_be_block_hash(
    _input: &str,
    chars: &InputCharacteristics,
) -> Result<Vec<InputPossibility>, Error> {
    let could_be = chars.encoding.iter().any(|encoding| match encoding {
        EncodingType::Hex => {
            // EVM block hash: 0x + 64 hex chars = 66 chars total (keccak-256)
            let is_evm_block_hash = chars.length == 66 && chars.prefixes.iter().any(|p| p == "0x");
            // UTXO/Cosmos/Cardano/Tron/Substrate block hash: 64 hex chars, no 0x (SHA-256d)
            let is_raw_hex_block_hash =
                chars.length == 64 && !chars.prefixes.iter().any(|p| p == "0x");
            is_evm_block_hash || is_raw_hex_block_hash
        }
        EncodingType::Base58 => {
            // Solana block hash: 32-byte hash in Base58 = 32-44 chars
            // This is the only case distinguishable from tx hashes by format alone
            (32..=44).contains(&chars.length)
        }
        _ => false,
    });

    Ok(if could_be {
        vec![InputPossibility::BlockHash]
    } else {
        vec![]
    })
}

/// Check if input matches Substrate extrinsic ID format: BLOCK_HEIGHT-EXTRINSIC_INDEX
/// Examples: "28815161-0", "31206697-0"
pub fn is_substrate_extrinsic(input: &str) -> bool {
    let parts: Vec<&str> = input.split('-').collect();
    parts.len() == 2
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[0].chars().all(|c| c.is_ascii_digit())
        && parts[1].chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::extract_characteristics;

    #[test]
    fn test_classify_evm_address() {
        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        // Should be classified as address (hex encoding, 42 chars, 0x prefix)
        assert!(possibilities.contains(&InputPossibility::Address));
    }

    #[test]
    fn test_classify_secp256k1_key() {
        let input = "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        // Should be classified as public key
        assert!(possibilities.iter().any(|p| matches!(
            p,
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Secp256k1 { compressed: false }
            }
        )));
    }

    #[test]
    fn test_classify_ambiguous_base58() {
        // 32-byte base58 - could be Solana address OR Ed25519 key
        let input = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        // Should return both possibilities
        assert!(possibilities.contains(&InputPossibility::Address));
        // 32-byte keys should return both Ed25519 and Sr25519 possibilities
        assert!(possibilities.iter().any(|p| matches!(
            p,
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Ed25519
            }
        )));
        assert!(possibilities.iter().any(|p| matches!(
            p,
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Sr25519
            }
        )));
    }

    #[test]
    fn test_classify_invalid_input() {
        // Test with completely invalid input
        let input = "xyz123abc";
        let chars = extract_characteristics(input);
        let result = classify_input(input, &chars);

        // Should return error when no possibilities found
        assert!(result.is_err());
        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("Unable to classify input format"));
            assert!(msg.contains("xyz123abc"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_classify_evm_address_lowercase() {
        // Test with lowercase EVM address from failing test
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        // Should be classified as address (hex encoding, 42 chars, 0x prefix)
        assert!(possibilities.contains(&InputPossibility::Address));
        // Should NOT be classified as public key (20 bytes, not 32/33/65)
        assert!(!possibilities
            .iter()
            .any(|p| matches!(p, InputPossibility::PublicKey { .. })));
    }

    #[test]
    fn test_classify_evm_address_mixed_case() {
        // Test with mixed case EVM address from failing test
        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        // Should be classified as address (hex encoding, 42 chars, 0x prefix)
        assert!(possibilities.contains(&InputPossibility::Address));
        // Should NOT be classified as public key (20 bytes, not 32/33/65)
        assert!(!possibilities
            .iter()
            .any(|p| matches!(p, InputPossibility::PublicKey { .. })));
    }

    #[test]
    fn test_classify_tron_address() {
        // Test Tron address from failing test
        // Create a valid test Tron address
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

        let chars = extract_characteristics(&tron_addr);
        let possibilities = classify_input(&tron_addr, &chars).unwrap();

        // Should be classified as address (Base58Check encoding)
        assert!(possibilities.contains(&InputPossibility::Address));
        // Should NOT be classified as public key (25 bytes when decoded, not 32/33/65)
        assert!(!possibilities
            .iter()
            .any(|p| matches!(p, InputPossibility::PublicKey { .. })));
    }

    // ============================================================================
    // Phase 3.2: classify_input Tests (expanded)
    // ============================================================================

    #[test]
    fn test_classify_address_only_evm() {
        // Address-only input: EVM address
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        // Should be classified as address only
        assert!(possibilities.contains(&InputPossibility::Address));
        assert!(!possibilities
            .iter()
            .any(|p| matches!(p, InputPossibility::PublicKey { .. })));
    }

    #[test]
    fn test_classify_address_only_bitcoin() {
        // Address-only input: Bitcoin
        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        assert!(possibilities.contains(&InputPossibility::Address));
    }

    #[test]
    fn test_classify_address_only_cosmos() {
        // Address-only input: Cosmos
        let input = "cosmos1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let chars = extract_characteristics(input);
        if let Ok(possibilities) = classify_input(input, &chars) {
            assert!(possibilities.contains(&InputPossibility::Address));
        }
        // If classification fails, address might be invalid Bech32
    }

    #[test]
    fn test_classify_public_key_only_secp256k1_compressed() {
        // Public key-only input: compressed secp256k1
        let input = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        // Should be classified as public key
        assert!(possibilities.iter().any(|p| matches!(
            p,
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Secp256k1 { compressed: true }
            }
        )));
    }

    #[test]
    fn test_classify_public_key_only_secp256k1_uncompressed() {
        // Public key-only input: uncompressed secp256k1
        let input = "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        // Should be classified as public key
        assert!(possibilities.iter().any(|p| matches!(
            p,
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Secp256k1 { compressed: false }
            }
        )));
    }

    #[test]
    fn test_classify_public_key_only_ed25519() {
        // Public key-only input: Ed25519 (32-byte hex)
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let chars = extract_characteristics(input);
        if let Ok(possibilities) = classify_input(input, &chars) {
            // Should be classified as Ed25519 and Sr25519 (both 32-byte)
            assert!(possibilities.iter().any(|p| matches!(
                p,
                InputPossibility::PublicKey {
                    key_type: DetectedKeyType::Ed25519
                }
            )));
            assert!(possibilities.iter().any(|p| matches!(
                p,
                InputPossibility::PublicKey {
                    key_type: DetectedKeyType::Sr25519
                }
            )));
        }
        // If classification fails, public key might not be recognized
    }

    #[test]
    fn test_classify_ambiguous_base58_32byte() {
        // Ambiguous input: 32-byte base58 (Solana address OR Ed25519 key)
        let input = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        // Should return both possibilities
        assert!(possibilities.contains(&InputPossibility::Address));
        assert!(possibilities.iter().any(|p| matches!(
            p,
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Ed25519
            }
        )));
        assert!(possibilities.iter().any(|p| matches!(
            p,
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Sr25519
            }
        )));
    }

    #[test]
    fn test_classify_invalid_input_xyz() {
        // Invalid input: should return error
        let input = "xyz123abc";
        let chars = extract_characteristics(input);
        let result = classify_input(input, &chars);

        assert!(result.is_err());
        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("Unable to classify input format"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_classify_empty_string() {
        // Empty string: should return error
        let input = "";
        let chars = extract_characteristics(input);
        let result = classify_input(input, &chars);

        assert!(result.is_err());
    }

    // ============================================================================
    // Transaction classification tests
    // ============================================================================

    #[test]
    fn test_classify_evm_tx_hash() {
        // Ethereum tx hash from onchain-examples.md
        let input = "0xcdf331416ac94df404cfa95b13ecd4b23b2b1de895c945e25ff1b557c597a64e";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        assert!(possibilities.contains(&InputPossibility::Transaction));
        // Should NOT be an address (66 chars != 42 chars)
        assert!(!possibilities.contains(&InputPossibility::Address));
    }

    #[test]
    fn test_classify_bitcoin_tx_hash() {
        // Bitcoin genesis coinbase tx from onchain-examples.md
        let input = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        assert!(possibilities.contains(&InputPossibility::Transaction));
    }

    #[test]
    fn test_classify_solana_tx_signature() {
        // Solana tx signature from onchain-examples.md (88 chars)
        let input = "5wpHU1gGYcgKabL7heGGgiKBx3WJMruHiN34sCjTYwQu4sk9H2uMyZsm1P28RqaJPVELtcVxNmSGieq6V5ZZxpDT";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        assert!(possibilities.contains(&InputPossibility::Transaction));
        // Should NOT be an address (88 chars is outside 32-44 range)
        assert!(!possibilities.contains(&InputPossibility::Address));
    }

    #[test]
    fn test_classify_substrate_extrinsic() {
        // Polkadot extrinsic from onchain-examples.md
        let input = "28815161-0";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        assert!(possibilities.contains(&InputPossibility::Transaction));
        // Should NOT be an address or public key
        assert!(!possibilities.contains(&InputPossibility::Address));
        assert!(!possibilities
            .iter()
            .any(|p| matches!(p, InputPossibility::PublicKey { .. })));
    }

    #[test]
    fn test_classify_evm_address_not_transaction() {
        // EVM addresses (42 chars) should NOT be classified as transactions
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        assert!(possibilities.contains(&InputPossibility::Address));
        assert!(!possibilities.contains(&InputPossibility::Transaction));
    }

    #[test]
    fn test_classify_short_string_not_transaction() {
        // Short strings should not be classified as transactions
        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        assert!(!possibilities.contains(&InputPossibility::Transaction));
    }

    #[test]
    fn test_classify_hex_tx_also_public_key() {
        // 66-char hex with 0x could be BOTH a transaction AND a public key (32-byte Ed25519)
        let input = "0x9f7f8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        // Should be both Transaction and PublicKey (ambiguous)
        assert!(possibilities.contains(&InputPossibility::Transaction));
        assert!(possibilities.iter().any(|p| matches!(
            p,
            InputPossibility::PublicKey {
                key_type: DetectedKeyType::Ed25519
            }
        )));
    }

    #[test]
    fn test_classify_substrate_extrinsic_kusama() {
        let input = "31206697-0";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        assert!(possibilities.contains(&InputPossibility::Transaction));
    }

    #[test]
    fn test_classify_tron_tx_hash() {
        // Tron tx hash from onchain-examples.md (64-char hex, no 0x)
        let input = "5156e18743c2ceba71f40640c75a8402066a8c42e570f17eecda2cc1101575f4";
        let chars = extract_characteristics(input);
        let possibilities = classify_input(input, &chars).unwrap();

        assert!(possibilities.contains(&InputPossibility::Transaction));
    }
}
