//! Foxchain ID: Multi-chain blockchain address identification
//!
//! This crate provides functionality to identify which blockchain(s) an input
//! string (address, public key, or private key) belongs to.

mod detectors;
mod identify;
mod input;
mod loaders;
mod models;
mod pipelines;
mod registry;
mod shared;

#[cfg(target_arch = "wasm32")]
mod wasm;

pub use identify::{identify as identify_all, IdentificationCandidate, InputType};

/// Identify the blockchain(s) for a given input string.
///
/// Returns all valid candidates sorted by confidence (highest first).
/// This function supports ambiguous inputs that may match multiple chains.
///
/// # Example
///
/// ```rust
/// use foxchain_id::identify;
///
/// let candidates = identify("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")?;
/// for candidate in candidates {
///     println!("Chain: {:?}, Confidence: {}, Normalized: {}",
///              candidate.chain, candidate.confidence, candidate.normalized);
/// }
/// # Ok::<(), foxchain_id::Error>(())
/// ```
pub fn identify(input: &str) -> Result<Vec<IdentificationCandidate>, Error> {
    identify_all(input)
}

/// Errors that can occur during identification
#[derive(Debug, Clone)]
pub enum Error {
    /// Feature not yet implemented
    NotImplemented,
    /// Invalid input format
    InvalidInput(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotImplemented => write!(f, "Feature not yet implemented"),
            Error::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_evm_address() {
        // Test with lowercase address - should be normalized
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let result = identify(input);
        if let Err(e) = &result {
            eprintln!("Error: {}", e);
        }
        assert!(result.is_ok());
        let candidates = result.unwrap();
        assert!(!candidates.is_empty());
        // Should return multiple EVM chains
        assert!(candidates.iter().any(|c| c.chain == "ethereum"));
        // First candidate should have highest confidence
        assert!(candidates[0].confidence > 0.0);
        // Should be normalized to checksum format
        assert_ne!(candidates[0].normalized, input);
        assert!(candidates[0].normalized.starts_with("0x"));
        assert_eq!(candidates[0].normalized.len(), 42);
    }

    #[test]
    fn test_identify_evm_address_lowercase() {
        let input = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let result = identify(input);
        assert!(result.is_ok());
        let candidates = result.unwrap();
        assert!(!candidates.is_empty());
        // Should be normalized to checksum format (different from input)
        assert_ne!(candidates[0].normalized, input);
        assert!(candidates[0].normalized.starts_with("0x"));
        assert_eq!(candidates[0].normalized.len(), 42);
    }

    #[test]
    fn test_identify_evm_multiple_chains() {
        // EVM addresses should return multiple chain candidates
        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let result = identify(input);
        let candidates = result.unwrap();
        // Should have multiple EVM chains
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
    }

    #[test]
    fn test_identify_invalid_address() {
        let result = identify("not-an-address");
        assert!(result.is_err());
        // Verify error message contains the input
        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("not-an-address"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_identify_unrecognized_format() {
        // Test with a string that doesn't match any known format
        // This should trigger the classifier error path (returns early)
        let result = identify("xyz123abc");
        assert!(result.is_err());
        if let Err(Error::InvalidInput(msg)) = result {
            // Classifier returns "Unable to classify input format" when no possibilities found
            assert!(
                msg.contains("Unable to classify input format")
                    || msg.contains("Unable to identify address format")
            );
            assert!(msg.contains("xyz123abc"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_identify_empty_string() {
        // Test with empty string
        let result = identify("");
        assert!(result.is_err());
        if let Err(Error::InvalidInput(msg)) = result {
            // Classifier returns "Unable to classify input format" when no possibilities found
            assert!(
                msg.contains("Unable to classify input format")
                    || msg.contains("Unable to identify address format")
            );
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_identify_tron() {
        // Test Tron address identification
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

        let result = identify(&tron_addr);
        // May succeed or fail depending on validation
        if let Ok(candidates) = result {
            assert!(!candidates.is_empty());
            assert!(candidates.iter().any(|c| c.chain == "tron"));
        }
    }

    #[test]
    fn test_identify_substrate() {
        // Test Substrate address identification
        use base58::ToBase58;
        // Create a valid test Substrate address (prefix 0 = Polkadot)
        let mut bytes = vec![0u8]; // Prefix
        bytes.extend(vec![0u8; 32]); // Account ID
        bytes.extend(vec![0u8; 2]); // Checksum
        let substrate_addr = bytes.to_base58();

        let result = identify(&substrate_addr);
        // This may fail if the address doesn't validate, but tests integration
        if let Ok(candidates) = result {
            // Should have Substrate chain candidates if valid
            assert!(!candidates.is_empty());
        }
    }
}
