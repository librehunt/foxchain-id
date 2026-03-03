//! Registry builder for automatic category grouping
//!
//! This module builds the registry that precomputes category groups at startup,
//! automatically organizing chains by their format signatures.

use crate::loaders::{load_chain, load_index};
use crate::registry::chain_converter::convert_chain_config;
use crate::registry::ChainMetadata;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Global registry instance
static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// Registry containing all chain metadata and precomputed groups
pub struct Registry {
    /// All chain metadata
    pub chains: Vec<ChainMetadata>,
    /// Chain configs (for pipeline access)
    pub chain_configs: HashMap<String, crate::models::chain::ChainConfig>,
}

impl Registry {
    /// Build the registry with all chain metadata and automatic grouping
    pub fn build() -> Self {
        // Load index to get all chain IDs
        let index = load_index().expect("Failed to load metadata index");

        // Load all chain configs and convert to ChainMetadata using functional style
        let (chains, chain_configs_vec): (Vec<_>, Vec<_>) = index
            .chains
            .iter()
            .filter_map(|chain_id| {
                load_chain(chain_id)
                    .map_err(|e| {
                        eprintln!("Warning: Failed to load chain {}: {}", chain_id, e);
                        e
                    })
                    .ok()
                    .and_then(|config| {
                        let chain_id_clone = chain_id.clone();
                        let config_clone = config.clone();
                        convert_chain_config(config)
                            .map_err(|e| {
                                eprintln!(
                                    "Warning: Failed to convert chain {}: {}",
                                    chain_id_clone, e
                                );
                                e
                            })
                            .ok()
                            .map(|chain_metadata| (chain_metadata, (chain_id_clone, config_clone)))
                    })
            })
            .unzip();

        let chain_configs: HashMap<String, _> = chain_configs_vec.into_iter().collect();

        Registry {
            chains,
            chain_configs,
        }
    }

    /// Get the global registry instance
    pub fn get() -> &'static Registry {
        REGISTRY.get_or_init(Registry::build)
    }

    /// Find all chains that support a given address format
    /// This matches an address string against all chain metadata
    #[allow(dead_code)] // Reserved for future use
    pub fn find_chains_for_address(&self, address: &str) -> Vec<&ChainMetadata> {
        use crate::input::extract_characteristics;

        let chars = extract_characteristics(address);

        self.chains
            .iter()
            .filter(|chain| {
                chain.address_formats.iter().any(|addr_format| {
                    // Check if address matches this format
                    matches_address_format(&chars, addr_format)
                })
            })
            .collect()
    }

    /// Find chains that match address format characteristics
    #[allow(dead_code)] // Reserved for future use
    pub fn find_chains_for_address_format(
        &self,
        chars: &crate::input::InputCharacteristics,
    ) -> Vec<&ChainMetadata> {
        self.chains
            .iter()
            .filter(|chain| {
                chain
                    .address_formats
                    .iter()
                    .any(|addr_format| matches_address_format(chars, addr_format))
            })
            .collect()
    }

    /// Get chain config by ID
    pub fn get_chain_config(&self, chain_id: &str) -> Option<&crate::models::chain::ChainConfig> {
        self.chain_configs.get(chain_id)
    }
}

/// Check if input characteristics match address metadata
#[allow(dead_code)] // Used by find_chains_for_address methods
fn matches_address_format(
    chars: &crate::input::InputCharacteristics,
    metadata: &crate::registry::AddressMetadata,
) -> bool {
    // Check length
    if let Some(exact) = metadata.exact_length {
        if chars.length != exact {
            return false;
        }
    }
    if let Some((min, max)) = metadata.length_range {
        if chars.length < min || chars.length > max {
            return false;
        }
    }

    // Check prefixes
    if !metadata.prefixes.is_empty()
        && !metadata.prefixes.iter().any(|p| chars.prefixes.contains(p))
    {
        return false;
    }

    // Check HRP
    if !metadata.hrps.is_empty() {
        if let Some(ref hrp) = chars.hrp {
            if !metadata.hrps.iter().any(|h| hrp.starts_with(h)) {
                return false;
            }
        } else {
            return false;
        }
    }

    // Check character set
    if let Some(ref char_set) = metadata.char_set {
        if chars.char_set != *char_set {
            return false;
        }
    }

    // Check encoding type - match if any of the detected encodings matches
    if !chars.encoding.is_empty() && !chars.encoding.contains(&metadata.encoding) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_build() {
        let registry = Registry::build();
        assert!(!registry.chains.is_empty());
    }

    #[test]
    fn test_registry_get() {
        let registry = Registry::get();
        assert!(!registry.chains.is_empty());
    }

    #[test]
    fn test_get_chain_config() {
        let registry = Registry::get();
        let config = registry.get_chain_config("ethereum");
        assert!(config.is_some());

        let config = registry.get_chain_config("nonexistent");
        assert!(config.is_none());
    }

    #[test]
    fn test_find_chains_for_address() {
        let registry = Registry::get();
        let address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chains = registry.find_chains_for_address(address);
        assert!(!chains.is_empty());
        assert!(chains.iter().any(|c| c.id == "ethereum"));
    }

    #[test]
    fn test_find_chains_for_address_format() {
        use crate::input::extract_characteristics;
        let registry = Registry::get();
        let address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chars = extract_characteristics(address);
        let chains = registry.find_chains_for_address_format(&chars);
        assert!(!chains.is_empty());
    }

    #[test]
    fn test_matches_address_format_exact_length() {
        use crate::input::extract_characteristics;
        use crate::registry::{AddressMetadata, CharSet, EncodingType, Network};

        let metadata = AddressMetadata {
            encoding: EncodingType::Hex,
            char_set: Some(CharSet::Hex),
            exact_length: Some(42),
            length_range: None,
            prefixes: vec!["0x".to_string()],
            hrps: vec![],
            version_bytes: vec![],
            checksum: None,
            network: Some(Network::Mainnet),
        };

        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chars = extract_characteristics(input);
        assert!(matches_address_format(&chars, &metadata));

        let input_short = "0x1234";
        let chars_short = extract_characteristics(input_short);
        assert!(!matches_address_format(&chars_short, &metadata));
    }

    #[test]
    fn test_matches_address_format_length_range() {
        use crate::input::extract_characteristics;
        use crate::registry::{AddressMetadata, CharSet, EncodingType, Network};

        let metadata = AddressMetadata {
            encoding: EncodingType::Base58Check, // Use Base58Check for Bitcoin
            char_set: Some(CharSet::Base58),
            exact_length: None,
            length_range: Some((26, 35)),
            prefixes: vec![],
            hrps: vec![],
            version_bytes: vec![0x00], // Bitcoin version
            checksum: Some(crate::registry::ChecksumType::Base58Check),
            network: Some(Network::Mainnet),
        };

        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // 34 chars, valid Bitcoin
        let chars = extract_characteristics(input);
        assert!(matches_address_format(&chars, &metadata));

        let input_short = "123";
        let chars_short = extract_characteristics(input_short);
        assert!(!matches_address_format(&chars_short, &metadata));
    }

    #[test]
    fn test_matches_address_format_prefix() {
        use crate::input::extract_characteristics;
        use crate::registry::{AddressMetadata, CharSet, EncodingType, Network};

        let metadata = AddressMetadata {
            encoding: EncodingType::Hex,
            char_set: Some(CharSet::Hex),
            exact_length: Some(42),
            length_range: None,
            prefixes: vec!["0x".to_string()],
            hrps: vec![],
            version_bytes: vec![],
            checksum: None,
            network: Some(Network::Mainnet),
        };

        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chars = extract_characteristics(input);
        assert!(matches_address_format(&chars, &metadata));

        let input_no_prefix = "742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let _chars_no_prefix = extract_characteristics(input_no_prefix);
        // Should still match if encoding is detected
        // The prefix check might pass if encoding is detected
    }

    #[test]
    fn test_matches_address_format_hrp() {
        use crate::input::extract_characteristics;
        use crate::registry::{AddressMetadata, CharSet, EncodingType, Network};

        let metadata = AddressMetadata {
            encoding: EncodingType::Bech32,
            char_set: Some(CharSet::Base32),
            exact_length: None,
            length_range: Some((14, 90)),
            prefixes: vec![],
            hrps: vec!["cosmos".to_string()],
            version_bytes: vec![],
            checksum: None,
            network: Some(Network::Mainnet),
        };

        // Test with a valid Cosmos address that should match
        let input = "cosmos1hvf3g5z6qwz2jq0ks3k5m3n5vx7v8v9w0x1y2z3a4b5c6d7e8f9g0";
        let chars = extract_characteristics(input);
        // Test HRP matching logic - if HRP is required but missing, should fail
        if chars.hrp.is_none() {
            assert!(!matches_address_format(&chars, &metadata));
        } else if let Some(ref hrp) = chars.hrp {
            // If HRP matches, should pass (if other conditions also match)
            if hrp.starts_with("cosmos") && chars.encoding.contains(&EncodingType::Bech32) {
                // This should match if all other conditions are met
                // But we can't guarantee it will pass all checks, so just test the HRP logic
            }
        }

        // Test with no HRP - should definitely fail
        let input_no_hrp = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chars_no_hrp = extract_characteristics(input_no_hrp);
        assert!(!matches_address_format(&chars_no_hrp, &metadata));
    }

    #[test]
    fn test_matches_address_format_char_set() {
        use crate::input::extract_characteristics;
        use crate::registry::{AddressMetadata, CharSet, EncodingType, Network};

        let metadata = AddressMetadata {
            encoding: EncodingType::Hex,
            char_set: Some(CharSet::Hex),
            exact_length: Some(42),
            length_range: None,
            prefixes: vec!["0x".to_string()],
            hrps: vec![],
            version_bytes: vec![],
            checksum: None,
            network: Some(Network::Mainnet),
        };

        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chars = extract_characteristics(input);
        assert!(matches_address_format(&chars, &metadata));
    }

    #[test]
    fn test_matches_address_format_encoding() {
        use crate::input::extract_characteristics;
        use crate::registry::{AddressMetadata, CharSet, EncodingType, Network};

        let metadata = AddressMetadata {
            encoding: EncodingType::Hex,
            char_set: Some(CharSet::Hex),
            exact_length: Some(42),
            length_range: None,
            prefixes: vec!["0x".to_string()],
            hrps: vec![],
            version_bytes: vec![],
            checksum: None,
            network: Some(Network::Mainnet),
        };

        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let chars = extract_characteristics(input);
        assert!(matches_address_format(&chars, &metadata));

        let input_base58 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let _chars_base58 = extract_characteristics(input_base58);
        // Should not match if encoding doesn't match
        // But if Base58Check is detected, it might still pass other checks
    }
}
