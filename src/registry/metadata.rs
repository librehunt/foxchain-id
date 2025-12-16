//! Metadata structures for chain and format definitions
//!
//! This module defines the foundational metadata structures that drive the
//! entire detection pipeline. All format detection logic is declarative,
//! eliminating the need for hardcoded heuristics.

/// Metadata for a blockchain chain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainMetadata {
    /// Chain identifier (string ID from JSON metadata)
    pub id: String,
    /// Human-readable chain name
    pub name: String,
    /// Scanner URL template with {address} placeholder (optional)
    pub scanner_url_template: Option<String>,
    /// All supported address formats for this chain
    pub address_formats: Vec<AddressMetadata>,
    /// All supported public key formats for this chain
    pub public_key_formats: Vec<PublicKeyMetadata>,
}

/// Metadata for an address format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressMetadata {
    /// Encoding type used for this address format
    pub encoding: EncodingType,
    /// Character set used (if specific)
    pub char_set: Option<CharSet>,
    /// Exact length requirement (if any)
    pub exact_length: Option<usize>,
    /// Length range requirement (if any)
    pub length_range: Option<(usize, usize)>,
    /// Required prefixes (empty vec = no prefix requirement)
    pub prefixes: Vec<String>,
    /// Required HRPs for Bech32/Bech32m (empty vec = no HRP requirement)
    pub hrps: Vec<String>,
    /// Version bytes for Base58Check formats (empty vec = no version requirement)
    pub version_bytes: Vec<u8>,
    /// Checksum type (if any)
    pub checksum: Option<ChecksumType>,
    /// Network (mainnet/testnet)
    pub network: Option<Network>,
}

impl AddressMetadata {
    /// Validate raw input against this address metadata
    ///
    /// Performs structural validation: checksums, decodes, prefix/HRP rules.
    /// This is the metadata-driven validation stage.
    pub fn validate_raw(&self, raw: &str, chars: &crate::input::InputCharacteristics) -> bool {
        // Check encoding type matches - try all detected encodings
        if !chars.encoding.is_empty() && !chars.encoding.contains(&self.encoding) {
            return false;
        }

        // Check length
        if let Some(exact) = self.exact_length {
            if chars.length != exact {
                return false;
            }
        }
        if let Some((min, max)) = self.length_range {
            if chars.length < min || chars.length > max {
                return false;
            }
        }

        // Check prefixes
        // For Base58Check with version bytes, prefix is determined by version byte
        // so we skip prefix check and rely on version byte validation instead
        if !self.prefixes.is_empty() {
            let skip_prefix_check = matches!(self.encoding, EncodingType::Base58Check)
                && !self.version_bytes.is_empty();
            if !skip_prefix_check && !self.prefixes.iter().any(|p| chars.prefixes.contains(p)) {
                return false;
            }
        }

        // Check HRP
        if !self.hrps.is_empty() {
            if let Some(ref hrp) = chars.hrp {
                if !self.hrps.iter().any(|h| hrp.starts_with(h)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Structural validation based on encoding and checksum
        match self.encoding {
            EncodingType::Hex => {
                // EVM: For hex encoding, just validate it's valid hex
                // Don't enforce EIP55 checksum here - that's done in detect_address
                // Lowercase addresses are structurally valid and will be normalized later
                use crate::shared::encoding::hex;
                hex::decode(raw).is_ok()
            }
            EncodingType::Bech32 | EncodingType::Bech32m => {
                use crate::shared::encoding::bech32 as bech32_encoding;
                bech32_encoding::decode(raw).is_ok()
            }
            EncodingType::Base58Check => {
                use crate::shared::checksum::base58check;
                if let Some((version, _)) = base58check::validate(raw).unwrap_or(None) {
                    // Check version bytes if specified
                    if !self.version_bytes.is_empty() {
                        self.version_bytes.contains(&version)
                    } else {
                        true
                    }
                } else {
                    false
                }
            }
            EncodingType::SS58 => {
                use crate::shared::encoding::ss58;
                ss58::decode(raw).is_ok()
            }
            EncodingType::Base58 => {
                // Base58 validation - just check if it's valid Base58
                use crate::shared::encoding::base58;
                base58::decode(raw).is_ok()
            }
        }
    }
}

/// Metadata for a public key format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyMetadata {
    /// Encoding type used for this public key format
    pub encoding: EncodingType,
    /// Character set used (if specific)
    pub char_set: Option<CharSet>,
    /// Exact length requirement (if any)
    pub exact_length: Option<usize>,
    /// Length range requirement (if any)
    pub length_range: Option<(usize, usize)>,
    /// Required prefixes (empty vec = no prefix requirement)
    pub prefixes: Vec<String>,
    /// Required HRPs for Bech32/Bech32m (empty vec = no HRP requirement)
    pub hrps: Vec<String>,
    /// Public key type (secp256k1, Ed25519, sr25519)
    pub key_type: PublicKeyType,
    /// Checksum type (if any)
    pub checksum: Option<ChecksumType>,
}

/// Encoding type for addresses and public keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingType {
    /// Hexadecimal encoding (with or without 0x prefix)
    Hex,
    /// Base58 encoding (no checksum)
    Base58,
    /// Base58Check encoding (with checksum)
    Base58Check,
    /// Bech32 encoding
    Bech32,
    /// Bech32m encoding
    Bech32m,
    /// SS58 encoding (Substrate)
    SS58,
}

/// Character set used in the encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CharSet {
    /// Hexadecimal characters (0-9, a-f, A-F)
    Hex,
    /// Base58 characters (alphanumeric excluding 0, O, I, l)
    Base58,
    /// Base32 characters (used in Bech32)
    Base32,
    /// Alphanumeric characters
    Alphanumeric,
}

/// Checksum type used for validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)] // Variants used in pattern matching via metadata
pub enum ChecksumType {
    /// EIP-55 checksum (Ethereum)
    EIP55,
    /// Base58Check checksum (Bitcoin, etc.)
    Base58Check,
    /// Bech32 checksum
    Bech32,
    /// Bech32m checksum
    Bech32m,
    /// SS58 checksum (Substrate)
    SS58,
}

/// Network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Mainnet
    Mainnet,
    /// Testnet
    #[allow(dead_code)] // Reserved for future use
    Testnet,
}

/// Public key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicKeyType {
    /// secp256k1 public key (33 or 65 bytes)
    Secp256k1,
    /// Ed25519 public key (32 bytes)
    Ed25519,
    /// sr25519 public key (32 bytes)
    #[allow(dead_code)] // Reserved for future use
    Sr25519,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::extract_characteristics;

    #[test]
    fn test_validate_raw_hex_encoding_mismatch() {
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

        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // Base58, not hex
        let chars = extract_characteristics(input);

        assert!(!metadata.validate_raw(input, &chars));
    }

    #[test]
    fn test_validate_raw_length_mismatch() {
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

        let input = "0x1234"; // Too short
        let chars = extract_characteristics(input);

        assert!(!metadata.validate_raw(input, &chars));
    }

    #[test]
    fn test_validate_raw_length_range() {
        let metadata = AddressMetadata {
            encoding: EncodingType::Base58Check, // Use Base58Check for Bitcoin address
            char_set: Some(CharSet::Base58),
            exact_length: None,
            length_range: Some((26, 35)),
            prefixes: vec![],
            hrps: vec![],
            version_bytes: vec![0x00], // Bitcoin P2PKH version
            checksum: Some(ChecksumType::Base58Check),
            network: Some(Network::Mainnet),
        };

        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // 34 chars, within range, valid Bitcoin address
        let chars = extract_characteristics(input);

        assert!(metadata.validate_raw(input, &chars));
    }

    #[test]
    fn test_validate_raw_length_range_out_of_bounds() {
        let metadata = AddressMetadata {
            encoding: EncodingType::Base58,
            char_set: Some(CharSet::Base58),
            exact_length: None,
            length_range: Some((26, 35)),
            prefixes: vec![],
            hrps: vec![],
            version_bytes: vec![],
            checksum: None,
            network: Some(Network::Mainnet),
        };

        let input = "123"; // Too short
        let chars = extract_characteristics(input);

        assert!(!metadata.validate_raw(input, &chars));
    }

    #[test]
    fn test_validate_raw_hrp_mismatch() {
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

        let input = "osmo1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"; // Wrong HRP (osmo, not cosmos)
        let chars = extract_characteristics(input);

        assert!(!metadata.validate_raw(input, &chars));
    }

    #[test]
    fn test_validate_raw_hrp_required_but_missing() {
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

        let input = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"; // No HRP
        let chars = extract_characteristics(input);

        assert!(!metadata.validate_raw(input, &chars));
    }

    #[test]
    fn test_validate_raw_base58check_version_bytes() {
        let metadata = AddressMetadata {
            encoding: EncodingType::Base58Check,
            char_set: Some(CharSet::Base58),
            exact_length: None,
            length_range: Some((26, 35)),
            prefixes: vec!["1".to_string()], // Prefix check skipped when version_bytes present
            hrps: vec![],
            version_bytes: vec![0x00], // Bitcoin P2PKH version byte
            checksum: Some(ChecksumType::Base58Check),
            network: Some(Network::Mainnet),
        };

        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // Valid Bitcoin P2PKH
        let chars = extract_characteristics(input);

        assert!(metadata.validate_raw(input, &chars));
    }

    #[test]
    fn test_validate_raw_base58check_wrong_version() {
        let metadata = AddressMetadata {
            encoding: EncodingType::Base58Check,
            char_set: Some(CharSet::Base58),
            exact_length: None,
            length_range: Some((26, 35)),
            prefixes: vec![],
            hrps: vec![],
            version_bytes: vec![0x05], // P2SH version byte
            checksum: Some(ChecksumType::Base58Check),
            network: Some(Network::Mainnet),
        };

        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // P2PKH (version 0), not P2SH
        let chars = extract_characteristics(input);

        assert!(!metadata.validate_raw(input, &chars));
    }

    #[test]
    fn test_validate_raw_invalid_hex() {
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

        let input = "0xgggggggggggggggggggggggggggggggggggggggg"; // Invalid hex
        let chars = extract_characteristics(input);

        assert!(!metadata.validate_raw(input, &chars));
    }

    #[test]
    fn test_validate_raw_invalid_bech32() {
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

        let input = "cosmos1invalid"; // Invalid Bech32
        let chars = extract_characteristics(input);

        assert!(!metadata.validate_raw(input, &chars));
    }
}
