use crate::models::chain::ChainConfig;
use crate::registry::{
    AddressMetadata, ChainMetadata, CharSet, EncodingType, Network, PublicKeyMetadata,
    PublicKeyType,
};

/// Convert encoding string to EncodingType
fn encoding_str_to_enum(s: &str) -> EncodingType {
    match s {
        "hex" => EncodingType::Hex,
        "base58" => EncodingType::Base58,
        "base58check" => EncodingType::Base58Check,
        "bech32" => EncodingType::Bech32,
        "bech32m" => EncodingType::Bech32m,
        "ss58" => EncodingType::SS58,
        _ => EncodingType::Hex, // Default
    }
}

/// Convert curve string to PublicKeyType
fn curve_str_to_key_type(s: &str) -> PublicKeyType {
    match s {
        "secp256k1" => PublicKeyType::Secp256k1,
        "ed25519" => PublicKeyType::Ed25519,
        "sr25519" => PublicKeyType::Sr25519,
        _ => PublicKeyType::Secp256k1, // Default
    }
}

/// Convert JSON ChainConfig to Rust ChainMetadata
pub fn convert_chain_config(config: ChainConfig) -> Result<ChainMetadata, String> {
    // Create address metadata based on pipeline type with proper characteristics
    let address_formats = match config.address_pipeline.as_str() {
        "evm" => vec![AddressMetadata {
            encoding: EncodingType::Hex,
            char_set: Some(CharSet::Hex),
            exact_length: Some(42), // 0x + 40 hex chars
            length_range: None,
            prefixes: vec!["0x".to_string()],
            hrps: vec![],
            version_bytes: vec![],
            checksum: Some(crate::registry::ChecksumType::EIP55),
            network: Some(Network::Mainnet),
        }],
        "bitcoin_p2pkh" => {
            // Extract version byte from address_params
            let version_byte = config
                .address_params
                .get("version_byte")
                .and_then(|v| v.as_u64())
                .map(|v| v as u8)
                .unwrap_or(0);
            // Bitcoin supports both P2PKH (version 0) and P2SH (version 5)
            // Note: Prefix is determined by version byte, so we don't require prefix match
            // For Bitcoin (version 0) it's "1", for Dogecoin (version 30) it's "D", for Litecoin (version 48) it's "L"
            let mut formats = vec![AddressMetadata {
                encoding: EncodingType::Base58Check,
                char_set: Some(CharSet::Base58),
                exact_length: Some(34), // Standard P2PKH address length
                length_range: None,
                prefixes: vec![], // Empty - version byte validation is sufficient
                hrps: vec![],
                version_bytes: vec![version_byte], // P2PKH version (0 for Bitcoin, 30 for Dogecoin, 48 for Litecoin)
                checksum: Some(crate::registry::ChecksumType::Base58Check),
                network: Some(Network::Mainnet),
            }];
            // Add P2SH format (version 5 for Bitcoin mainnet)
            // Only add P2SH for Bitcoin (version_byte == 0), not for Dogecoin/Litecoin
            if version_byte == 0 {
                formats.push(AddressMetadata {
                    encoding: EncodingType::Base58Check,
                    char_set: Some(CharSet::Base58),
                    exact_length: Some(34), // Standard P2SH address length
                    length_range: None,
                    prefixes: vec![], // Empty - version byte validation is sufficient
                    hrps: vec![],
                    version_bytes: vec![5], // P2SH version (5 for Bitcoin mainnet)
                    checksum: Some(crate::registry::ChecksumType::Base58Check),
                    network: Some(Network::Mainnet),
                });
            }
            // Add Bech32 format for Bitcoin
            formats.push(AddressMetadata {
                encoding: EncodingType::Bech32,
                char_set: Some(CharSet::Base32),
                exact_length: None,
                length_range: Some((14, 74)), // Bech32 addresses can vary
                prefixes: vec![],
                hrps: vec!["bc".to_string()], // Mainnet HRP (bech32::decode returns "bc", not "bc1")
                version_bytes: vec![],
                checksum: Some(crate::registry::ChecksumType::Bech32),
                network: Some(Network::Mainnet),
            });
            formats
        }
        "bitcoin_bech32" => vec![AddressMetadata {
            encoding: EncodingType::Bech32,
            char_set: Some(CharSet::Base32),
            exact_length: None,
            length_range: Some((14, 74)), // Bech32 addresses can vary
            prefixes: vec![],
            hrps: vec!["bc".to_string()], // Mainnet HRP (bech32::decode returns "bc", not "bc1")
            version_bytes: vec![],
            checksum: Some(crate::registry::ChecksumType::Bech32),
            network: Some(Network::Mainnet),
        }],
        "cosmos" => {
            // Extract HRP from address_params
            let hrps: Vec<String> = config
                .address_params
                .get("hrp")
                .and_then(|h| h.as_str())
                .map(|h| vec![h.to_string()])
                .unwrap_or_else(|| {
                    // Try to get from array
                    config
                        .address_params
                        .get("hrps")
                        .and_then(|h| h.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default()
                });
            vec![AddressMetadata {
                encoding: EncodingType::Bech32,
                char_set: Some(CharSet::Base32),
                exact_length: None,
                length_range: Some((20, 90)), // Cosmos addresses vary
                prefixes: vec![],
                hrps,
                version_bytes: vec![],
                checksum: Some(crate::registry::ChecksumType::Bech32),
                network: Some(Network::Mainnet),
            }]
        }
        "cardano" => {
            // Extract HRPs from address_params
            let hrps: Vec<String> = config
                .address_params
                .get("hrps")
                .and_then(|h| h.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            vec![AddressMetadata {
                encoding: EncodingType::Bech32,
                char_set: Some(CharSet::Base32),
                exact_length: None,
                length_range: Some((50, 120)), // Cardano addresses vary
                prefixes: vec![],
                hrps,
                version_bytes: vec![],
                checksum: Some(crate::registry::ChecksumType::Bech32),
                network: Some(Network::Mainnet),
            }]
        }
        "solana" => vec![AddressMetadata {
            encoding: EncodingType::Base58,
            char_set: Some(CharSet::Base58),
            exact_length: None,
            length_range: Some((32, 44)), // Solana addresses vary
            prefixes: vec![],
            hrps: vec![],
            version_bytes: vec![],
            checksum: None,
            network: Some(Network::Mainnet),
        }],
        "ss58" => vec![AddressMetadata {
            encoding: EncodingType::SS58,
            char_set: Some(CharSet::Base58),
            exact_length: None,
            length_range: Some((35, 48)), // SS58 addresses vary
            prefixes: vec![],
            hrps: vec![],
            version_bytes: vec![],
            checksum: Some(crate::registry::ChecksumType::SS58),
            network: Some(Network::Mainnet),
        }],
        "tron" => vec![AddressMetadata {
            encoding: EncodingType::Base58Check,
            char_set: Some(CharSet::Base58),
            exact_length: Some(34), // Tron address length
            length_range: None,
            prefixes: vec![],
            hrps: vec![],
            version_bytes: vec![0x41], // Tron version byte
            checksum: Some(crate::registry::ChecksumType::Base58Check),
            network: Some(Network::Mainnet),
        }],
        _ => vec![AddressMetadata {
            encoding: EncodingType::Hex,
            char_set: None,
            exact_length: None,
            length_range: None,
            prefixes: vec![],
            hrps: vec![],
            version_bytes: vec![],
            checksum: None,
            network: Some(Network::Mainnet),
        }],
    };

    // Convert public key formats
    let public_key_formats: Vec<PublicKeyMetadata> = config
        .public_key_formats
        .into_iter()
        .map(|pk_fmt| PublicKeyMetadata {
            encoding: encoding_str_to_enum(&pk_fmt.encoding),
            char_set: match pk_fmt.encoding.as_str() {
                "hex" => Some(CharSet::Hex),
                "base58" => Some(CharSet::Base58),
                _ => None,
            },
            exact_length: pk_fmt.exact_length,
            length_range: pk_fmt.length_range,
            prefixes: pk_fmt.prefixes,
            hrps: vec![],
            key_type: curve_str_to_key_type(&config.curve),
            checksum: None,
        })
        .collect();

    Ok(ChainMetadata {
        id: config.id.clone(),
        name: config.name,
        scanner_url_template: config.scanner_url_template,
        address_formats,
        public_key_formats,
    })
}
