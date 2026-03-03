//! Base58Check validation
//!
//! Base58Check is used by Bitcoin and Tron addresses.
//! Format: 25 bytes total (1 version + 20 hash + 4 checksum)

use crate::shared::crypto::hash::double_sha256;
use crate::shared::encoding::base58::decode;
use crate::Error;

/// Validate Base58Check encoding and extract version byte and hash
///
/// Returns (version_byte, hash_bytes) if valid, None otherwise
/// Base58Check format: 25 bytes total (1 version + 20 hash + 4 checksum)
pub fn validate(input: &str) -> Result<Option<(u8, Vec<u8>)>, Error> {
    // Decode Base58
    let decoded = match decode(input) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };

    // Must be 25 bytes (1 version + 20 hash + 4 checksum)
    if decoded.len() != 25 {
        return Ok(None);
    }

    // Extract components
    let version = decoded[0];
    let hash = decoded[1..21].to_vec();
    let checksum = &decoded[21..25];

    // Verify checksum (double SHA256)
    let payload = [&[version], hash.as_slice()].concat();
    let hash_result = double_sha256(&payload);
    let expected_checksum = &hash_result[..4];

    if checksum != expected_checksum {
        return Ok(None);
    }

    Ok(Some((version, hash)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_bitcoin_address() {
        let input = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        let result = validate(input);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert!(decoded.is_some());
        let (version, hash) = decoded.unwrap();
        assert_eq!(version, 0x00); // Bitcoin P2PKH version
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_validate_valid_tron_address() {
        // Create a valid Tron address for testing
        use crate::shared::crypto::hash::double_sha256;
        use base58::ToBase58;

        let version = 0x41u8; // Tron version
        let address_bytes = vec![0u8; 20];
        let payload = [&[version], address_bytes.as_slice()].concat();
        let hash_result = double_sha256(&payload);
        let checksum = &hash_result[..4];
        let full_bytes = [payload, checksum.to_vec()].concat();
        let tron_addr = full_bytes.to_base58();

        let result = validate(&tron_addr);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert!(decoded.is_some());
        let (version_byte, hash) = decoded.unwrap();
        assert_eq!(version_byte, 0x41);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_validate_invalid_length() {
        let input = "1"; // Too short
        let result = validate(input);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_validate_invalid_base58() {
        let input = "0OIl"; // Invalid Base58
        let result = validate(input);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_validate_invalid_checksum() {
        // Create address with wrong checksum
        use base58::ToBase58;
        let version = 0x00u8;
        let address_bytes = vec![0u8; 20];
        let payload = [&[version], address_bytes.as_slice()].concat();
        let wrong_checksum = vec![0xFFu8; 4]; // Wrong checksum
        let full_bytes = [payload, wrong_checksum].concat();
        let invalid_addr = full_bytes.to_base58();

        let result = validate(&invalid_addr);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_validate_wrong_length_decoded() {
        // Create Base58 string that decodes to wrong length
        use base58::ToBase58;
        let short_bytes = [0u8; 20]; // 20 bytes, not 25
        let base58_short = short_bytes.to_base58();

        let result = validate(&base58_short);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
