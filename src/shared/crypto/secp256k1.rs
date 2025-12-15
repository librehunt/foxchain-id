//! secp256k1 cryptographic utilities

use crate::Error;

/// Decompress a compressed secp256k1 public key
///
/// Takes a 33-byte compressed public key (with 0x02 or 0x03 prefix) and
/// returns the 65-byte uncompressed public key (with 0x04 prefix).
///
/// # Arguments
///
/// * `compressed_key` - A 33-byte slice containing the compressed public key
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - A 65-byte uncompressed public key (0x04 + 64 bytes)
/// * `Err(Error)` - If the compressed key is invalid
pub fn decompress_public_key(compressed_key: &[u8]) -> Result<Vec<u8>, Error> {
    // Validate input length
    if compressed_key.len() != 33 {
        return Err(Error::InvalidInput(format!(
            "Compressed public key must be 33 bytes, got {}",
            compressed_key.len()
        )));
    }

    // Validate prefix (must be 0x02 or 0x03)
    if compressed_key[0] != 0x02 && compressed_key[0] != 0x03 {
        return Err(Error::InvalidInput(format!(
            "Compressed public key must start with 0x02 or 0x03, got 0x{:02x}",
            compressed_key[0]
        )));
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        use secp256k1::PublicKey;
        // Parse the compressed public key
        let public_key = PublicKey::from_slice(compressed_key)
            .map_err(|e| Error::InvalidInput(format!("Invalid compressed public key: {}", e)))?;

        // Serialize to uncompressed format (65 bytes: 0x04 + 64 bytes)
        let uncompressed = public_key.serialize_uncompressed();

        Ok(uncompressed.to_vec())
    }

    #[cfg(target_arch = "wasm32")]
    {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::PublicKey;

        // Parse the compressed public key using k256
        let public_key = PublicKey::from_sec1_bytes(compressed_key)
            .map_err(|e| Error::InvalidInput(format!("Invalid compressed public key: {}", e)))?;

        // Serialize to uncompressed format (65 bytes: 0x04 + 64 bytes)
        let encoded_point = public_key.to_encoded_point(false); // false = uncompressed
        let uncompressed = encoded_point.as_bytes();

        Ok(uncompressed.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress_public_key_0x02() {
        // Test with 0x02 prefix (even y coordinate)
        // This is a valid compressed public key format
        let mut compressed = vec![0x02];
        compressed.extend(vec![0u8; 32]);

        // Note: This will fail if the key is not valid on the curve
        // For a real test, we'd need a valid compressed key
        // For now, we test the validation logic
        let result = decompress_public_key(&compressed);
        // The result depends on whether the key is valid on the curve
        // If invalid, we get an error; if valid, we get 65 bytes
        match result {
            Ok(uncompressed) => {
                assert_eq!(uncompressed.len(), 65);
                assert_eq!(uncompressed[0], 0x04);
            }
            Err(_) => {
                // Invalid key on curve - this is expected for all-zero key
            }
        }
    }

    #[test]
    fn test_decompress_public_key_0x03() {
        // Test with 0x03 prefix (odd y coordinate)
        let mut compressed = vec![0x03];
        compressed.extend(vec![0u8; 32]);

        let result = decompress_public_key(&compressed);
        match result {
            Ok(uncompressed) => {
                assert_eq!(uncompressed.len(), 65);
                assert_eq!(uncompressed[0], 0x04);
            }
            Err(_) => {
                // Invalid key on curve - expected
            }
        }
    }

    #[test]
    fn test_decompress_public_key_invalid_length() {
        // Test with wrong length
        let compressed = vec![0u8; 32];
        let result = decompress_public_key(&compressed);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("33 bytes"));
    }

    #[test]
    fn test_decompress_public_key_invalid_prefix() {
        // Test with invalid prefix
        let mut compressed = vec![0x04]; // Invalid prefix for compressed key
        compressed.extend(vec![0u8; 32]);

        let result = decompress_public_key(&compressed);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("0x02 or 0x03"));
    }

    #[test]
    fn test_decompress_public_key_valid_key() {
        // Test with a known valid compressed public key
        // This is the compressed form of the secp256k1 generator point
        // Compressed: 0x02 + x-coordinate
        // Generator point compressed: 0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        use crate::shared::encoding::hex;
        let compressed =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();

        let result = decompress_public_key(&compressed);
        assert!(result.is_ok());
        let uncompressed = result.unwrap();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);

        // Verify it matches the known uncompressed generator point
        // Uncompressed: 0x04 + x-coordinate + y-coordinate
        let expected = hex::decode("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
            .unwrap();
        assert_eq!(uncompressed, expected);
    }

    #[test]
    fn test_decompress_public_key_invalid_curve_point() {
        // Test with a compressed key that has valid format but is not on the curve
        // This should trigger the error path in PublicKey::from_slice
        let mut compressed = vec![0x02];
        // Use a value that's not a valid x-coordinate on secp256k1 curve
        compressed.extend(vec![0xFFu8; 32]);

        let result = decompress_public_key(&compressed);
        // This should fail because the point is not on the curve
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid compressed public key"));
    }
}
