use crate::shared::crypto::hash::keccak256;
use crate::shared::crypto::secp256k1;
use crate::shared::encoding::hex;
use crate::Error;
use serde_json::Value;

/// Execute EVM address derivation pipeline
pub fn execute_evm_pipeline(pk_bytes: &[u8], _params: &Value) -> Result<String, Error> {
    // Extract 64-byte key
    let key_64 = extract_64_bytes(pk_bytes)?;

    // Hash with Keccak256
    let hash = keccak256(&key_64);

    // Slice last 20 bytes
    let address_bytes = &hash[12..32];

    // Encode as hex with 0x prefix
    // hex::encode already adds "0x" prefix, so use it directly
    Ok(hex::encode(address_bytes))
}

fn extract_64_bytes(public_key: &[u8]) -> Result<Vec<u8>, Error> {
    if public_key.len() == 33 {
        let uncompressed = secp256k1::decompress_public_key(public_key)?;
        if uncompressed.len() == 65 && uncompressed[0] == 0x04 {
            Ok(uncompressed[1..65].to_vec())
        } else {
            Err(Error::InvalidInput(
                "Invalid decompressed key format".to_string(),
            ))
        }
    } else if public_key.len() == 65 && public_key[0] == 0x04 {
        Ok(public_key[1..65].to_vec())
    } else if public_key.len() == 64 {
        Ok(public_key.to_vec())
    } else {
        Err(Error::InvalidInput(format!(
            "Invalid secp256k1 key length: {} bytes",
            public_key.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_evm_pipeline_compressed_key() {
        // Use a valid compressed secp256k1 key
        let compressed_key =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let params = json!({});

        let result = execute_evm_pipeline(&compressed_key, &params);
        assert!(result.is_ok());
        let address = result.unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_evm_pipeline_uncompressed_key() {
        let uncompressed_key = hex::decode("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap();
        let params = json!({});

        let result = execute_evm_pipeline(&uncompressed_key, &params);
        assert!(result.is_ok());
        let address = result.unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_evm_pipeline_64_byte_key() {
        let key_64 = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap();
        let params = json!({});

        let result = execute_evm_pipeline(&key_64, &params);
        assert!(result.is_ok());
        let address = result.unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_evm_pipeline_invalid_length() {
        let invalid_key = vec![0u8; 32];
        let params = json!({});

        let result = execute_evm_pipeline(&invalid_key, &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_evm_pipeline_invalid_decompressed_format() {
        // Test with a key that has invalid format (wrong prefix for compressed)
        // Use 0x04 prefix which is for uncompressed, but length is 33
        let invalid_key = vec![0x04u8; 33];
        let params = json!({});

        // This should fail at length validation or format check
        let result = execute_evm_pipeline(&invalid_key, &params);
        // Should fail - either at length check or decompression
        assert!(result.is_err());
    }
}
