//! WebAssembly bindings for foxchain-id
//!
//! This module provides WASM-compatible bindings for the identify function,
//! allowing the library to be used in web browsers and Node.js.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::identify::{IdentificationCandidate, InputType};
use crate::registry::EncodingType;

/// WASM-compatible identification candidate result
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmIdentificationCandidate {
    /// Type of input (address or public key)
    pub input_type: String,
    /// Chain identifier (string ID from metadata)
    pub chain: String,
    /// Encoding type used (as string)
    pub encoding: String,
    /// Normalized representation
    pub normalized: String,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Reasoning for this candidate
    pub reasoning: String,
}

/// Convert EncodingType enum to string representation
fn encoding_type_to_string(encoding: EncodingType) -> String {
    match encoding {
        EncodingType::Hex => "hex".to_string(),
        EncodingType::Base58 => "base58".to_string(),
        EncodingType::Base58Check => "base58check".to_string(),
        EncodingType::Bech32 => "bech32".to_string(),
        EncodingType::Bech32m => "bech32m".to_string(),
        EncodingType::SS58 => "ss58".to_string(),
    }
}

/// Convert InputType enum to string representation
fn input_type_to_string(input_type: InputType) -> String {
    match input_type {
        InputType::Address => "address".to_string(),
        InputType::PublicKey => "publicKey".to_string(),
    }
}

/// Convert Rust IdentificationCandidate to WASM-compatible structure
fn candidate_to_wasm(candidate: IdentificationCandidate) -> WasmIdentificationCandidate {
    WasmIdentificationCandidate {
        input_type: input_type_to_string(candidate.input_type),
        chain: candidate.chain,
        encoding: encoding_type_to_string(candidate.encoding),
        normalized: candidate.normalized,
        confidence: candidate.confidence,
        reasoning: candidate.reasoning,
    }
}

/// Identify the blockchain(s) for a given input string (WASM version)
///
/// This function provides the same functionality as the Rust `identify` function
/// but returns results in a format compatible with JavaScript/TypeScript.
///
/// # Arguments
///
/// * `input` - The input string to identify (address, public key, etc.)
///
/// # Returns
///
/// Returns a JavaScript array of identification candidates directly (not a JSON string),
/// or throws a JavaScript error if identification fails.
///
/// # Example (JavaScript)
///
/// ```javascript
/// import init, { identify } from './pkg/foxchain_id.js';
///
/// await init();
///
/// const candidates = identify("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
/// console.log(candidates); // candidates is already a JavaScript array
/// ```
#[wasm_bindgen]
pub fn identify(input: &str) -> Result<JsValue, JsValue> {
    use crate::identify::identify as identify_fn;

    match identify_fn(input) {
        Ok(candidates) => {
            let wasm_candidates: Vec<WasmIdentificationCandidate> =
                candidates.into_iter().map(candidate_to_wasm).collect();

            serde_wasm_bindgen::to_value(&wasm_candidates)
                .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
        }
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding_type_to_string() {
        assert_eq!(encoding_type_to_string(EncodingType::Hex), "hex");
        assert_eq!(encoding_type_to_string(EncodingType::Base58), "base58");
        assert_eq!(
            encoding_type_to_string(EncodingType::Base58Check),
            "base58check"
        );
        assert_eq!(encoding_type_to_string(EncodingType::Bech32), "bech32");
        assert_eq!(encoding_type_to_string(EncodingType::Bech32m), "bech32m");
        assert_eq!(encoding_type_to_string(EncodingType::SS58), "ss58");
    }

    #[test]
    fn test_input_type_to_string() {
        assert_eq!(input_type_to_string(InputType::Address), "address");
        assert_eq!(input_type_to_string(InputType::PublicKey), "publicKey");
    }
}
