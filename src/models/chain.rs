use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub scanner_url_template: Option<String>,
    /// Scanner URL template for transactions with {transaction} placeholder (optional)
    #[serde(default)]
    pub transaction_scanner_url_template: Option<String>,
    /// Scanner URL template for block hashes with {block_hash} placeholder (optional)
    #[serde(default)]
    pub block_hash_scanner_url_template: Option<String>,
    pub curve: String,
    pub address_pipeline: String,
    #[serde(default)]
    pub requires_stake_key: bool,
    #[serde(default)]
    pub address_params: Value,
    pub public_key_formats: Vec<PublicKeyFormat>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublicKeyFormat {
    pub encoding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length_range: Option<(usize, usize)>,
    #[serde(default)]
    pub prefixes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Fields used for JSON deserialization, may not all be read
pub struct MetadataIndex {
    pub curves: Vec<String>,
    pub pipelines: PipelineIndex,
    pub chains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Fields used for JSON deserialization, may not all be read
pub struct PipelineIndex {
    pub addresses: Vec<String>,
}
