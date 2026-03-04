# foxchain-id

Multi-chain blockchain address identification library for Rust.

## Overview

`foxchain-id` provides functionality to identify which blockchain(s) an input string (address, public key, or private key) belongs to. It supports multiple blockchain address formats and returns normalized addresses with confidence scores for candidate chains.

## Features

- **Multi-chain support**: Identify addresses across multiple blockchain networks
- **Address normalization**: Convert addresses to their canonical format
- **Confidence scoring**: Get confidence scores for each candidate chain
- **Format detection**: Automatically detect address format (EVM, Bitcoin, Solana, etc.)
- **EIP-55 checksum validation**: Validate and normalize EVM addresses according to EIP-55
- **Public key detection**: Detect public keys in various formats (hex, base58, bech32)
- **Address derivation**: Derive addresses from public keys for supported chains
- **Transaction identification**: Detect transaction hashes, extrinsic IDs, and Solana signatures
- **Block hash detection**: Detect block hashes as a first-class `InputType::BlockHash` alongside transactions (21 chains with block explorer URLs)
- **WebAssembly support**: Compile to WASM for use in web browsers and Node.js (see [WASM.md](WASM.md))

## Quick Start

```rust
use foxchain_id::identify;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Identify an EVM address
    let result = identify("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")?;
    
    println!("Normalized address: {}", result[0].normalized);
    for candidate in result {
        println!("Chain: {}, Confidence: {:.2}", candidate.chain, candidate.confidence);
        println!("Reasoning: {}", candidate.reasoning);
    }
    
    Ok(())
}
```

## Supported Formats

### Currently Implemented

- **EVM Addresses** (Ethereum, Polygon, BSC, Avalanche, Arbitrum, Optimism, Base, Fantom, Celo, Gnosis)
  - Format: `0x` followed by 40 hex characters
  - EIP-55 checksum validation and normalization
  - See [EVM Addresses Documentation](docs/evm-addresses.md) for details

- **Bitcoin Ecosystem** (Bitcoin, Litecoin, Dogecoin)
  - P2PKH addresses (legacy, starts with `1`)
  - P2SH addresses (script hash, starts with `3`)
  - Bech32 addresses (native SegWit, starts with `bc1`/`ltc1`/etc.)
  - Base58Check validation for P2PKH and P2SH
  - Bech32 validation for native SegWit
  - See [Bitcoin Addresses Documentation](docs/bitcoin-addresses.md) for details

- **Solana Addresses**
  - Base58 encoding (32-44 bytes when decoded)
  - Length validation (standard 32 bytes, up to 44 bytes)
  - Prefix filtering to avoid conflicts with other chains
  - See [Solana Addresses Documentation](docs/solana-addresses.md) for details

- **Tron Addresses**
  - Base58Check encoding (starts with T)
  - Version byte validation (0x41 for mainnet)
  - Length validation (25 bytes when decoded)
  - Base58Check checksum validation
  - See [Tron Addresses Documentation](docs/tron-addresses.md) for details

- **Cosmos Ecosystem Addresses** (Cosmos Hub, Osmosis, Juno, Akash, Stargaze, Secret Network, Terra, Kava, Regen, Sentinel)
  - Bech32 encoding with HRP (Human Readable Part) prefixes
  - Chain identification from HRP
  - Bech32 validation and checksum verification
  - Case-insensitive normalization
  - See [Cosmos Addresses Documentation](docs/cosmos-addresses.md) for details

- **Substrate/Polkadot Ecosystem Addresses** (Polkadot, Kusama, Generic Substrate)
  - SS58 encoding (Base58 with chain-specific prefixes)
  - Chain identification from SS58 prefix
  - SS58 structure validation
  - Account ID extraction (32 bytes)
  - See [Substrate Addresses Documentation](docs/substrate-addresses.md) for details

- **Cardano Addresses**
  - Bech32 encoding with HRP (Human Readable Part) prefixes
  - Support for mainnet (addr, stake) and testnet (addr_test, stake_test) addresses
  - Bech32 validation and checksum verification
  - Case-insensitive normalization

- **Public Key Detection and Address Derivation**
  - Hex public key detection (compressed/uncompressed secp256k1, Ed25519)
  - Base58 public key detection
  - Bech32 public key detection
  - EVM address derivation from secp256k1 public keys
  - Bitcoin address derivation from secp256k1 public keys (P2PKH)
  - Solana address derivation from Ed25519 public keys
  - Cosmos address derivation from Ed25519 public keys

- **Transaction Identification**
  - EVM transaction hashes (0x-prefixed keccak-256, 66 chars)
  - Bitcoin/Cosmos/Cardano/Tron transaction hashes (64 hex chars)
  - Solana transaction signatures (85-90 chars Base58, ed25519)
  - Substrate extrinsic IDs (`BLOCK_HEIGHT-INDEX` format)

- **Block Hash Detection** (`InputType::BlockHash`)
  - First-class type alongside `Transaction` — both returned for ambiguous inputs
  - EVM block hashes (keccak-256, same format as EVM tx — confidence 0.55)
  - UTXO/Cosmos/Tron block hashes (SHA-256d, same format as their tx — confidence 0.50)
  - Solana block hashes (32-44 char Base58, **distinct** from 85-90 char tx signature — confidence 0.75)
  - Substrate block hashes (64 hex chars)
  - Block explorer URLs via `block_hash_scanner_url_template` for 21 chains (etherscan, blockchain.com, solscan, subscan, mintscan, tronscan, cardanoscan…)
  - WASM serialization as `"blockHash"` for JavaScript consumers

### Planned

- TON, Algorand, Near, and more...

See [Format Documentation](docs/) for detailed information about each format.

## Usage

### Basic Identification

```rust
use foxchain_id::identify;

let result = identify("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")?;

// Get normalized address
let normalized = result[0].normalized;

// Get all candidate chains
for candidate in result {
    if candidate.confidence > 0.9 {
        println!("High confidence match: {}", candidate.chain);
    }
}
```

### Working with Results

```rust
use foxchain_id::{identify, InputType};

let result = identify("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")?;

// Find specific chain
if let Some(ethereum) = result.iter().find(|c| c.chain == "ethereum") {
    println!("Ethereum confidence: {}", ethereum.confidence);
}

// Get highest confidence candidate
let best_match = result.iter()
    .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap());
```

### Block Hash Detection

Block hashes and transaction hashes share the same format for most chains. `identify()` returns **both** `BlockHash` and `Transaction` candidates for ambiguous inputs:

```rust
use foxchain_id::{identify, InputType};

// EVM block hash (same format as EVM tx hash — both types returned)
let result = identify("0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6")?;

let block_hashes: Vec<_> = result.iter()
    .filter(|c| c.input_type == InputType::BlockHash)
    .collect();
let transactions: Vec<_> = result.iter()
    .filter(|c| c.input_type == InputType::Transaction)
    .collect();

// Both are returned — disambiguation requires application-level context
println!("Block hash candidates: {}", block_hashes.len()); // e.g. 10 EVM chains
println!("Transaction candidates: {}", transactions.len()); // same 10 EVM chains

// Block explorer URL is populated from block_hash_scanner_url_template
if let Some(eth) = block_hashes.iter().find(|c| c.chain == "ethereum") {
    println!("Explorer: {:?}", eth.scanner_url);
    // → Some("https://etherscan.io/block/0x88e96d...")
}

// Solana block hash IS distinguishable (32-44 char Base58 vs 85-90 char tx signature)
let sol_result = identify("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")?;
let sol_block = sol_result.iter().find(|c| c.input_type == InputType::BlockHash && c.chain == "solana");
println!("Solana block hash confidence: {:.2}", sol_block.unwrap().confidence); // 0.75
```

## Documentation

- [Format Documentation](docs/) - Detailed documentation for each address format
- [API Documentation](https://docs.rs/foxchain-id) - Full API reference (when published)
- [WASM Documentation](WASM.md) - WebAssembly build and usage guide

## Contributing

Contributions are welcome! Please see the main project repository for contribution guidelines.

## License

This project is licensed under the GPL-3.0 license.
