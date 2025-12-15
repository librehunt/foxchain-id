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
use foxchain_id::identify;

let result = identify("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")?;

// Find specific chain
if let Some(ethereum) = result.iter().find(|c| c.chain == "ethereum") {
    println!("Ethereum confidence: {}", ethereum.confidence);
}

// Get highest confidence candidate
let best_match = result.iter()
    .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap());
```

## Documentation

- [Format Documentation](docs/) - Detailed documentation for each address format
- [API Documentation](https://docs.rs/foxchain-id) - Full API reference (when published)
- [WASM Documentation](WASM.md) - WebAssembly build and usage guide

## Contributing

Contributions are welcome! Please see the main project repository for contribution guidelines.

## License

This project is licensed under the GPL-3.0 license.
