# Changelog

## [Unreleased](https://github.com/librehunt/foxchain-id/tree/HEAD)

[Full Changelog](https://github.com/librehunt/foxchain-id/compare/f9d6d027ed2e0164435e56e6c12f0184422a79c8...HEAD)

### Added
- **Block hash detection** (`InputType::BlockHash`) as a first-class input type alongside `Transaction`:
  - `InputPossibility::BlockHash` and `could_be_block_hash()` in the classifier
  - `block_hash_matches()` in the metadata matcher, gated on `block_hash_scanner_url_template`
  - `try_block_hash_detection_for_chain()` and `generate_block_hash_scanner_url()` in the identification pipeline
  - `block_hash_scanner_url_template` field in `ChainConfig`, `ChainMetadata`, and `chain_converter`
  - 21 chain JSON files updated with block explorer URLs (etherscan, bscscan, polygonscan, blockchain.com, litecoinspace, blockchair, solscan, mintscan, subscan, tronscan, cardanoscan…)
  - WASM binding: `InputType::BlockHash` serializes as `"blockHash"` for JavaScript consumers
  - 17 integration tests in `tests/block_hash_detection.rs`
  - Note: EVM and UTXO block hashes are format-identical to their tx hashes — both `BlockHash` and `Transaction` candidates are returned. Solana is the only chain with a distinguishable block hash format (32-44 char Base58 vs 85-90 char tx signature, confidence 0.75)
- **Compressed public key decompression support**: Added `decompress_public_key` function in `shared/crypto/secp256k1.rs` to support decompressing 33-byte compressed secp256k1 public keys to 65-byte uncompressed format
- **EVM address derivation from compressed keys**: `derive_evm_address` now supports compressed public keys (33 bytes with 0x02/0x03 prefix)
- **Bitcoin address derivation from compressed keys**: `derive_bitcoin_addresses` now supports compressed public keys (33 bytes with 0x02/0x03 prefix)
- Workspace structure with foxchain-id and foxchain-analysis crates
- Root library that re-exports both crates for unified access
- EVM address detection and normalization in foxchain-id crate
  - EIP-55 checksum validation and normalization
  - Support for 10+ EVM-compatible chains (Ethereum, Polygon, BSC, Avalanche, Arbitrum, Optimism, Base, Fantom, Celo, Gnosis)
  - Multi-chain candidate generation with confidence scores
- Bitcoin ecosystem address detection and normalization in foxchain-id crate
  - P2PKH address detection (legacy, starts with 1)
  - P2SH address detection (script hash, starts with 3)
  - Bech32 address detection (native SegWit, starts with bc1/ltc1/etc.)
  - Base58Check validation for P2PKH and P2SH addresses
  - Bech32 validation for native SegWit addresses
  - Support for Bitcoin, Litecoin, and Dogecoin
  - Chain identification based on version bytes and HRP prefixes
- Solana address detection and normalization in foxchain-id crate
  - Base58 address detection (32-44 bytes when decoded)
  - Length validation (standard 32 bytes, up to 44 bytes)
  - Prefix filtering to avoid conflicts with Bitcoin and EVM addresses
  - Confidence scoring based on address length
- Tron address detection and normalization in foxchain-id crate
  - Base58Check address detection (starts with T)
  - Version byte validation (0x41 for mainnet)
  - Length validation (25 bytes when decoded: 1 version + 20 address + 4 checksum)
  - Base58Check checksum validation
- Cosmos ecosystem address detection and normalization in foxchain-id crate
  - Bech32 address detection with HRP (Human Readable Part) identification
  - Support for 10+ major Cosmos chains (Cosmos Hub, Osmosis, Juno, Akash, Stargaze, Secret Network, Terra, Kava, Regen, Sentinel)
  - HRP-to-chain mapping for chain identification
  - Bech32 validation and checksum verification
  - Case-insensitive address normalization
- Substrate/Polkadot ecosystem address detection and normalization in foxchain-id crate
  - SS58 address detection (Base58 with chain-specific prefixes)
  - Support for major Substrate chains (Polkadot, Kusama, Generic Substrate)
  - Prefix-to-chain mapping for chain identification
  - SS58 structure validation (prefix + 32-byte account ID + 2-byte checksum)
  - SS58 checksum validation using Blake2b hash
  - Proper SS58 two-byte prefix decoding (64-16383 range)
  - Account ID extraction
- Cardano address detection and normalization in foxchain-id crate
  - Bech32 address detection with HRP identification
  - Support for mainnet (addr, stake) and testnet (addr_test, stake_test) addresses
  - Bech32 validation and checksum verification
  - Case-insensitive address normalization
- Public key detection and address derivation in foxchain-id crate
  - Hex public key detection (compressed/uncompressed secp256k1, Ed25519)
  - Base58 public key detection
  - Bech32 public key detection
  - EVM address derivation from secp256k1 public keys (Keccak-256 hash)
  - Bitcoin address derivation from secp256k1 public keys (P2PKH via hash160)
  - Solana address derivation from Ed25519 public keys (direct mapping)
  - Cosmos address derivation from Ed25519 public keys (SHA256 hash + Bech32 encoding)
- Automated publishing workflow for all crates to crates.io
  - Supports automatic publishing on release creation
  - Supports manual publishing via workflow_dispatch
  - Includes dry-run mode for validation
  - Publishes crates in correct dependency order
  - Version validation and synchronization

### Changed
- Rename project from rbase to foxchain: updated package name in Cargo.toml, README.md badges/links, and CHANGELOG.md URLs
- **Repository restructure**: Converted from Cargo workspace to single crate structure
  - Moved foxchain-id crate to root directory
  - Removed foxchain-analysis crate (will be moved to separate repository)
  - Removed workspace configuration
  - Updated all documentation and workflows to reflect single crate structure

**Merged pull requests:**

- fix: cron for sync template [\#16](https://github.com/librehunt/foxchain/pull/16) ([Lsh0x](https://github.com/Lsh0x))
- feat: add workflow to sync template [\#15](https://github.com/librehunt/foxchain/pull/15) ([Lsh0x](https://github.com/Lsh0x))
- .feat: update codecove version [\#14](https://github.com/librehunt/foxchain/pull/14) ([Lsh0x](https://github.com/Lsh0x))
- feat: rework codecov workflow [\#13](https://github.com/librehunt/foxchain/pull/13) ([Lsh0x](https://github.com/Lsh0x))
- feat: rework codecov workflow [\#12](https://github.com/librehunt/foxchain/pull/12) ([Lsh0x](https://github.com/Lsh0x))
- fix: libsso prob du latest ubuntu [\#11](https://github.com/librehunt/foxchain/pull/11) ([Lsh0x](https://github.com/Lsh0x))
- feat: upgrade version of actions cache [\#8](https://github.com/librehunt/foxchain/pull/8) ([Lsh0x](https://github.com/Lsh0x))
- fix: change last commit badge from master to main [\#5](https://github.com/librehunt/foxchain/pull/5) ([Lsh0x](https://github.com/Lsh0x))
- fix: github action coverage workflow [\#4](https://github.com/librehunt/foxchain/pull/4) ([Lsh0x](https://github.com/Lsh0x))
- Fix/transform template into lib [\#3](https://github.com/librehunt/foxchain/pull/3) ([Lsh0x](https://github.com/Lsh0x))
- feat: update github workflow for changelog [\#2](https://github.com/librehunt/foxchain/pull/2) ([Lsh0x](https://github.com/Lsh0x))
- feat: updates to 2022 [\#1](https://github.com/librehunt/foxchain/pull/1) ([Lsh0x](https://github.com/Lsh0x))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
