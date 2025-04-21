# Ether-Link

[![Crates.io](https://img.shields.io/crates/v/ether-link.svg)](https://crates.io/crates/ether-link)
[![Documentation](https://docs.rs/ether-link/badge.svg)](https://docs.rs/ether-link)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight Rust library focused on enabling secure communication between Ethereum address owners. Ether-Link provides simple yet powerful tools for Ethereum key management, message signing, and signature verification - allowing Ethereum wallet owners to securely exchange authenticated messages.

## Core Focus

Ether-Link is specifically designed to facilitate:

- **Secure Communication** between Ethereum address owners
- **Identity Verification** using cryptographic signatures
- **Message Authentication** ensuring only valid Ethereum address owners can participate
- **Decentralized Trust** leveraging Ethereum's cryptographic primitives

## Features

- **Key Management**: Generate new Ethereum key pairs with compressed and uncompressed public keys
- **Address Derivation**: Deterministically generate Ethereum addresses from public keys
- **Message Signing**: Sign messages using Ethereum's standard signing format
- **Signature Verification**: Verify message signatures against Ethereum addresses
- **Timestamped Messages**: Automatic timestamp inclusion to prevent replay attacks

## Upcoming Features (Next Version)

- **Message Encryption**: End-to-end encryption for messages between Ethereum addresses
  - ECIES (Elliptic Curve Integrated Encryption Scheme) implementation
  - Ability to encrypt messages that only specific Ethereum addresses can decrypt
  - Support for both text and binary data encryption
  - Simple API for encrypt/decrypt operations using existing key pairs
- **Batch Operations**: Ability to sign or verify multiple messages efficiently
- **Extended Compatibility**: Support for additional Ethereum signature standards and wallets

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ether-link = "0.0.1"
```

## Usage Examples

### Secure Communication Flow

Ether-Link enables a simple communication pattern between Ethereum address owners:

1. Sender signs a message with their Ethereum private key
2. Recipient verifies the signature using the sender's Ethereum address
3. Communication is authenticated without requiring password exchange or central authorities

### Generating a New Key Pair

```rust
use ether_link::EthKeyPair;

fn main() {
    // Generate a fresh Ethereum key pair
    let keypair = EthKeyPair::new();
    
    println!("Private Key: {}", keypair.privkey);
    println!("Ethereum Address: {}", keypair.address);
    println!("Compressed Public Key: {}", keypair.pubkey_compressed);
    println!("Uncompressed Public Key: {}", keypair.pubkey_uncompressed);
}
```

### Signing a Message

```rust
use ether_link::EthKeyPair;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = EthKeyPair::new();
    let message = "Hello, Ethereum!";
    
    let signature_json = keypair.sign_message(message).await?;
    println!("Signature: {}", signature_json);
    
    Ok(())
}
```

### Verifying a Signature

```rust
use ether_link::verify_ethereum_signature;
use serde_json::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Assume signature_json is the output from sign_message
    let signature_json: Value = serde_json::from_str(&signature_json_str)?;
    
    let address = signature_json["address"].as_str().unwrap();
    let signed_message = signature_json["signed_message"].as_str().unwrap();
    let signature = signature_json["signature"].as_str().unwrap();
    
    let is_valid = verify_ethereum_signature(
        signed_message,
        signature,
        address
    )?;
    
    println!("Signature is valid: {}", is_valid);
    
    Ok(())
}
```

## Key Components

- `EthKeyPair`: Core structure for generating and managing Ethereum key pairs
- `sign_message()`: Async method to sign messages with timestamps for security
- `verify_ethereum_signature()`: Function to verify signed messages against addresses

## Applications

- **Decentralized Identity**: Authenticate users by their Ethereum addresses
- **Secure Messaging**: Build messaging systems where sender identity is cryptographically verified
- **dApp Authentication**: Implement authentication flows without passwords
- **Smart Contract Interaction**: Sign messages intended for on-chain verification
- **Wallet-to-Wallet Communication**: Enable direct secure messaging between wallet owners

## Security Notes

- Private keys are stored in memory as hex strings. Handle with appropriate security measures
- The library adds timestamps to signed messages by default to prevent replay attacks
- Always verify signatures against known addresses before trusting signed messages

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
