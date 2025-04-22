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
- **Message Encryption**: End-to-end encryption for messages between Ethereum addresses
  - EIP-5630 compliant ECIES (Elliptic Curve Integrated Encryption Scheme) implementation
  - Encrypt messages that only specific Ethereum addresses can decrypt
  - AES-256-GCM encryption with HKDF key derivation
- **Message Decryption**: Decrypt messages encrypted with ECIES for your Ethereum address
- **Custom Key Import**: Create wallets from existing private keys

## Upcoming Features (Next Version)

- **Batch Operations**: Ability to sign or verify multiple messages efficiently
- **Extended Compatibility**: Support for additional Ethereum signature standards and wallets
- **More Cipher Options**: Support for additional encryption algorithms and modes

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ether-link = "0.0.5"
```

## Usage Examples

### Secure Communication Flow

Ether-Link enables a simple communication pattern between Ethereum address owners:

1. Sender signs a message with their Ethereum private key
2. Recipient verifies the signature using the sender's Ethereum address
3. Communication is authenticated without requiring password exchange or central authorities

### Generating a New Key Pair

```rust
use ether_link::Wallet;

fn main() {
    // Generate a fresh Ethereum key pair
    let wallet = Wallet::new();
    
    println!("Private Key: {}", wallet.privkey);
    println!("Ethereum Address: {}", wallet.address);
    println!("Compressed Public Key: {}", wallet.pubkey_compressed);
    println!("Uncompressed Public Key: {}", wallet.pubkey_uncompressed);
}
```

### Creating a Wallet from Existing Private Key

```rust
use ether_link::Wallet;

fn main() {
    // Create a wallet using an existing private key
    let private_key = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d";
    let wallet = Wallet::with_private_key(Some(private_key));
    
    println!("Ethereum Address: {}", wallet.address);
    // Should print: 0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b
}
```

### Signing a Message

```rust
use ether_link::Wallet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = Wallet::new();
    let message = "Hello, Ethereum!";
    
    let signature_json = wallet.sign_message(message).await?;
    println!("Signature: {}", signature_json);
    
    Ok(())
}
```

### Encrypting a Message

```rust
use ether_link::Wallet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = Wallet::new();
    let message = "Secret message for recipient!";
    let recipient_pubkey = "027a4066efb9f66a65cf5f30c5ccdc7c0cdd9608f699eb3c5da2172ea2f6f579dc"; // Recipient's compressed public key
    
    let encrypted = wallet.encrypt_message(message, recipient_pubkey)?;
    println!("Encrypted: {}", encrypted);
    
    Ok(())
}
```

### Decrypting a Message

```rust
use ether_link::Wallet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = Wallet::new(); // The recipient's wallet
    let encrypted_message = "0x0123..."; // Encrypted message from sender
    
    let decrypted = wallet.decrypt_message(encrypted_message)?;
    println!("Decrypted message: {}", decrypted);
    
    Ok(())
}
```

### Verifying a Signature

```rust
use ether_link::EthereumSignature;
use serde_json::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Assume signature_json is the output from sign_message
    let signature_json: Value = serde_json::from_str(&signature_json_str)?;
    
    let address = signature_json["address"].as_str().unwrap();
    let signed_message = signature_json["signed_message"].as_str().unwrap();
    let signature = signature_json["signature"].as_str().unwrap();
    
    let eth_signature = EthereumSignature::new(
        address.to_string(),
        signed_message.to_string(),
        signature.to_string()
    );
    
    let is_valid = eth_signature.verify_ethereum_signature()?;
    println!("Signature is valid: {}", is_valid);
    
    Ok(())
}
```

## Key Components

- `Wallet`: Core structure for generating and managing Ethereum key pairs
- `new()`: Create a new random wallet
- `with_private_key()`: Create a wallet from an existing private key
- `sign_message()`: Async method to sign messages with timestamps for security
- `encrypt_message()`: Method to encrypt messages for a specific recipient's public key
- `decrypt_message()`: Method to decrypt messages encrypted for this wallet
- `EthereumSignature`: Structure to verify signed messages against Ethereum addresses

## Applications

- **Decentralized Identity**: Authenticate users by their Ethereum addresses
- **Secure Messaging**: Build messaging systems where sender identity is cryptographically verified
- **dApp Authentication**: Implement authentication flows without passwords
- **Smart Contract Interaction**: Sign messages intended for on-chain verification
- **Wallet-to-Wallet Communication**: Enable direct secure messaging between wallet owners
- **Private Data Exchange**: Exchange encrypted data that only specific Ethereum addresses can access

## Security Notes

- Private keys are stored in memory as hex strings. Handle with appropriate security measures
- The library adds timestamps to signed messages by default to prevent replay attacks
- Always verify signatures against known addresses before trusting signed messages
- Encrypted messages follow the EIP-5630 standard for ECIES encryption
- The same shared secret is derived by both sender and recipient for encryption/decryption

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
