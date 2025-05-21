#[cfg(feature = "wallet")]
pub mod wallet;
#[cfg(feature = "wallet")]
pub use wallet::Wallet;

#[cfg(feature = "signature")]
pub mod signature;
#[cfg(feature = "signature")]
pub use signature::EthereumSignature;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_random_wallet_generation() {
        let wallet = Wallet::new();
        println!("Private Key: {}", wallet.privkey);
        println!("Compressed Public Key: {}", wallet.pubkey_compressed);
        println!("Uncompressed Public Key: {}", wallet.pubkey_uncompressed);
        println!("Ethereum Address: {}", wallet.address);
    }

    #[tokio::test]
    async fn test_wallet_from_private_key() {
        let wallet = Wallet::from_private_key(Some("0x1b5667a5972dba94b9baf4026288e4b51fdbc0c9c896473d394b78c5bd2ee92e"))
            .unwrap_or_else(|e| panic!("Failed to create wallet: {}", e));
        println!("Private Key: {}", wallet.privkey);
        println!("Compressed Public Key: {}", wallet.pubkey_compressed);
        println!("Uncompressed Public Key: {}", wallet.pubkey_uncompressed);
        println!("Ethereum Address: {}", wallet.address);
    }

    #[tokio::test]
    async fn test_wallet_from_private_key_invalid() {
        match Wallet::from_private_key(Some("0x1b5667a5972dba94b9baf4026288e4b51fdbc0c9c896473d394b78c5bd2ee92")) {
            Ok(wallet) => {
                println!("Private Key: {}", wallet.privkey);
                println!("Compressed Public Key: {}", wallet.pubkey_compressed);
                println!("Uncompressed Public Key: {}", wallet.pubkey_uncompressed);
                println!("Ethereum Address: {}", wallet.address);
            },
            Err(e) => {
                println!("Expected error occurred: {}", e);
                assert!(e.contains("Invalid private key"), "Error message should indicate invalid private key");
            }
        }
    }

    #[tokio::test]
    async fn test_sign_message() {
        let wallet = Wallet::new();
        let message = "Hello, world!";
        let signature = wallet.sign_message(message).await.unwrap_or_else(|e| panic!("Failed to sign message: {}", e));
        
        // Parse the signature JSON string
        let sig_json: serde_json::Value = serde_json::from_str(&signature).unwrap_or_else(|e| panic!("Failed to parse signature JSON: {}", e));
        println!("Signature JSON: {}", serde_json::to_string_pretty(&sig_json).unwrap_or_else(|e| panic!("Failed to format JSON: {}", e)));
        
        // Verify the signature contains all expected fields
        assert!(sig_json.get("address").is_some());
        assert!(sig_json.get("signed_message").is_some());
        assert!(sig_json.get("signature").is_some());
    }

    

    #[tokio::test]
    async fn test_check_signature_is_valid() {
        let wallet = Wallet::new();
        let message = "Hello, world!";
        let signature_json = wallet.sign_message(&message).await.unwrap_or_else(|e| panic!("Failed to sign message: {}", e));
        
        // Parse the signature JSON to extract the components
        let sig_json: serde_json::Value = serde_json::from_str(&signature_json).unwrap_or_else(|e| panic!("Failed to parse signature JSON: {}", e));
        let address = sig_json["address"].as_str().unwrap().to_string();
        let signed_message = sig_json["signed_message"].as_str().unwrap().to_string();
        let signature = sig_json["signature"].as_str().unwrap().to_string();

        println!("Address: {}", address);
        println!("Signed Message: {}", signed_message);
        println!("Signature: {}", signature);

        let eth_signature = EthereumSignature::new(address, signed_message, signature);
        let is_valid = eth_signature.verify().unwrap_or_else(|e| panic!("Failed to verify signature: {}", e));
        println!("Signature is valid: {}", is_valid);
        assert!(is_valid, "Signature verification failed");
    }
    #[tokio::test]
    async fn test_encrypt_and_decrypt_message() {
        let sender = Wallet::from_private_key(Some("0x1f87cca105d954f1ae230f6ccdf8ea2c7df5eec8bb5d6c706344b42b725bd07d"))
            .unwrap_or_else(|e| panic!("Failed to create sender wallet: {}", e));
        let receiver = Wallet::from_private_key(Some("0xa4df62cbf0d00a76c6bceb5c6606823b8f4edb69c8b68607621dcc0a2e87a766"))
            .unwrap_or_else(|e| panic!("Failed to create receiver wallet: {}", e));
        let message = "message from d07d to a4df: hello friend...ggagagag.?";
        let encrypted_message = sender.encrypt_message(message, &receiver.pubkey_compressed).unwrap_or_else(|e| panic!("Failed to encrypt message: {}", e));
        println!("Encrypted Message from sender(d07d) to receiver(a4df): {}", encrypted_message);
        println!("Length of encrypted message: {}", encrypted_message.len());
        let decrypted_message = receiver.decrypt_message(&encrypted_message).unwrap_or_else(|e| panic!("Failed to decrypt message: {}", e));
        println!("Decrypted Message from receiver(a4df) to sender(d07d): {}", decrypted_message);
    }
}
