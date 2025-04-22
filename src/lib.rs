pub mod wallet;
pub use wallet::Wallet;

pub mod signature;
pub use signature::EthereumSignature;

//pub mod encryption;
//pub mod types;


//pub use encryption::encrypt_message_with_hex_pubkey;
//pub use signature::sign_message;
//pub use types::{EncryptedMessage, SignaturePayload};

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
        let wallet = Wallet::with_private_key(Some("0x1b5667a5972dba94b9baf4026288e4b51fdbc0c9c896473d394b78c5bd2ee92e"));
        println!("Private Key: {}", wallet.privkey);
        println!("Compressed Public Key: {}", wallet.pubkey_compressed);
        println!("Uncompressed Public Key: {}", wallet.pubkey_uncompressed);
        println!("Ethereum Address: {}", wallet.address);
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
        let sender = Wallet::with_private_key(Some("0x1f87cca105d954f1ae230f6ccdf8ea2c7df5eec8bb5d6c706344b42b725bd07d"));
        let receiver = Wallet::with_private_key(Some("0xa4df62cbf0d00a76c6bceb5c6606823b8f4edb69c8b68607621dcc0a2e87a766"));
        let message = "message from d07d to a4df: hello friend...ggagagag.?";
        let encrypted_message = sender.encrypt_message(message, &receiver.pubkey_compressed).unwrap_or_else(|e| panic!("Failed to encrypt message: {}", e));
        println!("Encrypted Message from sender(d07d) to receiver(a4df): {}", encrypted_message);
        println!("Length of encrypted message: {}", encrypted_message.len());
        let decrypted_message = receiver.decrypt_message(&encrypted_message).unwrap_or_else(|e| panic!("Failed to decrypt message: {}", e));
        println!("Decrypted Message from receiver(a4df) to sender(d07d): {}", decrypted_message);
    }
    #[tokio::test]  
    async fn test_decrypt_message() {
        let wallet = Wallet::new();
        println!("private key {}", wallet.privkey);
        let message = "Hello, world!";
        let encrypted_message = wallet.encrypt_message(message, &wallet.pubkey_uncompressed).unwrap_or_else(|e| panic!("Failed to encrypt message: {}", e));
        println!("Encrypted Message: {}", encrypted_message);
        let decrypted_message = wallet.decrypt_message(&encrypted_message).unwrap_or_else(|e| panic!("Failed to decrypt message: {}", e));
        println!("Decrypted Message: {}", decrypted_message);
    }

    #[tokio::test]
    async fn test_decrypt_message_with_wrong_encrypted_message() {
        let wallet = Wallet::with_private_key(Some("0xa4df62cbf0d00a76c6bceb5c6606823b8f4edb69c8b68607621dcc0a2e87a766"));
        let encrypted_message = "0x03071daa81473f20e116f6e3985c4bae4da2ae4a7fe8a54486e61f6eb3872d2e8d1290448460c2a7f3a7ae7ff4bbc2d61a2111a8a5ca101bd593ca1bbc7dbeaf4cff3f4721d29e834f6d71e79e".to_string();
        let decrypted_message = wallet.decrypt_message(&encrypted_message).unwrap_or_else(|e| panic!("Failed to decrypt message: {}", e));
        println!("Decrypted Message: {}", decrypted_message);
    }

}
