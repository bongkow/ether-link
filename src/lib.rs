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
    use hex;

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

    #[test]
    fn test_eth_keypair_generation() {
        let wallet = Wallet::new();

        // Check that the address is 42 chars: "0x" + 40 hex digits
        assert_eq!(wallet.address.len(), 42);
        assert!(wallet.address.starts_with("0x"));

        // Check compressed key format (hex string should be 66 chars - 2 for each byte of the 33 byte key)
        assert_eq!(wallet.pubkey_compressed.len(), 66);
        
        // Convert hex to bytes for byte checking
        let compressed_bytes = hex::decode(&wallet.pubkey_compressed).unwrap();
        assert!(
            compressed_bytes[0] == 0x02 || compressed_bytes[0] == 0x03,
            "Compressed pubkey should start with 0x02 or 0x03"
        );

        // Check uncompressed key format (hex string should be 130 chars - 2 for each byte of the 65 byte key)
        assert_eq!(wallet.pubkey_uncompressed.len(), 130);
        
        // Convert hex to bytes for byte checking
        let uncompressed_bytes = hex::decode(&wallet.pubkey_uncompressed).unwrap();
        assert_eq!(uncompressed_bytes[0], 0x04, 
            "Uncompressed pubkey should start with 0x04");

        // Debug output
        println!("Private Key: {}", wallet.privkey);
        println!("Compressed Public Key: {}", wallet.pubkey_compressed);
        println!("Uncompressed Public Key: {}", wallet.pubkey_uncompressed);
        println!("Ethereum Address: {}", wallet.address);
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
        let is_valid = eth_signature.verify_ethereum_signature().unwrap_or_else(|e| panic!("Failed to verify signature: {}", e));
        println!("Signature is valid: {}", is_valid);
        assert!(is_valid, "Signature verification failed");
    }
}
