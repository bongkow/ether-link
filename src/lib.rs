use k256::{
    ecdsa::SigningKey,
    elliptic_curve::rand_core::OsRng,
};
use sha3::{Digest, Keccak256};

pub struct EthKeyPair {
    pub address: String,
    pub privkey: String,
    pub pubkey_compressed: String,
    pub pubkey_uncompressed: String,
}

impl EthKeyPair {
    // Generate a new Ethereum key pair
    pub fn new() -> Self {
        let private_key = SigningKey::random(&mut OsRng);
        let privkey_hex = hex::encode(private_key.to_bytes());

        let public_key = private_key.verifying_key();
        // Compressed public key (starts with 0x02 or 0x03)
        let pubkey_compressed = public_key.to_encoded_point(true).as_bytes().to_vec();
        let pubkey_compressed_hex = hex::encode(&pubkey_compressed);
        // Uncompressed public key (starts with 0x04)
        let pubkey_uncompressed = public_key.to_encoded_point(false).as_bytes().to_vec();
        let pubkey_uncompressed_hex = hex::encode(&pubkey_uncompressed);
        
        // Ethereum address (last 20 bytes of keccak256 of uncompressed key without prefix)
        let hash = Keccak256::digest(&pubkey_uncompressed[1..]); // remove 0x04 prefix
        let address = format!("0x{}", hex::encode(&hash[12..]));

        Self {
            address,
            privkey: privkey_hex,
            pubkey_compressed:pubkey_compressed_hex,
            pubkey_uncompressed:pubkey_uncompressed_hex,
        }
    }
    // Sign a message with the private key
    pub async fn sign_message(&self, message: &str) -> Result<String, String> {
        use ethers::core::types::Signature;
        use ethers::signers::{LocalWallet, Signer};
        use ethers::core::k256::SecretKey;
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Convert hex private key to SecretKey
        let secret_bytes = hex::decode(&self.privkey).map_err(|e| e.to_string())?;
        let secret_key = SecretKey::from_slice(&secret_bytes).map_err(|e| e.to_string())?;
        let wallet = LocalWallet::from(secret_key);
        
        let address = &self.address;
        let timestamps = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let message_with_timestamp = format!("{}:{}", message, timestamps);
        
        // Verify the wallet address matches our derived address
        let wallet_addr = format!("0x{}", hex::encode(wallet.address().as_bytes()));
        debug_assert_eq!(wallet_addr.to_lowercase(), address.to_lowercase());

        // Sign the hash with the private key
        let signature: Signature = wallet
            .sign_message(message_with_timestamp.clone())
            .await
            .map_err(|e| e.to_string())?;

        // Return a JSON string containing both the message and signature for verification
        let result = serde_json::json!({
            "address": address,
            "signed_message": message_with_timestamp,
            "signature": format!("0x{}", hex::encode(signature.to_vec())),
        });
        Ok(result.to_string())
    }
}

    // Verify the signature of a message
    pub fn verify_ethereum_signature(message: &str, signature: &str, address: &str) -> Result<bool, String> {
        use ethers::core::types::{Address, Signature};
        use ethers::utils::hash_message;
        use std::str::FromStr;

        // Parse the signature and address
        let signature = Signature::from_str(signature).map_err(|e| e.to_string())?;
        let expected_address = Address::from_str(address).map_err(|e| e.to_string())?;
        
        // Hash the message as per Ethereum signed message format
        let message_hash = hash_message(message);
        
        // Recover the address that signed the message
        let recovered_address = signature.recover(message_hash).map_err(|e| e.to_string())?;
        
        // Compare the recovered address with the expected address
        Ok(recovered_address == expected_address)
    }

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[tokio::test]
    async fn test_sign_message() {
        let keypair = EthKeyPair::new();
        let message = "Hello, world!";
        let signature = keypair.sign_message(message).await.unwrap_or_else(|e| panic!("Failed to sign message: {}", e));
        
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
        let keypair = EthKeyPair::new();

        // Check that the address is 42 chars: "0x" + 40 hex digits
        assert_eq!(keypair.address.len(), 42);
        assert!(keypair.address.starts_with("0x"));

        // Check compressed key format (hex string should be 66 chars - 2 for each byte of the 33 byte key)
        assert_eq!(keypair.pubkey_compressed.len(), 66);
        
        // Convert hex to bytes for byte checking
        let compressed_bytes = hex::decode(&keypair.pubkey_compressed).unwrap();
        assert!(
            compressed_bytes[0] == 0x02 || compressed_bytes[0] == 0x03,
            "Compressed pubkey should start with 0x02 or 0x03"
        );

        // Check uncompressed key format (hex string should be 130 chars - 2 for each byte of the 65 byte key)
        assert_eq!(keypair.pubkey_uncompressed.len(), 130);
        
        // Convert hex to bytes for byte checking
        let uncompressed_bytes = hex::decode(&keypair.pubkey_uncompressed).unwrap();
        assert_eq!(uncompressed_bytes[0], 0x04, 
            "Uncompressed pubkey should start with 0x04");

        // Debug output
        println!("Private Key: {}", keypair.privkey);
        println!("Compressed Public Key: {}", keypair.pubkey_compressed);
        println!("Uncompressed Public Key: {}", keypair.pubkey_uncompressed);
        println!("Ethereum Address: {}", keypair.address);
    }

    #[tokio::test]
    async fn test_check_signature_is_valid() {
        let keypair = EthKeyPair::new();
        let message = "Hello, world!";
        
        // Sign the message
        let signature = keypair.sign_message(message)
            .await
            .unwrap_or_else(|e| panic!("Failed to sign message: {}", e));
        
        // Parse the signature JSON
        let sig_json: serde_json::Value = serde_json::from_str(&signature)
            .unwrap_or_else(|e| panic!("Failed to parse signature JSON: {}", e));
        
        // Get the signature components with better error handling
        let address = sig_json["address"].as_str()
            .expect("Missing 'address' field in signature JSON");
        let signed_message = sig_json["signed_message"].as_str()
            .expect("Missing 'signed_message' field in signature JSON"); 
        let signature_hex = sig_json["signature"].as_str()
            .expect("Missing 'signature' field in signature JSON");
        
        // Verify the signature matches the message and address
        let is_valid = verify_ethereum_signature(
            signed_message,
            signature_hex,
            address
        ).expect("Signature verification failed");
        
        assert!(is_valid, "Signature verification failed");
    }
}
