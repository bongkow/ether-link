use k256::{
    ecdsa::SigningKey,
    elliptic_curve::rand_core::OsRng,
};
use sha3::{Digest, Keccak256};

pub struct Wallet {
    pub address: String,
    pub privkey: String,
    pub pubkey_compressed: String,
    pub pubkey_uncompressed: String,
}

impl Wallet {
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


