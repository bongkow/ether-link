use k256::{
    ecdsa::SigningKey,
    elliptic_curve::rand_core::OsRng,
    PublicKey,
    SecretKey,
};
use sha3::{Digest, Keccak256};
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use rand::RngCore;

pub struct Wallet {
    pub address: String,
    pub privkey: String,
    pub pubkey_compressed: String,
    pub pubkey_uncompressed: String,
}

impl Wallet {
    // Generate a new Ethereum key pair
    pub fn new() -> Self {
        Self::from_private_key(None)
    }

    // Create a wallet from an existing private key or generate a new one if None
    pub fn from_private_key(private_key_hex: Option<&str>) -> Self {
        let private_key = match private_key_hex {
            Some(hex_key) => {
                // Convert hex string to bytes
                let key_bytes = hex::decode(hex_key.trim_start_matches("0x"))
                    .expect("Invalid private key format");
                
                // Create SigningKey from bytes
                let secret_key = SecretKey::from_slice(&key_bytes)
                    .expect("Invalid private key");
                SigningKey::from(secret_key)
            },
            None => {
                // Generate random key
                SigningKey::random(&mut OsRng)
            }
        };

        let privkey_hex = format!("0x{}", hex::encode(private_key.to_bytes()));

        let public_key = private_key.verifying_key();
        // Compressed public key (starts with 0x02 or 0x03)
        let pubkey_compressed = public_key.to_encoded_point(true).as_bytes().to_vec();
        let pubkey_compressed_hex = format!("0x{}", hex::encode(&pubkey_compressed));
        // Uncompressed public key (starts with 0x04)
        let pubkey_uncompressed = public_key.to_encoded_point(false).as_bytes().to_vec();
        let pubkey_uncompressed_hex = format!("0x{}", hex::encode(&pubkey_uncompressed));
        
        // Ethereum address (last 20 bytes of keccak256 of uncompressed key without prefix)
        let hash = Keccak256::digest(&pubkey_uncompressed[1..]); // remove 0x04 prefix
        let address = format!("0x{}", hex::encode(&hash[12..]));

        Self {
            address,
            privkey: privkey_hex,
            pubkey_compressed: pubkey_compressed_hex,
            pubkey_uncompressed: pubkey_uncompressed_hex,
        }
    }
    // Sign a message with the private key
    pub async fn sign_message(&self, message: &str) -> Result<String, String> {
        use ethers::core::types::Signature;
        use ethers::signers::{LocalWallet, Signer};
        use ethers::core::k256::SecretKey;
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Convert hex private key to SecretKey
        let secret_bytes = hex::decode(self.privkey.trim_start_matches("0x")).map_err(|e| e.to_string())?;
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
    
    // Encrypt a message using EIP-5630 compliant ECIES encryption
    pub fn encrypt_message(&self, message: &str, recipient_compressed_pubkey: &str) -> Result<String, String> {
        // Step 1: Parse the recipient's public key
        let recipient_pubkey_bytes = hex::decode(recipient_compressed_pubkey.trim_start_matches("0x"))
            .map_err(|e| format!("Invalid recipient public key: {}", e))?;
        
        let recipient_public_key = PublicKey::from_sec1_bytes(&recipient_pubkey_bytes)
            .map_err(|e| format!("Failed to parse recipient public key: {}", e))?;
            
        // Step 3: Generate ephemeral key pair for ECIES
        let ephemeral_private_key = SigningKey::random(&mut OsRng);
        let ephemeral_public_key = ephemeral_private_key.verifying_key();
        
        // Step 4: Perform ECDH to derive shared secret
        let shared_secret = {
            use ethers::core::k256::ecdh::diffie_hellman;
            let secret = diffie_hellman(
                ephemeral_private_key.as_nonzero_scalar(), 
                recipient_public_key.as_affine()
            );
            secret.raw_secret_bytes().to_vec()
        };
        
        // Step 5: Derive encryption key using HKDF-SHA256
        let kdf = Hkdf::<Keccak256>::new(None, &shared_secret);
        let mut derived_key = [0u8; 32]; // 256 bits for AES-256-GCM
        kdf.expand(b"EIP-5630-ECIES-AES-256-GCM", &mut derived_key)
            .map_err(|_| "HKDF expansion failed".to_string())?;
        
        // Step 6: Generate random nonce for AES-GCM
        let mut nonce_bytes = [0u8; 12]; // 96 bits
        rand::rng().fill_bytes(&mut nonce_bytes);
        
        // Step 7: Encrypt the message using AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|_| "Failed to create cipher".to_string())?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, message.as_bytes().as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Step 8: Prepare the ephemeral public key for transmission
        let ephemeral_pubkey_bytes = ephemeral_public_key.to_encoded_point(true).as_bytes().to_vec();
        
        // Step 9: Format according to EIP-5630 (ephemeral_pubkey || nonce || ciphertext)
        let encrypted_data = [
            ephemeral_pubkey_bytes.as_slice(),
            &nonce_bytes,
            ciphertext.as_slice(),
        ].concat();
        
        // Return as hex string with 0x prefix
        Ok(format!("0x{}", hex::encode(encrypted_data)))
    }
    pub fn decrypt_message(&self, encrypted_message: &str) -> Result<String, String> {
        // Step 1: Decode the encrypted message
        let encrypted_data = hex::decode(encrypted_message.trim_start_matches("0x"))
            .map_err(|e| format!("Invalid encrypted message: {}", e))?;

        // Ensure message has minimum required length (33 bytes pubkey + 12 bytes nonce + at least 16 bytes ciphertext)
        if encrypted_data.len() < 33 + 12 + 16 {
            return Err("Encrypted message is too short".to_string());
        }

        // Step 2: Extract components from encrypted data (ephemeral_pubkey || nonce || ciphertext)
        let ephemeral_pubkey_bytes = &encrypted_data[0..33]; // Compressed public key is 33 bytes
        let nonce_bytes = &encrypted_data[33..45]; // 12 bytes nonce
        let ciphertext = &encrypted_data[45..]; // Rest is ciphertext

        // Step 3: Parse the ephemeral public key
        let ephemeral_public_key = PublicKey::from_sec1_bytes(ephemeral_pubkey_bytes)
            .map_err(|e| format!("Failed to parse ephemeral public key: {}", e))?;

        // Step 4: Parse our private key for ECDH
        let private_key_bytes = hex::decode(self.privkey.trim_start_matches("0x"))
            .map_err(|e| format!("Failed to decode private key: {}", e))?;
        
        // Use SecretKey for conversion
        let secret_key = SecretKey::from_slice(&private_key_bytes)
            .map_err(|e| format!("Failed to create secret key: {}", e))?;
        let private_key = SigningKey::from(secret_key);

        // Step 5: Perform ECDH to derive shared secret (same as in encrypt but with roles reversed)
        let shared_secret = {
            use ethers::core::k256::ecdh::diffie_hellman;
            let secret = diffie_hellman(
                private_key.as_nonzero_scalar(),
                ephemeral_public_key.as_affine()
            );
            secret.raw_secret_bytes().to_vec()
        };

        // Step 6: Derive encryption key using HKDF-SHA256 (same as in encrypt)
        let kdf = Hkdf::<Keccak256>::new(None, &shared_secret);
        let mut derived_key = [0u8; 32]; // 256 bits for AES-256-GCM
        kdf.expand(b"EIP-5630-ECIES-AES-256-GCM", &mut derived_key)
            .map_err(|_| "HKDF expansion failed".to_string())?;
        // Step 7: Decrypt the message using AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|_| "Failed to create cipher".to_string())?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| "Decryption failed".to_string())?;

        // Step 8: Convert plaintext bytes to string
        let message = String::from_utf8(plaintext)
            .map_err(|e| format!("Failed to decode message: {}", e))?;

        Ok(message)
    }
    
}


