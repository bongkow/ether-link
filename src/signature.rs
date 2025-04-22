pub struct EthereumSignature {
    pub expected_address: String,
    pub signed_message: String,
    pub signature: String,
}

impl EthereumSignature {
    pub fn new(expected_address: String, signed_message: String, signature: String) -> Self {
        Self { expected_address, signed_message, signature }
    }
    // Verify the signature of a message
    pub fn verify_ethereum_signature(&self) -> Result<bool, String> {
        use ethers::core::types::{Address, Signature};
        use ethers::utils::hash_message;
        use std::str::FromStr;

        // Parse the signature and address
        let signature = Signature::from_str(&self.signature).map_err(|e| e.to_string())?;
        let expected_address = Address::from_str(&self.expected_address).map_err(|e| e.to_string())?;
        
        // Hash the message as per Ethereum signed message format
        let message_hash = hash_message(&self.signed_message);
        
        // Recover the address that signed the message
        let recovered_address = signature.recover(message_hash).map_err(|e| e.to_string())?;
        
        // Compare the recovered address with the expected address
        Ok(recovered_address == expected_address)
    }
}
