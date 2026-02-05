//! Join token format for cluster membership
//!
//! Tokens contain:
//! - Master identity key (encrypted)
//! - Initiator's WireGuard public key
//! - Initiator's endpoint
//! - Cluster ID (derived from master key)
//!
//! Format: base64url(encrypted_payload)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Token version for forward compatibility
const TOKEN_VERSION: u8 = 1;

/// Nonce size for AES-GCM (96 bits)
const NONCE_SIZE: usize = 12;

/// Join token payload (before encryption)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinTokenPayload {
    /// Token version
    pub version: u8,
    /// Master identity key seed (32 bytes)
    pub master_key_seed: [u8; 32],
    /// Master onion address
    pub master_onion: String,
    /// Initiator's WireGuard public key (32 bytes)
    pub initiator_wg_pubkey: [u8; 32],
    /// Initiator's public endpoint (IP:port)
    pub initiator_endpoint: String,
    /// Cluster ID (first 8 bytes of master pubkey hash)
    pub cluster_id: [u8; 8],
    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
}

/// Encrypted token container
#[derive(Debug, Clone)]
pub struct JoinToken {
    /// Encryption nonce
    nonce: [u8; NONCE_SIZE],
    /// Encrypted payload
    ciphertext: Vec<u8>,
}

impl JoinToken {
    /// Create a new token from payload, encrypted with password
    pub fn create(payload: &JoinTokenPayload, password: &str) -> Result<Self> {
        let key = derive_key(password);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("valid key size");

        // Generate random nonce
        let nonce_bytes = crate::util::rand::random_bytes::<NONCE_SIZE>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Serialize and encrypt payload
        let plaintext = serde_json::to_vec(payload).context("Failed to serialize token payload")?;

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(Self {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt and parse token
    pub fn decrypt(&self, password: &str) -> Result<JoinTokenPayload> {
        let key = derive_key(password);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("valid key size");
        let nonce = Nonce::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|_| {
                anyhow::anyhow!("Decryption failed - invalid password or corrupted token")
            })?;

        let payload: JoinTokenPayload =
            serde_json::from_slice(&plaintext).context("Failed to parse token payload")?;

        if payload.version != TOKEN_VERSION {
            bail!(
                "Unsupported token version: {} (expected {})",
                payload.version,
                TOKEN_VERSION
            );
        }

        Ok(payload)
    }

    /// Encode token to base64url string
    pub fn encode(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        // Format: version || nonce || ciphertext
        let mut data = Vec::with_capacity(1 + NONCE_SIZE + self.ciphertext.len());
        data.push(TOKEN_VERSION);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.ciphertext);

        URL_SAFE_NO_PAD.encode(&data)
    }

    /// Decode token from base64url string
    pub fn decode(encoded: &str) -> Result<Self> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let data = URL_SAFE_NO_PAD
            .decode(encoded)
            .context("Invalid base64 encoding")?;

        if data.len() < 1 + NONCE_SIZE + 16 {
            // 16 = minimum ciphertext (tag only)
            bail!("Token too short");
        }

        let version = data[0];
        if version != TOKEN_VERSION {
            bail!(
                "Unsupported token version: {} (expected {})",
                version,
                TOKEN_VERSION
            );
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[1..1 + NONCE_SIZE]);
        let ciphertext = data[1 + NONCE_SIZE..].to_vec();

        Ok(Self { nonce, ciphertext })
    }
}

/// Derive encryption key from password using SHA-256
fn derive_key(password: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // Simple key derivation - could use Argon2 for production
    let mut hasher = Sha256::new();
    hasher.update(b"rustbalance-token-v1:");
    hasher.update(password.as_bytes());
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Generate cluster ID from master public key
pub fn cluster_id_from_pubkey(pubkey: &[u8; 32]) -> [u8; 8] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"rustbalance-cluster:");
    hasher.update(pubkey);
    let result = hasher.finalize();

    let mut id = [0u8; 8];
    id.copy_from_slice(&result[..8]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_roundtrip() {
        let payload = JoinTokenPayload {
            version: TOKEN_VERSION,
            master_key_seed: [1u8; 32],
            master_onion: "example.onion".to_string(),
            initiator_wg_pubkey: [2u8; 32],
            initiator_endpoint: "192.168.1.1:51820".to_string(),
            cluster_id: [3u8; 8],
            created_at: 1_234_567_890,
        };

        let password = "test-password-123";
        let token = JoinToken::create(&payload, password).unwrap();
        let encoded = token.encode();

        let decoded = JoinToken::decode(&encoded).unwrap();
        let decrypted = decoded.decrypt(password).unwrap();

        assert_eq!(decrypted.master_key_seed, payload.master_key_seed);
        assert_eq!(decrypted.master_onion, payload.master_onion);
        assert_eq!(decrypted.initiator_wg_pubkey, payload.initiator_wg_pubkey);
        assert_eq!(decrypted.initiator_endpoint, payload.initiator_endpoint);
    }

    #[test]
    fn test_wrong_password() {
        let payload = JoinTokenPayload {
            version: TOKEN_VERSION,
            master_key_seed: [1u8; 32],
            master_onion: "example.onion".to_string(),
            initiator_wg_pubkey: [2u8; 32],
            initiator_endpoint: "192.168.1.1:51820".to_string(),
            cluster_id: [3u8; 8],
            created_at: 1_234_567_890,
        };

        let token = JoinToken::create(&payload, "correct-password").unwrap();
        let encoded = token.encode();
        let decoded = JoinToken::decode(&encoded).unwrap();

        assert!(decoded.decrypt("wrong-password").is_err());
    }
}
