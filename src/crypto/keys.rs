//! Ed25519 key management for v3 Onion Services

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest as Sha2Digest, Sha512};
use std::path::Path;

/// Master identity key pair
#[derive(Clone)]
pub struct MasterIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    /// The clamped private scalar from the expanded key (for blinding operations)
    private_scalar: [u8; 32],
    /// The PRF secret (k) - bytes 32-64 of the expanded key, used for blinded signing
    /// This is required for deriving k' = H("Derive temporary signing key hash input" || k)[:32]
    prf_secret: [u8; 32],
}

impl MasterIdentity {
    /// Create from raw seed bytes (32 bytes)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();

        // Derive the expanded key from the seed via SHA-512
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let expanded = hasher.finalize();

        // First 32 bytes (clamped) = private scalar
        let mut private_scalar = [0u8; 32];
        private_scalar.copy_from_slice(&expanded[..32]);
        // Apply Ed25519 clamping
        private_scalar[0] &= 248;
        private_scalar[31] &= 63;
        private_scalar[31] |= 64;

        // Second 32 bytes = PRF secret (k)
        let mut prf_secret = [0u8; 32];
        prf_secret.copy_from_slice(&expanded[32..64]);

        Self {
            signing_key,
            verifying_key,
            private_scalar,
            prf_secret,
        }
    }

    /// Create from expanded secret key with explicit public key
    ///
    /// This is used for Tor's key format where the secret key is already expanded
    /// and we have the public key from a separate file.
    pub fn from_expanded_with_pubkey(expanded: &[u8; 64], pubkey: [u8; 32]) -> Result<Self> {
        // For Tor's expanded format:
        // - bytes 0-31: the clamped private scalar
        // - bytes 32-63: the "nonce" or "prefix" for signing (PRF secret k)
        //
        // We'll create a signing key from the seed-like derivation of the first 32 bytes,
        // but use the explicit public key for verification/address derivation.
        // We also store the private scalar for blinding operations.

        let mut private_scalar = [0u8; 32];
        private_scalar.copy_from_slice(&expanded[..32]);

        // The private scalar in Tor's expanded format should already be clamped,
        // but let's make sure
        private_scalar[0] &= 248;
        private_scalar[31] &= 63;
        private_scalar[31] |= 64;

        // Extract the PRF secret (k) - bytes 32-63 of expanded key
        let mut prf_secret = [0u8; 32];
        prf_secret.copy_from_slice(&expanded[32..64]);

        // We need a SigningKey for the sign() method.
        // This is tricky because ed25519-dalek expects to derive keys from seeds.
        // As a workaround, we use a seed that won't match the expanded format.
        // Signing with this won't produce valid signatures for the original key,
        // but that's okay because we use the blinded key for descriptor signing.
        let signing_key = SigningKey::from_bytes(&expanded[..32].try_into().unwrap());

        let verifying_key =
            VerifyingKey::from_bytes(&pubkey).context("Invalid public key bytes")?;

        Ok(Self {
            signing_key,
            verifying_key,
            private_scalar,
            prf_secret,
        })
    }

    /// Get the public verifying key
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get raw public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get the private scalar for blinding operations
    pub fn private_scalar(&self) -> &[u8; 32] {
        &self.private_scalar
    }

    /// Get the PRF secret (k) for blinded signing operations
    ///
    /// This is the second 32 bytes of the expanded private key, used to derive
    /// k' = H("Derive temporary signing key hash input" || k)[:32] for blinded signatures.
    pub fn prf_secret(&self) -> &[u8; 32] {
        &self.prf_secret
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Derive the v3 onion address from public key
    pub fn onion_address(&self) -> String {
        // v3 address = base32(pubkey || checksum || version)
        let pubkey = self.public_key_bytes();

        // Checksum = H(".onion checksum" || pubkey || version)[:2]
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(&pubkey);
        hasher.update(&[0x03]); // version 3
        let checksum = hasher.finalize();

        // Build address bytes
        let mut addr_bytes = [0u8; 35];
        addr_bytes[..32].copy_from_slice(&pubkey);
        addr_bytes[32..34].copy_from_slice(&checksum[..2]);
        addr_bytes[34] = 0x03;

        // Base32 encode (lowercase, no padding)
        let encoded = base32_encode(&addr_bytes);
        format!("{}.onion", encoded.to_lowercase())
    }
}

/// Load identity key from file
///
/// Supports Tor's expanded key format (64 bytes) or seed (32 bytes)
/// Also handles Tor's format with text header (96 bytes with "== ed25519v1-secret" header)
/// If a companion public key file exists, uses the public key from there for accuracy
pub fn load_identity_key(path: &Path) -> Result<MasterIdentity> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read key file: {:?}", path))?;

    // Try to load accompanying public key file for accurate public key
    // First try Tor's naming convention: hs_ed25519_secret_key -> hs_ed25519_public_key
    let path_str = path.to_string_lossy();
    let pub_path = if path_str.ends_with("hs_ed25519_secret_key") {
        path.parent()
            .map(|p| p.join("hs_ed25519_public_key"))
            .unwrap_or_else(|| path.with_extension("pub"))
    } else {
        // Fallback: try .pub extension
        path.with_extension("pub")
    };

    let pubkey_bytes = if pub_path.exists() {
        let pub_data = std::fs::read(&pub_path)
            .with_context(|| format!("Failed to read public key file: {:?}", pub_path))?;

        // Handle Tor's public key format: 32-byte header + 32-byte pubkey
        if pub_data.len() == 64 && pub_data.starts_with(b"== ed25519v1-pub") {
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&pub_data[32..64]);
            tracing::info!("Loaded public key from Tor format .pub file");
            Some(pubkey)
        } else if pub_data.len() == 32 {
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&pub_data);
            Some(pubkey)
        } else {
            tracing::warn!("Public key file has unexpected format, deriving from secret");
            None
        }
    } else {
        None
    };

    // Check for Tor's text header format
    // Format: "== ed25519v1-secret: type0 ==" (32 bytes) + 64 bytes of key data
    if bytes.len() == 96 && bytes.starts_with(b"== ed25519v1-secret") {
        // Skip 32-byte header
        // The next 64 bytes are the expanded secret key (clamped scalar + PRF secret)
        if let Some(pubkey) = pubkey_bytes {
            // Create identity with the known public key
            let mut expanded = [0u8; 64];
            expanded.copy_from_slice(&bytes[32..96]);

            tracing::info!("Loaded Tor format identity key with separate public key");
            return MasterIdentity::from_expanded_with_pubkey(&expanded, pubkey);
        }
        // Tor format keys REQUIRE the .pub file because we can't derive the
        // public key from an already-expanded secret key
        bail!("Tor format key file requires accompanying .pub file (hs_ed25519_public_key)");
    }

    match bytes.len() {
        32 => {
            // Raw seed
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Ok(MasterIdentity::from_seed(&seed))
        },
        64 => {
            // Tor expanded format without header - first 32 bytes are clamped scalar
            // This is NOT a seed - we need to treat it as an expanded key
            if let Some(pubkey) = pubkey_bytes {
                let mut expanded = [0u8; 64];
                expanded.copy_from_slice(&bytes);
                tracing::info!("Loaded 64-byte Tor expanded key with separate public key");
                Ok(MasterIdentity::from_expanded_with_pubkey(
                    &expanded, pubkey,
                )?)
            } else {
                // Without public key file, we can derive it from the scalar
                // But this is complex - for now, require the pubkey file
                bail!("64-byte key file requires accompanying .pub file for Tor format keys");
            }
        },
        96 => {
            // Tor expanded + public key format (without standard header)
            // Check if it might be a different format
            if let Some(pubkey) = pubkey_bytes {
                // Assume first 64 bytes are expanded key, ignore last 32
                let mut expanded = [0u8; 64];
                expanded.copy_from_slice(&bytes[..64]);
                tracing::info!("Loaded 96-byte key with separate public key");
                Ok(MasterIdentity::from_expanded_with_pubkey(
                    &expanded, pubkey,
                )?)
            } else {
                bail!("96-byte key file requires accompanying .pub file");
            }
        },
        other => {
            bail!(
                "Invalid key file size: {} bytes (expected 32, 64, or 96)",
                other
            );
        },
    }
}

/// Simple base32 encoding (RFC 4648, no padding)
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u64);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }

    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        result.push(ALPHABET[idx] as char);
    }

    result
}

/// Simple base32 decoding (RFC 4648)
fn base32_decode(data: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;

    for c in data.chars() {
        let c_upper = c.to_ascii_uppercase();
        let idx = ALPHABET.iter().position(|&x| x as char == c_upper)?;
        buffer = (buffer << 5) | (idx as u64);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            result.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    Some(result)
}

/// Extract the ed25519 public key from a v3 onion address
///
/// A v3 .onion address is: base32(pubkey || checksum || version)
/// - pubkey: 32 bytes
/// - checksum: 2 bytes (H(".onion checksum" || pubkey || version)[:2])
/// - version: 1 byte (0x03)
pub fn pubkey_from_onion_address(onion_addr: &str) -> Result<VerifyingKey> {
    // Strip .onion suffix and normalize
    let addr = onion_addr
        .trim()
        .to_lowercase()
        .trim_end_matches(".onion")
        .to_uppercase();

    // v3 addresses are 56 base32 characters
    if addr.len() != 56 {
        bail!(
            "Invalid v3 onion address length: {} (expected 56)",
            addr.len()
        );
    }

    // Base32 decode
    let decoded = base32_decode(&addr)
        .with_context(|| format!("Failed to base32 decode onion address: {}", addr))?;

    if decoded.len() < 35 {
        bail!("Decoded address too short: {} bytes", decoded.len());
    }

    // Extract components
    let pubkey_bytes = &decoded[..32];
    let checksum = &decoded[32..34];
    let version = decoded[34];

    // Verify version
    if version != 0x03 {
        bail!("Invalid onion address version: {} (expected 3)", version);
    }

    // Verify checksum
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey_bytes);
    hasher.update(&[0x03]);
    let computed_checksum = hasher.finalize();

    if &computed_checksum[..2] != checksum {
        bail!("Onion address checksum mismatch");
    }

    // Convert to VerifyingKey
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(pubkey_bytes);
    VerifyingKey::from_bytes(&key_array).context("Invalid ed25519 public key in onion address")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let seed = [0u8; 32];
        let identity = MasterIdentity::from_seed(&seed);
        let addr = identity.onion_address();
        assert!(addr.ends_with(".onion"));
        assert_eq!(addr.len(), 56 + 6); // 56 chars + ".onion"
    }

    #[test]
    fn test_pubkey_roundtrip() {
        // Generate a key, get its address, extract pubkey back
        let seed = [42u8; 32];
        let identity = MasterIdentity::from_seed(&seed);
        let addr = identity.onion_address();

        let extracted_key = pubkey_from_onion_address(&addr).unwrap();
        assert_eq!(
            extracted_key.as_bytes(),
            identity.public_key().as_bytes(),
            "Extracted public key should match original"
        );
    }

    #[test]
    fn test_real_onion_address() {
        // Test with a known v3 onion address format
        let dread_addr = "dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion";
        let result = pubkey_from_onion_address(dread_addr);
        assert!(
            result.is_ok(),
            "Should parse valid v3 address: {:?}",
            result
        );
    }
}
