//! Descriptor encryption and signing for v3 Onion Services
//!
//! Implements Tor rend-spec-v3 descriptor format:
//! - Outer layer: signed with blinded key
//! - Middle layer: encrypted with subcredential
//! - Inner layer: contains introduction points

use aes::Aes256;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use ctr::cipher::{KeyIvInit, StreamCipher};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest as Sha2Digest, Sha512};
use sha3::digest::{ExtendableOutput, Update as XofUpdate, XofReader};
use sha3::{Digest, Sha3_256, Shake256};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use super::blinding::{
    blind_identity, blind_private_key, current_time_period, derive_subcredential,
};
use super::keys::MasterIdentity;
use crate::tor::{IntroductionPoint, LinkSpecifier};

/// AES-256-CTR cipher type
type Aes256Ctr = ctr::Ctr64BE<Aes256>;

/// Descriptor builder for creating v3 onion service descriptors
pub struct DescriptorBuilder<'a> {
    identity: &'a MasterIdentity,
    revision_counter: u64,
    /// Ephemeral descriptor signing keypair - generated fresh for each descriptor
    desc_signing_key: SigningKey,
}

impl<'a> DescriptorBuilder<'a> {
    /// Create a new descriptor builder
    pub fn new(identity: &'a MasterIdentity, revision_counter: u64) -> Self {
        // Generate a fresh ephemeral descriptor signing keypair
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let desc_signing_key = SigningKey::from_bytes(&seed);

        Self {
            identity,
            revision_counter,
            desc_signing_key,
        }
    }

    /// Build a complete v3 descriptor
    pub fn build(&self, intro_points: &[IntroductionPoint]) -> Result<DescriptorOutput> {
        let time_period = current_time_period();
        self.build_for_period(intro_points, time_period)
    }

    /// Build a complete v3 descriptor for a specific time period
    ///
    /// Per rend-spec-v3 §2.2.1, a service must publish descriptors for both
    /// the current AND the next time period. Use this method to build
    /// a descriptor for each.
    pub fn build_for_period(
        &self,
        intro_points: &[IntroductionPoint],
        time_period: u64,
    ) -> Result<DescriptorOutput> {
        // Convert time_period to timestamp for blinding (multiply by period length in seconds)
        let time_period_secs = time_period * 86400;

        // Step 1: Compute blinded key for this time period
        let blinded_key = blind_identity(self.identity.public_key(), time_period_secs, None);

        // Step 2: Compute subcredential
        let subcredential = derive_subcredential(self.identity.public_key(), &blinded_key);

        // Step 3: Build and encrypt inner layer (intro points)
        // String constant: "hsdir-encrypted-data" for inner layer
        let inner_plaintext = self.build_inner_layer(intro_points);
        let inner_encrypted = self.encrypt_layer(
            &inner_plaintext,
            &blinded_key,
            &subcredential,
            b"hsdir-encrypted-data",
        )?;

        // Step 4: Build and encrypt middle layer
        // String constant: "hsdir-superencrypted-data" for outer/superencrypted layer
        let middle_plaintext = self.build_middle_layer(&inner_encrypted);
        let middle_encrypted = self.encrypt_layer(
            &middle_plaintext,
            &blinded_key,
            &subcredential,
            b"hsdir-superencrypted-data",
        )?;

        // Step 5: Build outer layer (signed with ephemeral desc signing key)
        let outer_descriptor =
            self.build_outer_layer(&blinded_key, &middle_encrypted, time_period_secs)?;

        Ok(DescriptorOutput {
            descriptor: outer_descriptor,
            blinded_key,
            subcredential,
            revision_counter: self.revision_counter,
        })
    }

    /// Build the inner layer containing introduction points
    fn build_inner_layer(&self, intro_points: &[IntroductionPoint]) -> Vec<u8> {
        let mut data = Vec::new();

        // Format: "create2-formats 2\n" followed by intro point entries
        data.extend_from_slice(b"create2-formats 2\n");

        for ip in intro_points {
            // Each intro point starts with "introduction-point"
            data.extend_from_slice(b"introduction-point ");

            // Build link specifiers blob: NSPEC (1 byte) + NSPEC entries
            // Each entry is: LSTYPE (1 byte) + LSLEN (1 byte) + LSDATA (LSLEN bytes)
            let mut ls_blob = Vec::new();
            #[allow(clippy::cast_possible_truncation)] // Link specifier count always small
            ls_blob.push(ip.link_specifiers.len() as u8); // NSPEC

            for spec in &ip.link_specifiers {
                match spec {
                    LinkSpecifier::IPv4 { addr, port } => {
                        ls_blob.push(0); // Type 0 = IPv4
                        ls_blob.push(6); // Length = 4 + 2
                        ls_blob.extend_from_slice(addr);
                        ls_blob.extend_from_slice(&port.to_be_bytes());
                    },
                    LinkSpecifier::IPv6 { addr, port } => {
                        ls_blob.push(1); // Type 1 = IPv6
                        ls_blob.push(18); // Length = 16 + 2
                        ls_blob.extend_from_slice(addr);
                        ls_blob.extend_from_slice(&port.to_be_bytes());
                    },
                    LinkSpecifier::LegacyId(id) => {
                        ls_blob.push(2); // Type 2 = Legacy ID
                        ls_blob.push(20); // Length = 20
                        ls_blob.extend_from_slice(id);
                    },
                    LinkSpecifier::Ed25519Id(id) => {
                        ls_blob.push(3); // Type 3 = Ed25519 ID
                        ls_blob.push(32); // Length = 32
                        ls_blob.extend_from_slice(id);
                    },
                }
            }

            let encoded = base64_encode(&ls_blob);
            data.extend_from_slice(encoded.as_bytes());
            data.push(b'\n');

            // Onion key
            data.extend_from_slice(b"onion-key ntor ");
            data.extend_from_slice(base64_encode(&ip.onion_key).as_bytes());
            data.push(b'\n');

            // Auth key certificate - rebuilt with our descriptor signing key
            // IMPORTANT: We must preserve the original certificate's expiration time
            // to match OnionBalance's recertification behavior
            data.extend_from_slice(b"auth-key\n");
            data.extend_from_slice(b"-----BEGIN ED25519 CERT-----\n");
            if let Some(auth_key) = ip.auth_key() {
                // Get original expiration from the certificate (or use default)
                let orig_expiration = ip.auth_key_cert_expiration();
                // Rebuild the certificate with our descriptor signing key, preserving expiration
                tracing::info!(
                    "Re-signing auth-key cert for intro point (auth_key={}, orig_exp={:?})",
                    hex::encode(&auth_key),
                    orig_expiration
                );
                let new_cert = self.build_auth_key_cert(&auth_key, orig_expiration);
                data.extend_from_slice(base64_encode(&new_cert).as_bytes());
            } else {
                // This should not happen if parsing worked - log an error
                tracing::error!(
                    "Missing auth_key for intro point! auth_key_cert len={}",
                    ip.auth_key_cert.len()
                );
                // Fall back to original cert if we have it (won't work but at least valid format)
                if ip.auth_key_cert.is_empty() {
                    // Create a dummy cert - this intro point won't work
                    tracing::error!("No auth_key_cert available - intro point will be unusable");
                    let dummy_key = [0u8; 32];
                    let dummy_cert = self.build_auth_key_cert(&dummy_key, None);
                    data.extend_from_slice(base64_encode(&dummy_cert).as_bytes());
                } else {
                    data.extend_from_slice(base64_encode(&ip.auth_key_cert).as_bytes());
                }
            }
            data.push(b'\n');
            data.extend_from_slice(b"-----END ED25519 CERT-----\n");

            // Encryption key
            data.extend_from_slice(b"enc-key ntor ");
            data.extend_from_slice(base64_encode(&ip.enc_key).as_bytes());
            data.push(b'\n');

            // Enc key cert - rebuilt with our descriptor signing key
            // IMPORTANT: Per stem's implementation, the enc_key_cert uses the AUTH KEY
            // as the certified key, NOT the enc_key. We must also preserve original expiration.
            data.extend_from_slice(b"enc-key-cert\n");
            data.extend_from_slice(b"-----BEGIN ED25519 CERT-----\n");
            // Get auth_key for the enc_key_cert (stem uses auth_key for both certs)
            if let Some(auth_key) = ip.auth_key() {
                let orig_expiration = ip.enc_key_cert_expiration();
                tracing::debug!(
                    "Re-signing enc-key cert for intro point (using auth_key={}, orig_exp={:?})",
                    hex::encode(&auth_key),
                    orig_expiration
                );
                let new_enc_cert = self.build_enc_key_cert(&auth_key, orig_expiration);
                data.extend_from_slice(base64_encode(&new_enc_cert).as_bytes());
            } else {
                // Fallback: use enc_key if auth_key not available (shouldn't happen)
                tracing::warn!("No auth_key available for enc-key-cert, using enc_key as fallback");
                let orig_expiration = ip.enc_key_cert_expiration();
                let new_enc_cert = self.build_enc_key_cert(&ip.enc_key, orig_expiration);
                data.extend_from_slice(base64_encode(&new_enc_cert).as_bytes());
            }
            data.push(b'\n');
            data.extend_from_slice(b"-----END ED25519 CERT-----\n");
        }

        data
    }

    /// Build the middle layer wrapping the encrypted inner layer
    ///
    /// The middle layer format (per rend-spec) requires:
    /// - desc-auth-type x25519
    /// - desc-auth-ephemeral-key <base64 x25519 pubkey>
    /// - auth-client entries (at least 16 to hide whether auth is enabled)
    /// - encrypted block containing the inner layer
    fn build_middle_layer(&self, encrypted_inner: &[u8]) -> Vec<u8> {
        use rand::RngCore;

        let mut data = Vec::new();

        // Even when restricted discovery is disabled, we must include fake auth fields
        // to avoid leaking whether auth is enabled (per spec)
        data.extend_from_slice(b"desc-auth-type x25519\n");

        // Generate a fresh random ephemeral x25519 keypair (unused when auth disabled)
        let mut ephemeral_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ephemeral_key);
        data.extend_from_slice(b"desc-auth-ephemeral-key ");
        data.extend_from_slice(base64_encode(&ephemeral_key).as_bytes());
        data.push(b'\n');

        // Generate 16 fake auth-client entries (spec requires multiple of 16)
        // Each entry has: client-id (8 bytes), iv (16 bytes), encrypted-cookie (16 bytes)
        for _ in 0..16 {
            let mut client_id = [0u8; 8];
            let mut iv = [0u8; 16];
            let mut encrypted_cookie = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut client_id);
            rand::thread_rng().fill_bytes(&mut iv);
            rand::thread_rng().fill_bytes(&mut encrypted_cookie);

            data.extend_from_slice(b"auth-client ");
            data.extend_from_slice(base64_encode(&client_id).as_bytes());
            data.push(b' ');
            data.extend_from_slice(base64_encode(&iv).as_bytes());
            data.push(b' ');
            data.extend_from_slice(base64_encode(&encrypted_cookie).as_bytes());
            data.push(b'\n');
        }

        // Encrypted inner layer
        data.extend_from_slice(b"encrypted\n");
        data.extend_from_slice(b"-----BEGIN MESSAGE-----\n");

        // Base64 encode the encrypted inner layer in 64-char lines
        let encoded = base64_encode(encrypted_inner);
        for chunk in encoded.as_bytes().chunks(64) {
            data.extend_from_slice(chunk);
            data.push(b'\n');
        }

        data.extend_from_slice(b"-----END MESSAGE-----\n");

        data
    }

    /// Encrypt a layer using Tor's descriptor format: AES-256-CTR + SHA3-256 MAC
    ///
    /// Format: SALT (16 bytes) || ENCRYPTED || MAC (32 bytes)
    ///
    /// Key derivation:
    ///   secret_input = blinded_key || subcredential || INT_8(revision_counter)
    ///   keys = SHAKE-256(secret_input || salt || string_constant, 80)
    ///   SECRET_KEY = keys[0:32]
    ///   SECRET_IV = keys[32:48]
    ///   MAC_KEY = keys[48:80]
    ///
    /// MAC computation:
    ///   MAC = SHA3-256(mac_key_len || MAC_KEY || salt_len || SALT || ENCRYPTED)
    fn encrypt_layer(
        &self,
        plaintext: &[u8],
        blinded_key: &[u8; 32],
        subcredential: &[u8; 32],
        string_constant: &[u8],
    ) -> Result<Vec<u8>> {
        use rand::RngCore;

        // Generate random 16-byte SALT
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);

        // Build secret_input: blinded_key || subcredential || INT_8(revision_counter)
        let mut secret_input = Vec::with_capacity(72);
        secret_input.extend_from_slice(blinded_key);
        secret_input.extend_from_slice(subcredential);
        secret_input.extend_from_slice(&self.revision_counter.to_be_bytes());

        // Derive keys using SHAKE-256 XOF
        // keys = SHAKE-256(secret_input || salt || string_constant, 80)
        let mut hasher = Shake256::default();
        XofUpdate::update(&mut hasher, &secret_input);
        XofUpdate::update(&mut hasher, &salt);
        XofUpdate::update(&mut hasher, string_constant);

        let mut reader = hasher.finalize_xof();
        let mut secret_key = [0u8; 32];
        let mut secret_iv = [0u8; 16];
        let mut mac_key = [0u8; 32];
        reader.read(&mut secret_key);
        reader.read(&mut secret_iv);
        reader.read(&mut mac_key);

        tracing::debug!(
            "encrypt_layer: derived secret_key={}, secret_iv={}, mac_key={}",
            hex::encode(&secret_key),
            hex::encode(&secret_iv),
            hex::encode(&mac_key)
        );

        // Encrypt using AES-256-CTR
        let mut encrypted = plaintext.to_vec();
        let mut cipher = Aes256Ctr::new(&secret_key.into(), &secret_iv.into());
        cipher.apply_keystream(&mut encrypted);

        // Compute MAC: SHA3-256(mac_key_len || MAC_KEY || salt_len || SALT || ENCRYPTED)
        let mut mac_hasher = Sha3_256::new();
        Digest::update(&mut mac_hasher, &(mac_key.len() as u64).to_be_bytes());
        Digest::update(&mut mac_hasher, &mac_key);
        Digest::update(&mut mac_hasher, &(salt.len() as u64).to_be_bytes());
        Digest::update(&mut mac_hasher, &salt);
        Digest::update(&mut mac_hasher, &encrypted);
        let mac = mac_hasher.finalize();

        // Build result: SALT || ENCRYPTED || MAC
        let mut result = Vec::with_capacity(16 + encrypted.len() + 32);
        result.extend_from_slice(&salt);
        result.extend_from_slice(&encrypted);
        result.extend_from_slice(&mac);

        tracing::debug!(
            "encrypt_layer: salt={}, encrypted={} bytes, mac={}",
            hex::encode(&salt),
            encrypted.len(),
            hex::encode(&mac)
        );

        Ok(result)
    }

    /// Build the outer descriptor layer
    fn build_outer_layer(
        &self,
        blinded_key: &[u8; 32],
        encrypted_middle: &[u8],
        time_period: u64,
    ) -> Result<String> {
        let mut desc = String::new();

        // Header
        desc.push_str("hs-descriptor 3\n");
        desc.push_str("descriptor-lifetime 180\n");

        // Descriptor signing key cert (certifies desc_signing_key, signed by blinded key)
        desc.push_str("descriptor-signing-key-cert\n");
        desc.push_str("-----BEGIN ED25519 CERT-----\n");
        let cert = self.build_signing_key_cert(blinded_key, time_period);
        for chunk in base64_encode(&cert).as_bytes().chunks(64) {
            desc.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            desc.push('\n');
        }
        desc.push_str("-----END ED25519 CERT-----\n");

        // Revision counter
        desc.push_str(&format!("revision-counter {}\n", self.revision_counter));

        // Encrypted body
        desc.push_str("superencrypted\n");
        desc.push_str("-----BEGIN MESSAGE-----\n");
        let encoded = base64_encode(encrypted_middle);
        for chunk in encoded.as_bytes().chunks(64) {
            desc.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            desc.push('\n');
        }
        desc.push_str("-----END MESSAGE-----\n");

        // Signature (using ephemeral desc_signing_key, NOT blinded key)
        let sig = self.sign_descriptor(&desc, blinded_key);
        desc.push_str("signature ");
        desc.push_str(&base64_encode_no_pad(&sig));
        desc.push('\n');

        Ok(desc)
    }

    /// Build signing key certificate
    ///
    /// Tor cert format (proposal 220):
    /// - 1 byte: version (0x01)
    /// - 1 byte: cert type (0x08 for BLINDED_ID_V_SIGNING)
    /// - 4 bytes: expiration (hours since epoch)
    /// - 1 byte: cert key type (0x01 for ed25519)
    /// - 32 bytes: certified key (descriptor signing public key)
    /// - 1 byte: n_extensions
    /// - Extension 04: signed-with-ed25519-key (blinded public key)
    ///   - 2 bytes: ext length (32)
    ///   - 1 byte: ext type (0x04)
    ///   - 1 byte: ext flags (0x01 = AFFECTS_VALIDATION)
    ///   - 32 bytes: blinded public key
    /// - 64 bytes: signature (signed with blinded private key)
    fn build_signing_key_cert(&self, blinded_key: &[u8; 32], time_period_secs: u64) -> Vec<u8> {
        let mut cert = Vec::with_capacity(140);

        // Version
        cert.push(0x01);

        // Cert type: 0x08 = BLINDED_ID_V_SIGNING
        cert.push(0x08);

        // Expiration: 3 hours from now (in hours since epoch)
        #[allow(clippy::cast_possible_truncation)]
        let hours_since_epoch = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 3600
            + 3) as u32;
        cert.extend_from_slice(&hours_since_epoch.to_be_bytes());

        // Cert key type: 0x01 = ed25519
        cert.push(0x01);

        // Certified key: the ephemeral descriptor signing public key
        cert.extend_from_slice(self.desc_signing_key.verifying_key().as_bytes());

        // Number of extensions: 1 (the signed-with-ed25519-key extension)
        cert.push(0x01);

        // Extension 04: signed-with-ed25519-key
        cert.extend_from_slice(&32u16.to_be_bytes()); // ExtLen = 32
        cert.push(0x04); // ExtType = 04 (signed-with-ed25519-key)
        cert.push(0x01); // ExtFlags = 01 (AFFECTS_VALIDATION)
        cert.extend_from_slice(blinded_key); // ExtData = blinded public key

        // Sign the cert with the blinded private key
        // Per Tor cert-spec.txt: "The signature is formed by signing the first N-64
        // bytes of the certificate." There is NO prefix for certificate signatures.
        let blinded_private_scalar = blind_private_key(
            self.identity.public_key(),
            self.identity.private_scalar(),
            time_period_secs,
            None,
        );

        // Ed25519 signature using blinded private key with correct k' derivation
        let signature = self.sign_with_blinded_key(
            &cert,
            blinded_key,
            &blinded_private_scalar,
            self.identity.prf_secret(),
        );
        cert.extend_from_slice(&signature);

        // Debug: Log the full certificate hex for analysis
        tracing::info!(
            "build_signing_key_cert: cert_hex={}, len={}, blinded_key_in_ext={}",
            hex::encode(&cert),
            cert.len(),
            hex::encode(blinded_key)
        );

        cert
    }

    /// Sign data with the blinded private key
    ///
    /// This follows the Tor spec for blinded signing:
    /// 1. The blinded private scalar (a') is computed as: a' = a * blinding_factor mod l
    /// 2. The PRF secret k' is computed as: k' = H("Derive temporary signing key hash input" || k)[:32]
    /// 3. The nonce r is computed as: r = H(k' || message) mod l
    /// 4. The signature is: R = r*G, s = r + H(R||A'||message)*a' mod l
    fn sign_with_blinded_key(
        &self,
        data: &[u8],
        blinded_pubkey: &[u8; 32],
        blinded_private_scalar: &[u8; 32],
        prf_secret: &[u8; 32],
    ) -> [u8; 64] {
        tracing::info!(
            "sign_with_blinded_key: blinded_pubkey={}, blinded_private_scalar={}, prf_secret={}",
            hex::encode(blinded_pubkey),
            hex::encode(blinded_private_scalar),
            hex::encode(prf_secret)
        );

        let blinded_scalar = Scalar::from_bytes_mod_order(*blinded_private_scalar);
        tracing::info!(
            "sign_with_blinded_key: blinded_scalar_reduced={}",
            hex::encode(blinded_scalar.as_bytes())
        );

        // Derive the blinded PRF secret k':
        // k' = SHA-512(k || "Derive temporary signing key hash input")[:32]
        // NOTE: stem/OnionBalance uses (prf_secret || personalization) order
        let mut k_prime_hasher = Sha512::new();
        Sha2Digest::update(&mut k_prime_hasher, prf_secret);
        Sha2Digest::update(
            &mut k_prime_hasher,
            b"Derive temporary signing key hash input",
        );
        let k_prime_full = k_prime_hasher.finalize();
        let k_prime = &k_prime_full[..32];
        tracing::info!("sign_with_blinded_key: k_prime={}", hex::encode(k_prime));

        // Derive the nonce deterministically: r = SHA-512(k' || message) mod l
        let mut r_hasher = Sha512::new();
        Sha2Digest::update(&mut r_hasher, k_prime);
        Sha2Digest::update(&mut r_hasher, data);
        let r_hash = r_hasher.finalize();
        let r = Scalar::from_bytes_mod_order_wide(&r_hash.into());
        tracing::info!(
            "sign_with_blinded_key: r_hash={}, r={}",
            hex::encode(&r_hash),
            hex::encode(r.as_bytes())
        );

        // R = r * G
        let big_r = (&r * ED25519_BASEPOINT_TABLE).compress();
        tracing::info!("sign_with_blinded_key: R={}", hex::encode(big_r.as_bytes()));

        // Compute challenge: k = SHA-512(R || A' || data)
        let mut challenge_hasher = Sha512::new();
        Sha2Digest::update(&mut challenge_hasher, big_r.as_bytes());
        Sha2Digest::update(&mut challenge_hasher, blinded_pubkey);
        Sha2Digest::update(&mut challenge_hasher, data);
        let challenge_hash = challenge_hasher.finalize();
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_hash.into());

        // s = r + challenge * a' mod l
        let s = r + challenge * blinded_scalar;
        tracing::info!("sign_with_blinded_key: s={}", hex::encode(s.as_bytes()));

        // Signature is (R, s)
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(big_r.as_bytes());
        signature[32..].copy_from_slice(&s.to_bytes());

        signature
    }

    /// Sign the descriptor with the ephemeral descriptor signing key
    fn sign_descriptor(&self, descriptor: &str, blinded_pubkey: &[u8; 32]) -> [u8; 64] {
        // The signature covers "Tor onion service descriptor sig v3" || descriptor
        let mut message = Vec::new();
        message.extend_from_slice(b"Tor onion service descriptor sig v3");
        message.extend_from_slice(descriptor.as_bytes());

        // Sign with the ephemeral descriptor signing key
        let signature = self.desc_signing_key.sign(&message);

        tracing::debug!(
            "Signed descriptor with desc_signing_key, blinded key: {}",
            hex::encode(&blinded_pubkey[..8])
        );

        signature.to_bytes()
    }

    /// Build auth-key certificate (type 09)
    ///
    /// Certifies the introduction point auth key, signed by descriptor signing key.
    /// Per the spec, the cert should contain the intro auth key as certified key,
    /// signed by descriptor signing key, with signing key extension.
    ///
    /// If `original_expiration` is provided, it will be used to preserve the original
    /// certificate's expiration time (matching OnionBalance's recertification behavior).
    fn build_auth_key_cert(
        &self,
        auth_key: &[u8; 32],
        original_expiration: Option<u32>,
    ) -> Vec<u8> {
        let mut cert = Vec::with_capacity(140);

        // Version
        cert.push(0x01);

        // Cert type: 0x09 = HS_IP_V_SIGNING (intro point auth key cert)
        cert.push(0x09);

        // Expiration: use original if provided, otherwise 3 hours from now
        let hours_since_epoch = match original_expiration {
            Some(exp) => exp,
            None => {
                #[allow(clippy::cast_possible_truncation)]
                let exp = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    / 3600
                    + 3) as u32;
                exp
            },
        };
        cert.extend_from_slice(&hours_since_epoch.to_be_bytes());

        // Cert key type: 0x01 = ed25519
        cert.push(0x01);

        // Certified key: the introduction point auth key
        cert.extend_from_slice(auth_key);

        // Number of extensions: 1 (the signed-with-ed25519-key extension)
        cert.push(0x01);

        // Extension 04: signed-with-ed25519-key
        cert.extend_from_slice(&32u16.to_be_bytes()); // ExtLen = 32
        cert.push(0x04); // ExtType = 04 (signed-with-ed25519-key)
        cert.push(0x01); // ExtFlags = 01 (AFFECTS_VALIDATION)
        cert.extend_from_slice(self.desc_signing_key.verifying_key().as_bytes()); // Signing key

        // Sign with descriptor signing key
        let signature = self.desc_signing_key.sign(&cert);
        cert.extend_from_slice(&signature.to_bytes());

        cert
    }

    /// Build enc-key certificate (type 0B)
    ///
    /// Certifies the auth key (NOT the enc_key!), signed by descriptor signing key.
    ///
    /// IMPORTANT: Per stem's implementation in IntroductionPointV3.create_for_address(),
    /// the enc_key_cert uses the AUTH KEY as the certified key, not the encryption key.
    /// This matches: `enc_key_cert = Ed25519CertificateV1(CertType.HS_V3_NTOR_ENC, ..., auth_key, ...)`
    ///
    /// If `original_expiration` is provided, it will be used to preserve the original
    /// certificate's expiration time (matching OnionBalance's recertification behavior).
    fn build_enc_key_cert(&self, auth_key: &[u8; 32], original_expiration: Option<u32>) -> Vec<u8> {
        let mut cert = Vec::with_capacity(140);

        // Version
        cert.push(0x01);

        // Cert type: 0x0B = NTOR_CC_V_SIGNING (enc key cert)
        cert.push(0x0B);

        // Expiration: use original if provided, otherwise 3 hours from now
        let hours_since_epoch = match original_expiration {
            Some(exp) => exp,
            None => {
                #[allow(clippy::cast_possible_truncation)]
                let exp = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    / 3600
                    + 3) as u32;
                exp
            },
        };
        cert.extend_from_slice(&hours_since_epoch.to_be_bytes());

        // Cert key type: 0x01 = ed25519
        cert.push(0x01);

        // Certified key: the AUTH KEY (not enc_key!)
        // Per stem's implementation, both auth_key_cert and enc_key_cert certify the auth_key
        cert.extend_from_slice(auth_key);

        // Number of extensions: 1 (the signed-with-ed25519-key extension)
        cert.push(0x01);

        // Extension 04: signed-with-ed25519-key
        cert.extend_from_slice(&32u16.to_be_bytes()); // ExtLen = 32
        cert.push(0x04); // ExtType = 04 (signed-with-ed25519-key)
        cert.push(0x01); // ExtFlags = 01 (AFFECTS_VALIDATION)
        cert.extend_from_slice(self.desc_signing_key.verifying_key().as_bytes()); // Signing key

        // Sign with descriptor signing key
        let signature = self.desc_signing_key.sign(&cert);
        cert.extend_from_slice(&signature.to_bytes());

        cert
    }
}

/// Output from descriptor building
#[derive(Debug)]
pub struct DescriptorOutput {
    /// The complete descriptor string ready for upload
    pub descriptor: String,
    /// The blinded public key used
    pub blinded_key: [u8; 32],
    /// The subcredential used for encryption
    pub subcredential: [u8; 32],
    /// The revision counter
    pub revision_counter: u64,
}

/// Simple base64 encoding (with padding)
fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

/// Base64 encoding without padding (required for Tor signature lines)
fn base64_encode_no_pad(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    STANDARD_NO_PAD.encode(data)
}

/// Decrypt a descriptor layer (for parsing backend descriptors)
///
/// Tor descriptor encryption format (from rend-spec-v3.txt):
/// encrypted_data = SALT || ENCRYPTED || MAC
/// where:
///   SALT: 16 bytes random
///   ENCRYPTED: AES-256-CTR ciphertext (variable length)
///   MAC: 32 bytes SHA3-256 hash
///
/// Key derivation:
///   secret_input = SECRET_DATA || subcredential || INT_8(revision_counter)
///   where SECRET_DATA = blinded_key for first layer
///   keys = SHAKE-256(secret_input || salt || string_constant, 80)
///   SECRET_KEY = keys[0:32]   for AES-256
///   SECRET_IV = keys[32:48]   for CTR IV
///   MAC_KEY = keys[48:80]     for authentication
///
/// MAC verification:
///   D_MAC = SHA3_256(mac_key_len || MAC_KEY || salt_len || SALT || ENCRYPTED)
///   where mac_key_len and salt_len are 8-byte big-endian lengths
///
/// String constants:
///   - Outer (superencrypted): "hsdir-superencrypted-data"
///   - Inner (encrypted): "hsdir-encrypted-data"
pub fn decrypt_layer(
    ciphertext: &[u8],
    blinded_key: &[u8; 32],
    subcredential: &[u8; 32],
    revision_counter: u64,
    string_constant: &[u8],
) -> Result<Vec<u8>> {
    // Minimum size: SALT (16) + MAC (32) + at least 1 byte of data
    if ciphertext.len() < 49 {
        anyhow::bail!(
            "Ciphertext too short: {} bytes (minimum 49)",
            ciphertext.len()
        );
    }

    // Extract components: SALT || ENCRYPTED || MAC
    let salt = &ciphertext[..16];
    let encrypted = &ciphertext[16..ciphertext.len() - 32];
    let mac = &ciphertext[ciphertext.len() - 32..];

    tracing::info!(
        "decrypt_layer: salt={}, encrypted={} bytes, mac={}, string_const={}",
        hex::encode(salt),
        encrypted.len(),
        hex::encode(mac),
        String::from_utf8_lossy(string_constant)
    );

    // Build secret_input per rend-spec-v3.txt:
    // secret_input = SECRET_DATA || subcredential || INT_8(revision_counter)
    // For first layer: SECRET_DATA = blinded_key
    let mut secret_input = Vec::with_capacity(72);
    secret_input.extend_from_slice(blinded_key);
    secret_input.extend_from_slice(subcredential);
    secret_input.extend_from_slice(&revision_counter.to_be_bytes());

    tracing::info!(
        "decrypt_layer: blinded_key={}, subcred={}, rev={}",
        hex::encode(blinded_key),
        hex::encode(subcredential),
        revision_counter
    );

    // Derive keys using SHAKE-256 XOF
    // keys = SHAKE-256(secret_input || salt || STRING_CONSTANT, 80)
    let mut hasher = Shake256::default();
    XofUpdate::update(&mut hasher, &secret_input);
    XofUpdate::update(&mut hasher, salt);
    XofUpdate::update(&mut hasher, string_constant);

    let mut reader = hasher.finalize_xof();
    let mut secret_key = [0u8; 32];
    let mut secret_iv = [0u8; 16];
    let mut mac_key = [0u8; 32];
    reader.read(&mut secret_key);
    reader.read(&mut secret_iv);
    reader.read(&mut mac_key);

    tracing::info!(
        "decrypt_layer: derived secret_key={}, secret_iv={}, mac_key={}",
        hex::encode(&secret_key),
        hex::encode(&secret_iv),
        hex::encode(&mac_key)
    );

    tracing::info!(
        "decrypt_layer: secret_input={} (len={})",
        hex::encode(&secret_input),
        secret_input.len()
    );

    // Verify MAC BEFORE decrypting (to avoid timing attacks)
    // D_MAC = SHA3_256(mac_key_len || MAC_KEY || salt_len || SALT || ENCRYPTED)
    // where lengths are 8-byte big-endian
    use sha3::{Digest as Sha3Digest, Sha3_256};
    let mut mac_hasher = Sha3_256::new();
    Sha3Digest::update(&mut mac_hasher, &(mac_key.len() as u64).to_be_bytes()); // mac_key_len
    Sha3Digest::update(&mut mac_hasher, &mac_key);
    Sha3Digest::update(&mut mac_hasher, &(salt.len() as u64).to_be_bytes()); // salt_len
    Sha3Digest::update(&mut mac_hasher, salt);
    Sha3Digest::update(&mut mac_hasher, encrypted);
    let computed_mac = mac_hasher.finalize();

    if computed_mac.as_slice() != mac {
        tracing::warn!(
            "MAC mismatch: expected {}, computed {}",
            hex::encode(mac),
            hex::encode(&computed_mac)
        );

        // Save data for debugging
        if let Ok(mut f) = std::fs::File::create("/tmp/debug_mac.txt") {
            use std::io::Write;
            let _ = writeln!(f, "salt={}", hex::encode(salt));
            let _ = writeln!(f, "encrypted_len={}", encrypted.len());
            let _ = writeln!(
                f,
                "encrypted_first32={}",
                hex::encode(&encrypted[..32.min(encrypted.len())])
            );
            let _ = writeln!(
                f,
                "encrypted_last32={}",
                if encrypted.len() >= 32 {
                    hex::encode(&encrypted[encrypted.len() - 32..])
                } else {
                    hex::encode(encrypted)
                }
            );
            let _ = writeln!(f, "mac_expected={}", hex::encode(mac));
            let _ = writeln!(f, "mac_computed={}", hex::encode(&computed_mac));
            let _ = writeln!(f, "mac_key={}", hex::encode(&mac_key));
            let _ = writeln!(f, "blinded_key={}", hex::encode(blinded_key));
            let _ = writeln!(f, "subcredential={}", hex::encode(subcredential));
            let _ = writeln!(f, "revision={}", revision_counter);
            let _ = writeln!(f, "secret_input={}", hex::encode(&secret_input));
            let _ = writeln!(
                f,
                "string_constant={}",
                String::from_utf8_lossy(string_constant)
            );
        }
        // Also save raw encrypted data for verification
        let _ = std::fs::write("/tmp/debug_encrypted.bin", encrypted);
        let _ = std::fs::write("/tmp/debug_ciphertext.bin", ciphertext);

        anyhow::bail!(
            "MAC verification failed: descriptor decryption error (wrong key or corrupted data)"
        );
    }

    tracing::info!("decrypt_layer: MAC verified successfully");

    // Decrypt using AES-256-CTR
    let mut decrypted = encrypted.to_vec();
    let mut cipher = Aes256Ctr::new(&secret_key.into(), &secret_iv.into());
    cipher.apply_keystream(&mut decrypted);

    tracing::debug!("decrypt_layer: {} bytes decrypted", decrypted.len());
    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_layer_too_short() {
        let blinded_key = [0x41u8; 32];
        let subcred = [0x42u8; 32];
        let revision = 1u64;

        // Test that ciphertext too short returns error
        assert!(decrypt_layer(&[0u8; 5], &blinded_key, &subcred, revision, b"test").is_err());
        assert!(decrypt_layer(&[0u8; 48], &blinded_key, &subcred, revision, b"test").is_err());
    }
}
