//! Hidden Service descriptor parsing
//!
//! Parses v3 onion service descriptors and extracts introduction points.

use anyhow::{bail, Context, Result};
use std::time::SystemTime;

/// Parsed v3 Hidden Service descriptor
#[derive(Debug, Clone)]
pub struct HsDescriptor {
    /// Descriptor version (should be 3)
    pub version: u8,
    /// Lifetime in minutes
    pub lifetime: u32,
    /// Signing key certificate (raw bytes)
    pub signing_key_cert: Vec<u8>,
    /// Blinded public key (extracted from cert)
    pub blinded_key: [u8; 32],
    /// Revision counter (for freshness)
    pub revision_counter: u64,
    /// Encrypted body (contains intro points)
    pub encrypted_body: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
    /// When this descriptor was fetched
    pub fetch_time: SystemTime,
    /// Parsed introduction points (after decryption)
    pub introduction_points: Vec<IntroductionPoint>,
}

/// A single introduction point from a descriptor
#[derive(Debug, Clone)]
pub struct IntroductionPoint {
    /// Link specifiers (how to reach this relay)
    pub link_specifiers: Vec<LinkSpecifier>,
    /// Onion key for key exchange
    pub onion_key: [u8; 32],
    /// Authentication key certificate
    pub auth_key_cert: Vec<u8>,
    /// Encryption key (for encrypted introduction)
    pub enc_key: [u8; 32],
    /// Encryption key certificate
    pub enc_key_cert: Vec<u8>,
}

impl IntroductionPoint {
    /// Serialize intro point to bytes for network transmission
    /// Format: link_spec_count(1) + link_specs + onion_key(32) + auth_key_cert_len(2) + auth_key_cert
    ///         + enc_key(32) + enc_key_cert_len(2) + enc_key_cert
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Link specifiers
        #[allow(clippy::cast_possible_truncation)]
        buf.push(self.link_specifiers.len() as u8);
        for spec in &self.link_specifiers {
            match spec {
                LinkSpecifier::IPv4 { addr, port } => {
                    buf.push(0); // Type
                    buf.push(6); // Length
                    buf.extend_from_slice(addr);
                    buf.extend_from_slice(&port.to_be_bytes());
                },
                LinkSpecifier::IPv6 { addr, port } => {
                    buf.push(1);
                    buf.push(18);
                    buf.extend_from_slice(addr);
                    buf.extend_from_slice(&port.to_be_bytes());
                },
                LinkSpecifier::LegacyId(id) => {
                    buf.push(2);
                    buf.push(20);
                    buf.extend_from_slice(id);
                },
                LinkSpecifier::Ed25519Id(id) => {
                    buf.push(3);
                    buf.push(32);
                    buf.extend_from_slice(id);
                },
            }
        }

        // Onion key
        buf.extend_from_slice(&self.onion_key);

        // Auth key cert (length-prefixed)
        #[allow(clippy::cast_possible_truncation)]
        let auth_len = self.auth_key_cert.len() as u16;
        buf.extend_from_slice(&auth_len.to_be_bytes());
        buf.extend_from_slice(&self.auth_key_cert);

        // Enc key
        buf.extend_from_slice(&self.enc_key);

        // Enc key cert (length-prefixed)
        #[allow(clippy::cast_possible_truncation)]
        let enc_len = self.enc_key_cert.len() as u16;
        buf.extend_from_slice(&enc_len.to_be_bytes());
        buf.extend_from_slice(&self.enc_key_cert);

        buf
    }

    /// Deserialize intro point from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let mut offset = 0;

        // Parse link specifiers
        let nspec = data[offset] as usize;
        offset += 1;

        let mut link_specifiers = Vec::new();
        for _ in 0..nspec {
            if offset + 2 > data.len() {
                return None;
            }
            let lstype = data[offset];
            let lslen = data[offset + 1] as usize;
            offset += 2;

            if offset + lslen > data.len() {
                return None;
            }
            let lsdata = &data[offset..offset + lslen];
            offset += lslen;

            match lstype {
                0 if lslen >= 6 => {
                    let addr = [lsdata[0], lsdata[1], lsdata[2], lsdata[3]];
                    let port = u16::from_be_bytes([lsdata[4], lsdata[5]]);
                    link_specifiers.push(LinkSpecifier::IPv4 { addr, port });
                },
                1 if lslen >= 18 => {
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&lsdata[0..16]);
                    let port = u16::from_be_bytes([lsdata[16], lsdata[17]]);
                    link_specifiers.push(LinkSpecifier::IPv6 { addr, port });
                },
                2 if lslen >= 20 => {
                    let mut id = [0u8; 20];
                    id.copy_from_slice(&lsdata[..20]);
                    link_specifiers.push(LinkSpecifier::LegacyId(id));
                },
                3 if lslen >= 32 => {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&lsdata[..32]);
                    link_specifiers.push(LinkSpecifier::Ed25519Id(id));
                },
                _ => {}, // Skip unknown
            }
        }

        // Onion key
        if offset + 32 > data.len() {
            return None;
        }
        let mut onion_key = [0u8; 32];
        onion_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Auth key cert
        if offset + 2 > data.len() {
            return None;
        }
        let auth_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + auth_len > data.len() {
            return None;
        }
        let auth_key_cert = data[offset..offset + auth_len].to_vec();
        offset += auth_len;

        // Enc key
        if offset + 32 > data.len() {
            return None;
        }
        let mut enc_key = [0u8; 32];
        enc_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Enc key cert
        if offset + 2 > data.len() {
            return None;
        }
        let enc_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + enc_len > data.len() {
            return None;
        }
        let enc_key_cert = data[offset..offset + enc_len].to_vec();

        Some(Self {
            link_specifiers,
            onion_key,
            auth_key_cert,
            enc_key,
            enc_key_cert,
        })
    }

    /// Extract the auth key from the auth key certificate
    /// Certificate format: version(1) + type(1) + expiry(4) + key_type(1) + key(32) + ...
    pub fn auth_key(&self) -> Option<[u8; 32]> {
        if self.auth_key_cert.len() >= 39 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&self.auth_key_cert[7..39]);
            Some(key)
        } else {
            None
        }
    }

    /// Extract the expiration (hours since epoch) from the auth key certificate
    /// Certificate format: version(1) + type(1) + expiry(4 bytes, big-endian) + ...
    pub fn auth_key_cert_expiration(&self) -> Option<u32> {
        if self.auth_key_cert.len() >= 6 {
            let expiry_bytes: [u8; 4] = self.auth_key_cert[2..6].try_into().ok()?;
            Some(u32::from_be_bytes(expiry_bytes))
        } else {
            None
        }
    }

    /// Extract the expiration (hours since epoch) from the enc key certificate
    /// Certificate format: version(1) + type(1) + expiry(4 bytes, big-endian) + ...
    pub fn enc_key_cert_expiration(&self) -> Option<u32> {
        if self.enc_key_cert.len() >= 6 {
            let expiry_bytes: [u8; 4] = self.enc_key_cert[2..6].try_into().ok()?;
            Some(u32::from_be_bytes(expiry_bytes))
        } else {
            None
        }
    }
}

/// Link specifier (address/identity of relay)
#[derive(Debug, Clone)]
pub enum LinkSpecifier {
    /// IPv4 address and port
    IPv4 { addr: [u8; 4], port: u16 },
    /// IPv6 address and port  
    IPv6 { addr: [u8; 16], port: u16 },
    /// Legacy identity (RSA fingerprint)
    LegacyId([u8; 20]),
    /// Ed25519 identity
    Ed25519Id([u8; 32]),
}

impl HsDescriptor {
    /// Parse a raw descriptor string
    pub fn parse(raw: &str) -> Result<Self> {
        let mut version = 0u8;
        let mut lifetime = 180u32; // default 3 hours
        let mut revision_counter = 0u64;
        let mut in_encrypted = false;
        let mut encrypted_lines = Vec::new();
        let mut in_cert = false;
        let mut cert_lines = Vec::new();
        let mut signature_b64 = String::new();

        for line in raw.lines() {
            if line.starts_with("hs-descriptor ") {
                version = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            } else if line.starts_with("descriptor-lifetime ") {
                lifetime = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(180);
            } else if line.starts_with("revision-counter ") {
                revision_counter = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            } else if line == "-----BEGIN MESSAGE-----" {
                in_encrypted = true;
            } else if line == "-----END MESSAGE-----" {
                in_encrypted = false;
            } else if in_encrypted {
                encrypted_lines.push(line);
            } else if line == "-----BEGIN ED25519 CERT-----" {
                in_cert = true;
            } else if line == "-----END ED25519 CERT-----" {
                in_cert = false;
            } else if in_cert {
                cert_lines.push(line);
            } else if line.starts_with("signature ") {
                signature_b64 = line.strip_prefix("signature ").unwrap_or("").to_string();
            }
        }

        if version != 3 {
            bail!("Unsupported descriptor version: {}", version);
        }

        // Decode encrypted body
        let encrypted_b64: String = encrypted_lines.join("");
        let encrypted_body =
            base64_decode(&encrypted_b64).context("Failed to decode encrypted body")?;

        // Decode signing key cert
        let cert_b64: String = cert_lines.join("");
        let signing_key_cert = base64_decode(&cert_b64).unwrap_or_default();

        // Extract blinded key from certificate
        // Ed25519 cert format (cert-spec.txt):
        //   VERSION (1) | CERT_TYPE (1) | EXPIRATION (4) | KEY_TYPE (1) | CERTIFIED_KEY (32) | ...
        let blinded_key = extract_blinded_key_from_cert(&signing_key_cert)?;

        // Decode signature
        let signature = base64_decode(&signature_b64).unwrap_or_default();

        Ok(Self {
            version,
            lifetime,
            signing_key_cert,
            blinded_key,
            revision_counter,
            encrypted_body,
            signature,
            fetch_time: SystemTime::now(),
            introduction_points: Vec::new(), // Populated after decryption
        })
    }

    /// Parse a raw descriptor and decrypt intro points
    /// Parse and decrypt a descriptor using the identity public key.
    ///
    /// This derives the subcredential using the blinded key extracted from
    /// the descriptor's signing cert, which is the correct approach per Tor spec.
    pub fn parse_and_decrypt_with_pubkey(
        raw: &str,
        identity_pubkey: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self> {
        // First parse to extract the blinded key from the certificate
        let desc = Self::parse(raw)?;

        tracing::info!(
            "Descriptor parsed: rev={}, blinded_key={}, encrypted_body={} bytes",
            desc.revision_counter,
            hex::encode(&desc.blinded_key),
            desc.encrypted_body.len()
        );

        // Derive subcredential using the blinded key from the descriptor
        let subcredential = crate::crypto::derive_subcredential(identity_pubkey, &desc.blinded_key);

        tracing::info!(
            "Subcredential derived: identity={}, subcred={}",
            hex::encode(identity_pubkey.as_bytes()),
            hex::encode(&subcredential)
        );

        // Now decrypt using the correct subcredential
        Self::parse_and_decrypt(raw, &subcredential)
    }

    pub fn parse_and_decrypt(raw: &str, subcredential: &[u8; 32]) -> Result<Self> {
        let mut desc = Self::parse(raw)?;

        tracing::debug!(
            "Decrypting descriptor: rev={}, blinded_key={}",
            desc.revision_counter,
            hex::encode(&desc.blinded_key)
        );

        // Decrypt outer layer (superencrypted)
        // String constant per rend-spec-v3.txt: "hsdir-superencrypted-data"
        let middle_plain = crate::crypto::decrypt_layer(
            &desc.encrypted_body,
            &desc.blinded_key,
            subcredential,
            desc.revision_counter,
            b"hsdir-superencrypted-data",
        )
        .context("Failed to decrypt outer (superencrypted) layer")?;

        tracing::debug!("Outer layer decrypted: {} bytes", middle_plain.len());

        // Log the middle plaintext to understand what we're getting
        let middle_text = String::from_utf8_lossy(&middle_plain);
        tracing::info!(
            "Middle layer plaintext full ({} bytes): {:?}",
            middle_text.len(),
            middle_text
        );

        // Parse middle layer to get inner encrypted blob
        let inner_encrypted = Self::extract_inner_blob(&middle_plain)?;

        tracing::debug!("Inner encrypted blob: {} bytes", inner_encrypted.len());

        // Decrypt inner layer (encrypted)
        // String constant per rend-spec-v3.txt: "hsdir-encrypted-data"
        let inner_plain = crate::crypto::decrypt_layer(
            &inner_encrypted,
            &desc.blinded_key,
            subcredential,
            desc.revision_counter,
            b"hsdir-encrypted-data",
        )
        .context("Failed to decrypt inner (encrypted) layer")?;

        tracing::debug!("Inner layer decrypted: {} bytes", inner_plain.len());

        // Show the inner plaintext (should contain introduction points)
        let inner_text = String::from_utf8_lossy(&inner_plain);
        let preview_len = std::cmp::min(500, inner_text.len());
        tracing::info!(
            "Inner layer plaintext preview: {:?}",
            &inner_text[..preview_len]
        );

        // Parse introduction points from inner layer
        desc.introduction_points = Self::parse_intro_points(&inner_plain)?;

        tracing::info!(
            "Successfully decrypted descriptor with {} introduction points",
            desc.introduction_points.len()
        );

        Ok(desc)
    }

    /// Extract the encrypted inner blob from middle layer plaintext
    fn extract_inner_blob(middle_plain: &[u8]) -> Result<Vec<u8>> {
        let text = String::from_utf8_lossy(middle_plain);
        let mut in_message = false;
        let mut message_lines = Vec::new();

        for line in text.lines() {
            // Trim null bytes and whitespace from line for comparison
            let clean_line = line.trim().trim_matches('\0');

            if clean_line == "-----BEGIN MESSAGE-----" {
                in_message = true;
            } else if clean_line == "-----END MESSAGE-----"
                || clean_line.starts_with("-----END MESSAGE-----")
            {
                break; // Stop after first message block
            } else if in_message {
                // Also clean the data lines of any trailing nulls
                let clean_data = line.trim().trim_matches('\0');
                if !clean_data.is_empty() {
                    message_lines.push(clean_data);
                }
            }
        }

        tracing::info!("Inner blob: {} lines collected", message_lines.len());
        let b64: String = message_lines.join("");
        tracing::info!("Inner blob base64: {} chars", b64.len());

        match base64_decode(&b64) {
            Some(bytes) => {
                tracing::info!("Inner blob decoded: {} bytes", bytes.len());
                Ok(bytes)
            },
            None => {
                // Debug: find invalid characters
                let invalid: Vec<(usize, char)> = b64
                    .char_indices()
                    .filter(|(_, c)| {
                        !c.is_ascii_alphanumeric() && *c != '+' && *c != '/' && *c != '='
                    })
                    .take(10)
                    .collect();
                tracing::error!("Base64 decode failed. Invalid chars: {:?}", invalid);

                // Show context around first invalid char
                if let Some((pos, _)) = invalid.first() {
                    let start = if *pos > 30 { pos - 30 } else { 0 };
                    let end = std::cmp::min(pos + 50, b64.len());
                    tracing::error!(
                        "Context around invalid char at {}: {:?}",
                        pos,
                        &b64[start..end]
                    );
                }

                anyhow::bail!("Failed to decode inner message")
            },
        }
    }

    /// Parse introduction points from decrypted inner layer
    fn parse_intro_points(inner_plain: &[u8]) -> Result<Vec<IntroductionPoint>> {
        let text = String::from_utf8_lossy(inner_plain);
        let mut intro_points = Vec::new();
        let mut current_ip: Option<IntroPointBuilder> = None;
        let mut in_auth_key_cert = false;
        let mut in_enc_key_cert = false;
        let mut cert_lines: Vec<&str> = Vec::new();

        for line in text.lines() {
            // Handle certificate parsing (multi-line PEM blocks)
            if line == "-----BEGIN ED25519 CERT-----" {
                cert_lines.clear();
                // in_auth_key_cert or in_enc_key_cert is already set by the keyword line before this
                continue;
            } else if line == "-----END ED25519 CERT-----" {
                if let Some(ref mut builder) = current_ip {
                    let cert_b64: String = cert_lines.join("");
                    if let Some(cert_bytes) = base64_decode(&cert_b64) {
                        if in_auth_key_cert {
                            builder.auth_key_cert = cert_bytes;
                            tracing::debug!(
                                "Parsed auth-key cert: {} bytes",
                                builder.auth_key_cert.len()
                            );
                        } else if in_enc_key_cert {
                            builder.enc_key_cert = cert_bytes;
                            tracing::debug!(
                                "Parsed enc-key cert: {} bytes",
                                builder.enc_key_cert.len()
                            );
                        }
                    }
                }
                in_auth_key_cert = false;
                in_enc_key_cert = false;
                cert_lines.clear();
                continue;
            } else if in_auth_key_cert || in_enc_key_cert {
                cert_lines.push(line.trim());
                continue;
            }

            if line.starts_with("introduction-point ") {
                // Save previous IP if any
                if let Some(builder) = current_ip.take() {
                    if let Some(ip) = builder.build() {
                        intro_points.push(ip);
                    }
                }
                // Start new IP
                let id_b64 = line.strip_prefix("introduction-point ").unwrap_or("");
                let mut builder = IntroPointBuilder::default();
                if let Some(id_bytes) = base64_decode(id_b64) {
                    tracing::debug!("Introduction point ID decoded: {} bytes", id_bytes.len());
                    // Parse link specifiers from the encoded data
                    // Format: NSPEC (1 byte) then NSPEC link specifier entries
                    if !id_bytes.is_empty() {
                        let nspec = id_bytes[0] as usize;
                        let mut offset = 1;
                        for _i in 0..nspec {
                            if offset + 2 > id_bytes.len() {
                                break;
                            }
                            let lstype = id_bytes[offset];
                            let lslen = id_bytes[offset + 1] as usize;
                            offset += 2;
                            if offset + lslen > id_bytes.len() {
                                break;
                            }
                            let data = &id_bytes[offset..offset + lslen];
                            offset += lslen;

                            match lstype {
                                0 => {
                                    // TLS-over-TCP IPv4
                                    if data.len() >= 6 {
                                        let addr = [data[0], data[1], data[2], data[3]];
                                        let port = u16::from_be_bytes([data[4], data[5]]);
                                        builder
                                            .link_specifiers
                                            .push(LinkSpecifier::IPv4 { addr, port });
                                    }
                                },
                                1 => {
                                    // TLS-over-TCP IPv6
                                    if data.len() >= 18 {
                                        let mut addr = [0u8; 16];
                                        addr.copy_from_slice(&data[0..16]);
                                        let port = u16::from_be_bytes([data[16], data[17]]);
                                        builder
                                            .link_specifiers
                                            .push(LinkSpecifier::IPv6 { addr, port });
                                    }
                                },
                                2 => {
                                    // Legacy RSA ID
                                    if data.len() >= 20 {
                                        let mut id = [0u8; 20];
                                        id.copy_from_slice(&data[..20]);
                                        builder.link_specifiers.push(LinkSpecifier::LegacyId(id));
                                    }
                                },
                                3 => {
                                    // Ed25519 ID
                                    if data.len() >= 32 {
                                        let mut id = [0u8; 32];
                                        id.copy_from_slice(&data[..32]);
                                        builder.link_specifiers.push(LinkSpecifier::Ed25519Id(id));
                                    }
                                },
                                _ => {
                                    // Unknown type, skip
                                },
                            }
                        }
                    }
                }
                current_ip = Some(builder);
            } else if let Some(ref mut builder) = current_ip {
                if line.starts_with("onion-key ntor ") {
                    let key_b64 = line.strip_prefix("onion-key ntor ").unwrap_or("");
                    if let Some(key_bytes) = base64_decode(key_b64) {
                        if key_bytes.len() == 32 {
                            builder.onion_key.copy_from_slice(&key_bytes);
                        }
                    }
                } else if line.starts_with("enc-key ntor ") {
                    let key_b64 = line.strip_prefix("enc-key ntor ").unwrap_or("");
                    if let Some(key_bytes) = base64_decode(key_b64) {
                        if key_bytes.len() == 32 {
                            builder.enc_key.copy_from_slice(&key_bytes);
                        }
                    }
                } else if line == "auth-key" {
                    in_auth_key_cert = true;
                } else if line == "enc-key-cert" {
                    in_enc_key_cert = true;
                }
            }
        }

        // Don't forget the last one
        if let Some(builder) = current_ip {
            if let Some(ip) = builder.build() {
                intro_points.push(ip);
            }
        }

        tracing::info!(
            "Parsed {} introduction points from inner layer",
            intro_points.len()
        );

        Ok(intro_points)
    }

    /// Check if descriptor is still valid
    pub fn is_valid(&self) -> bool {
        if let Ok(elapsed) = self.fetch_time.elapsed() {
            let lifetime_secs = u64::from(self.lifetime) * 60;
            elapsed.as_secs() < lifetime_secs
        } else {
            false
        }
    }

    /// Check if this descriptor is fresher than another
    pub fn is_fresher_than(&self, other: &HsDescriptor) -> bool {
        self.revision_counter > other.revision_counter
    }
}

/// Builder for constructing IntroductionPoint during parsing
#[derive(Default)]
struct IntroPointBuilder {
    link_specifiers: Vec<LinkSpecifier>,
    onion_key: [u8; 32],
    auth_key_cert: Vec<u8>,
    enc_key: [u8; 32],
    enc_key_cert: Vec<u8>,
}

impl IntroPointBuilder {
    fn build(self) -> Option<IntroductionPoint> {
        // Must have at least a link specifier
        if self.link_specifiers.is_empty() {
            return None;
        }
        Some(IntroductionPoint {
            link_specifiers: self.link_specifiers,
            onion_key: self.onion_key,
            auth_key_cert: self.auth_key_cert,
            enc_key: self.enc_key,
            enc_key_cert: self.enc_key_cert,
        })
    }
}

impl IntroductionPoint {
    /// Get the Ed25519 identity of the introduction point relay
    pub fn relay_identity(&self) -> Option<&[u8; 32]> {
        for spec in &self.link_specifiers {
            if let LinkSpecifier::Ed25519Id(id) = spec {
                return Some(id);
            }
        }
        None
    }

    /// Get the IPv4 address if available
    pub fn ipv4_address(&self) -> Option<([u8; 4], u16)> {
        for spec in &self.link_specifiers {
            if let LinkSpecifier::IPv4 { addr, port } = spec {
                return Some((*addr, *port));
            }
        }
        None
    }
}

/// Simple base64 decoder
fn base64_decode(data: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(data.trim()).ok()
}

/// Extract blinded public key from Ed25519 certificate
///
/// Ed25519 certificate format (cert-spec.txt):
///   VERSION (1 byte): Must be 0x01
///   CERT_TYPE (1 byte): Type of cert
///   EXPIRATION (4 bytes): Expiration in hours since epoch
///   KEY_TYPE (1 byte): 0x01 for Ed25519
///   CERTIFIED_KEY (32 bytes): The certified public key
///   N_EXTENSIONS (1 byte): Number of extensions
///   EXTENSIONS... (variable)
///   SIGNATURE (64 bytes)
///
/// For descriptor signing certs (type 0x08 = HS_V3_DESC_SIGNING):
/// - CERTIFIED_KEY = the blinded public key (this is what we need for subcredential!)
/// - Extension type 0x04 = the signing key derived from blinded secret key
///
/// This is confirmed by stem library behavior which uses signing_cert.key (CERTIFIED_KEY)
/// for subcredential derivation and successfully decrypts descriptors.
fn extract_blinded_key_from_cert(cert: &[u8]) -> Result<[u8; 32]> {
    // Minimum cert size: 1 + 1 + 4 + 1 + 32 + 1 = 40 bytes (without extensions/sig)
    if cert.len() < 40 {
        bail!("Certificate too short: {} bytes (minimum 40)", cert.len());
    }

    let version = cert[0];
    if version != 0x01 {
        bail!("Unsupported certificate version: {}", version);
    }

    let cert_type = cert[1];
    if cert_type != 0x08 {
        tracing::debug!(
            "Certificate type 0x{:02x} (expected 0x08 for HS_V3_DESC_SIGNING)",
            cert_type
        );
    }

    let key_type = cert[6];
    if key_type != 0x01 {
        bail!(
            "Unsupported key type: {} (expected 0x01 for Ed25519)",
            key_type
        );
    }

    // For HS_V3_DESC_SIGNING certs (type 0x08), the blinded public key for
    // descriptor decryption is in EXTENSION type 0x04 (SIGNED_KEY), NOT in
    // the CERTIFIED_KEY field. This is what stem's signing_key() returns.
    //
    // Cert structure after CERTIFIED_KEY (offset 39):
    // - N_EXTENSIONS (1 byte)
    // - For each extension:
    //   - EXT_DATA_LEN (2 bytes, big-endian) - length of EXT_DATA only
    //   - EXT_TYPE (1 byte)
    //   - EXT_FLAGS (1 byte)
    //   - EXT_DATA (EXT_DATA_LEN bytes)

    let n_extensions = cert[39] as usize;
    let mut offset = 40;

    for _ in 0..n_extensions {
        if offset + 4 > cert.len() {
            bail!("Extension header truncated");
        }

        let data_len = u16::from_be_bytes([cert[offset], cert[offset + 1]]) as usize;
        let ext_type = cert[offset + 2];
        // ext_flags = cert[offset + 3]

        if ext_type == 0x04 {
            // Found the SIGNED_KEY extension - this contains the blinded public key
            if data_len < 32 {
                bail!("SIGNED_KEY extension data too short: {} bytes", data_len);
            }
            if offset + 4 + 32 > cert.len() {
                bail!("SIGNED_KEY extension data truncated");
            }

            let mut blinded_key = [0u8; 32];
            blinded_key.copy_from_slice(&cert[offset + 4..offset + 4 + 32]);

            tracing::debug!(
                "Extracted blinded key from SIGNED_KEY extension (0x04): {}",
                hex::encode(&blinded_key)
            );

            return Ok(blinded_key);
        }

        offset += 4 + data_len; // 2 (len) + 1 (type) + 1 (flags) + data_len
    }

    // Fallback: if no extension 0x04 found, use CERTIFIED_KEY (but this may not work)
    tracing::warn!("No SIGNED_KEY extension (0x04) found, falling back to CERTIFIED_KEY");
    let mut blinded_key = [0u8; 32];
    blinded_key.copy_from_slice(&cert[7..39]);

    tracing::debug!(
        "Extracted blinded key from cert CERTIFIED_KEY field: {}",
        hex::encode(&blinded_key)
    );

    Ok(blinded_key)
}
