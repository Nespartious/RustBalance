//! HSDir interaction for descriptor publishing
//!
//! Handles uploading descriptors to the Hidden Service Directory ring.

use crate::crypto::blinding::current_time_period;

/// Calculate the HSDir nodes responsible for a blinded key
pub fn calculate_hsdir_indices(blinded_key: &[u8; 32], spread: u8) -> Vec<[u8; 32]> {
    use sha3::{Digest, Sha3_256};

    let time_period = current_time_period();
    let mut indices = Vec::with_capacity(spread as usize);

    for replica in 0..spread {
        let mut hasher = Sha3_256::new();
        hasher.update(b"hsdir_index");
        hasher.update(blinded_key);
        hasher.update(&replica.to_be_bytes());
        hasher.update(&time_period.to_be_bytes());

        let hash = hasher.finalize();
        let mut index = [0u8; 32];
        index.copy_from_slice(&hash[..32]);
        indices.push(index);
    }

    indices
}

/// Descriptor upload result
#[derive(Debug)]
pub struct UploadResult {
    /// Number of HSDirs successfully uploaded to
    pub success_count: u32,
    /// Number of upload failures
    pub failure_count: u32,
    /// Specific failures (node identity, error)
    pub failures: Vec<(String, String)>,
}

impl UploadResult {
    pub fn is_success(&self) -> bool {
        self.success_count > 0 && self.failure_count == 0
    }

    pub fn is_partial(&self) -> bool {
        self.success_count > 0 && self.failure_count > 0
    }
}

/// Build the outer layer of a v3 descriptor
///
/// This is the structure that gets signed and uploaded
pub fn build_outer_descriptor(
    _blinded_key: &[u8; 32],
    revision_counter: u64,
    encrypted_body: &[u8],
    signature: &[u8; 64],
) -> String {
    use crate::util::base64_encode;

    let mut desc = String::new();

    desc.push_str("hs-descriptor 3\n");
    desc.push_str(&format!("descriptor-lifetime 180\n"));
    desc.push_str(&format!("descriptor-signing-key-cert\n"));
    desc.push_str("-----BEGIN ED25519 CERT-----\n");
    // TODO: actual cert
    desc.push_str("-----END ED25519 CERT-----\n");
    desc.push_str(&format!("revision-counter {}\n", revision_counter));
    desc.push_str("superencrypted\n");
    desc.push_str("-----BEGIN MESSAGE-----\n");
    desc.push_str(&base64_encode(encrypted_body));
    desc.push_str("\n-----END MESSAGE-----\n");
    desc.push_str(&format!("signature {}\n", base64_encode(signature)));

    desc
}
