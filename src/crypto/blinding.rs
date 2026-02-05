//! v3 Onion Service key blinding
//!
//! Implements Tor Proposal 224 blinding for v3 hidden services.
//! The blinded key changes each time period, preventing linkability.
//!
//! Reference: https://spec.torproject.org/rend-spec/deriving-keys.html

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::VerifyingKey;
use sha3::{Digest, Sha3_256};

/// Time period length in minutes (default: 1440 = 24 hours)
const TIME_PERIOD_LENGTH_MINUTES: u64 = 1440;

/// Time period length in seconds
const TIME_PERIOD_LENGTH: u64 = TIME_PERIOD_LENGTH_MINUTES * 60;

/// Time period rotation offset in minutes (12 hours)
/// Tor applies this offset before computing the period number,
/// so period boundaries occur at 12:00 UTC, not 00:00 UTC.
/// See prop224 section [TIME-PERIODS].
const TIME_PERIOD_ROTATION_OFFSET_MINUTES: u64 = 720;

/// Ed25519 basepoint string as specified in Tor spec
const ED25519_BASEPOINT_STR: &[u8] = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)";

/// Compute the blinding factor according to Tor spec
///
/// h = SHA3-256(BLIND_STRING | A | s | B | N)
fn compute_blinding_factor(
    public_key: &VerifyingKey,
    period_num: u64,
    period_length_minutes: u64,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // BLIND_STRING with null terminator
    let blind_string = b"Derive temporary signing key\x00";
    hasher.update(blind_string);

    // A = 32-byte public identity key
    hasher.update(public_key.as_bytes());

    // s = shared secret (empty for standard blinding)
    // (nothing to add)

    // B = Ed25519 basepoint string representation
    hasher.update(ED25519_BASEPOINT_STR);

    // N = "key-blind" + period_num + period_length
    let n_prefix = b"key-blind";
    hasher.update(n_prefix);
    hasher.update(period_num.to_be_bytes());
    hasher.update(period_length_minutes.to_be_bytes());

    tracing::info!(
        "compute_blinding_factor: blind_string_len={}, pubkey={}, basepoint_len={}, period_num={}, period_len_min={}",
        blind_string.len(),
        hex::encode(public_key.as_bytes()),
        ED25519_BASEPOINT_STR.len(),
        period_num,
        period_length_minutes
    );

    let result: [u8; 32] = hasher.finalize().into();
    tracing::info!("compute_blinding_factor: h={}", hex::encode(&result));
    result
}

/// Clamp a 32-byte value for use as an Ed25519 scalar
///
/// This is the standard Ed25519 clamping operation.
fn clamp_integer(mut h: [u8; 32]) -> [u8; 32] {
    h[0] &= 248; // Clear lowest 3 bits
    h[31] &= 63; // Clear highest 2 bits
    h[31] |= 64; // Set second-highest bit
    h
}

/// Blind a public identity key for a given time period
///
/// This performs proper elliptic curve scalar multiplication:
/// A' = h * A (where h is the blinding factor scalar)
pub fn blind_identity(
    public_key: &VerifyingKey,
    time_period: u64,
    period_length: Option<u64>,
) -> [u8; 32] {
    let period_len = period_length.unwrap_or(TIME_PERIOD_LENGTH);
    let period_len_minutes = period_len / 60;
    let period_num = time_period / period_len;

    tracing::info!(
        "blind_identity: pubkey={}, time_period={}, period_len={}, period_len_min={}, period_num={}",
        hex::encode(public_key.as_bytes()),
        time_period,
        period_len,
        period_len_minutes,
        period_num
    );

    // Compute blinding factor
    let h = compute_blinding_factor(public_key, period_num, period_len_minutes);
    let clamped = clamp_integer(h);

    tracing::info!(
        "blind_identity: blinding_hash={}, clamped={}",
        hex::encode(&h),
        hex::encode(&clamped)
    );

    // Clamp and convert to scalar
    let blinding_factor = Scalar::from_bytes_mod_order(clamped);

    // Decompress public key to curve point
    let pubkey_compressed = CompressedEdwardsY(*public_key.as_bytes());
    let Some(pubkey_point) = pubkey_compressed.decompress() else {
        tracing::error!("Failed to decompress public key for blinding");
        // Fallback: return hash-based result (will be invalid but won't panic)
        return h;
    };

    // Scalar * Point multiplication: A' = h * A
    let blinded_point = blinding_factor * pubkey_point;

    // Compress back to bytes
    let result = blinded_point.compress().0;
    tracing::info!("blind_identity: result={}", hex::encode(&result));
    result
}

/// Compute the blinded private key for signing
///
/// a' = h * a mod l (scalar multiplication)
/// where h is the blinding factor and a is the private key scalar
///
/// Returns the blinded private scalar as 32 bytes
pub fn blind_private_key(
    public_key: &VerifyingKey,
    private_scalar: &[u8; 32],
    time_period: u64,
    period_length: Option<u64>,
) -> [u8; 32] {
    let period_len = period_length.unwrap_or(TIME_PERIOD_LENGTH);
    let period_len_minutes = period_len / 60;
    let period_num = time_period / period_len;

    // Compute blinding factor
    let h = compute_blinding_factor(public_key, period_num, period_len_minutes);

    // Clamp and convert to scalar
    let clamped_h = clamp_integer(h);
    tracing::info!(
        "blind_private_key: h={}, clamped_h={}",
        hex::encode(&h),
        hex::encode(&clamped_h)
    );
    let blinding_factor = Scalar::from_bytes_mod_order(clamped_h);
    tracing::info!(
        "blind_private_key: blinding_factor_scalar={}",
        hex::encode(blinding_factor.as_bytes())
    );

    // Convert private key to scalar (it should already be clamped from Ed25519 derivation)
    let private_scalar = Scalar::from_bytes_mod_order(*private_scalar);
    tracing::info!(
        "blind_private_key: private_scalar={}",
        hex::encode(private_scalar.as_bytes())
    );

    // Multiply: a' = h * a mod l
    let blinded_scalar = blinding_factor * private_scalar;
    tracing::info!(
        "blind_private_key: blinded_scalar={}",
        hex::encode(blinded_scalar.as_bytes())
    );

    blinded_scalar.to_bytes()
}

/// Derive the subcredential for a time period
///
/// Used for descriptor encryption and authentication
pub fn derive_subcredential(public_key: &VerifyingKey, blinded_key: &[u8; 32]) -> [u8; 32] {
    // credential = H("credential" || public_key)
    let mut hasher = Sha3_256::new();
    hasher.update(b"credential");
    hasher.update(public_key.as_bytes());
    let credential = hasher.finalize();

    // subcredential = H("subcredential" || credential || blinded_key)
    let mut hasher = Sha3_256::new();
    hasher.update(b"subcredential");
    hasher.update(&credential);
    hasher.update(blinded_key);

    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output
}

/// Get the current time period number
///
/// This applies the 12-hour rotation offset per prop224 [TIME-PERIODS]:
/// period_num = (minutes_since_epoch - rotation_offset) / period_length
/// This causes period boundaries to occur at 12:00 UTC rather than 00:00 UTC.
pub fn current_time_period() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    // Convert to minutes and apply rotation offset
    let minutes_since_epoch = now / 60;
    let offset_minutes = minutes_since_epoch.saturating_sub(TIME_PERIOD_ROTATION_OFFSET_MINUTES);
    offset_minutes / TIME_PERIOD_LENGTH_MINUTES
}

/// Calculate time until next period boundary
pub fn time_until_next_period() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    // Account for the rotation offset in boundary calculation
    let minutes_since_epoch = now / 60;
    let offset_minutes = minutes_since_epoch.saturating_sub(TIME_PERIOD_ROTATION_OFFSET_MINUTES);
    let current_period = offset_minutes / TIME_PERIOD_LENGTH_MINUTES;
    let next_period_start_minutes =
        (current_period + 1) * TIME_PERIOD_LENGTH_MINUTES + TIME_PERIOD_ROTATION_OFFSET_MINUTES;
    let next_period_start_secs = next_period_start_minutes * 60;
    next_period_start_secs.saturating_sub(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_blinding_deterministic() {
        let seed = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key();

        let blind1 = blind_identity(&public_key, 1000, None);
        let blind2 = blind_identity(&public_key, 1000, None);

        assert_eq!(blind1, blind2, "Blinding must be deterministic");
    }

    #[test]
    fn test_blinding_varies_by_period() {
        let seed = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key();

        let blind1 = blind_identity(&public_key, 1000, Some(100));
        let blind2 = blind_identity(&public_key, 2000, Some(100));

        assert_ne!(
            blind1, blind2,
            "Different periods must produce different blinded keys"
        );
    }

    #[test]
    fn test_blinded_key_is_valid_point() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key();

        let blinded = blind_identity(&public_key, 1000, None);

        // The blinded key should be a valid compressed Edwards point
        let compressed = CompressedEdwardsY(blinded);
        assert!(
            compressed.decompress().is_some(),
            "Blinded key must be a valid curve point"
        );
    }

    #[test]
    fn test_blinding_factor_matches_tor() {
        // Test with known values to verify our blinding factor matches Tor's
        // Identity key: e33734887a0d09abdf3470ca9839814b5813e29844f05feaff0609899f8ce633
        // Period number: 20487
        // Period length: 1440 minutes
        // Expected blinding factor h: b3d814222111c07d4b0abfad4a9327ca3bda2548f0b3641126e4780a285a2d23

        let pubkey_bytes: [u8; 32] = [
            0xe3, 0x37, 0x34, 0x88, 0x7a, 0x0d, 0x09, 0xab, 0xdf, 0x34, 0x70, 0xca, 0x98, 0x39,
            0x81, 0x4b, 0x58, 0x13, 0xe2, 0x98, 0x44, 0xf0, 0x5f, 0xea, 0xff, 0x06, 0x09, 0x89,
            0x9f, 0x8c, 0xe6, 0x33,
        ];
        let public_key = VerifyingKey::from_bytes(&pubkey_bytes).unwrap();

        let period_num: u64 = 20487;
        let period_length_minutes: u64 = 1440;

        let h = compute_blinding_factor(&public_key, period_num, period_length_minutes);

        let expected_h: [u8; 32] = [
            0xb3, 0xd8, 0x14, 0x22, 0x21, 0x11, 0xc0, 0x7d, 0x4b, 0x0a, 0xbf, 0xad, 0x4a, 0x93,
            0x27, 0xca, 0x3b, 0xda, 0x25, 0x48, 0xf0, 0xb3, 0x64, 0x11, 0x26, 0xe4, 0x78, 0x0a,
            0x28, 0x5a, 0x2d, 0x23,
        ];

        assert_eq!(
            h, expected_h,
            "Blinding factor must match Tor's computation.\nGot: {:02x?}\nExpected: {:02x?}",
            h, expected_h
        );
    }

    #[test]
    fn test_blinded_key_matches_python_nacl() {
        // Test that our blinded public key matches what Python nacl computes
        // This verifies the EC scalar multiplication is correct
        //
        // Identity key: e33734887a0d09abdf3470ca9839814b5813e29844f05feaff0609899f8ce633
        // Period number: 20487
        // Clamped h: b0d814222111c07d4b0abfad4a9327ca3bda2548f0b3641126e4780a285a2d63
        // Python nacl computed blinded key: b03fd1be70bb50c29e73aaaa972ffb63b8f4efc0fe472e22444f33d505054955

        let pubkey_bytes: [u8; 32] = [
            0xe3, 0x37, 0x34, 0x88, 0x7a, 0x0d, 0x09, 0xab, 0xdf, 0x34, 0x70, 0xca, 0x98, 0x39,
            0x81, 0x4b, 0x58, 0x13, 0xe2, 0x98, 0x44, 0xf0, 0x5f, 0xea, 0xff, 0x06, 0x09, 0x89,
            0x9f, 0x8c, 0xe6, 0x33,
        ];
        let public_key = VerifyingKey::from_bytes(&pubkey_bytes).unwrap();

        // Use the same time period that gives period_num=20487 with 86400 second periods
        // period_num = timestamp / 86400 = 20487
        // So timestamp = 20487 * 86400 = 1770076800
        let time_period_secs: u64 = 20487 * 86400;

        let blinded = blind_identity(&public_key, time_period_secs, None);

        // This is what Python nacl computed with crypto_scalarmult_ed25519_noclamp
        let expected_blinded: [u8; 32] = [
            0xb0, 0x3f, 0xd1, 0xbe, 0x70, 0xbb, 0x50, 0xc2, 0x9e, 0x73, 0xaa, 0xaa, 0x97, 0x2f,
            0xfb, 0x63, 0xb8, 0xf4, 0xef, 0xc0, 0xfe, 0x47, 0x2e, 0x22, 0x44, 0x4f, 0x33, 0xd5,
            0x05, 0x05, 0x49, 0x55,
        ];

        // Print what we got for debugging
        println!("Our blinded key: {:02x?}", blinded);
        println!("Expected (nacl): {:02x?}", expected_blinded);

        assert_eq!(
            blinded, expected_blinded,
            "Blinded public key must match Python nacl computation"
        );
    }

    #[test]
    fn test_blinded_private_key_corresponds_to_public() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key();

        // Get the private scalar (first 32 bytes of expanded key)
        // For ed25519-dalek, we can hash the seed to get the expanded key
        use sha2::{Digest as Sha2Digest, Sha512};
        let mut hasher = Sha512::new();
        Sha2Digest::update(&mut hasher, &seed);
        let expanded = hasher.finalize();
        let mut private_scalar = [0u8; 32];
        private_scalar.copy_from_slice(&expanded[..32]);
        // Clamp the scalar as Ed25519 requires
        private_scalar[0] &= 248;
        private_scalar[31] &= 63;
        private_scalar[31] |= 64;

        let time_period = 1000u64;

        // Get blinded public key
        let blinded_pub = blind_identity(&public_key, time_period, None);

        // Get blinded private key
        let blinded_priv = blind_private_key(&public_key, &private_scalar, time_period, None);

        // Derive public key from blinded private key: A' = a' * G
        let blinded_scalar = Scalar::from_bytes_mod_order(blinded_priv);
        let derived_pub: curve25519_dalek::edwards::CompressedEdwardsY =
            (&blinded_scalar * ED25519_BASEPOINT_TABLE).compress();

        assert_eq!(
            blinded_pub, derived_pub.0,
            "Blinded private key must correspond to blinded public key"
        );
    }
}
