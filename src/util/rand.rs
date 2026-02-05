//! Randomization utilities

use rand::Rng;
use std::time::Duration;

/// Generate random jitter within a range
pub fn jitter(base_secs: u64, max_jitter_secs: u64) -> Duration {
    let mut rng = rand::thread_rng();
    let jitter: u64 = rng.gen_range(0..=max_jitter_secs);
    Duration::from_secs(base_secs + jitter)
}

/// Generate random jitter (can be positive or negative)
pub fn signed_jitter(base_secs: u64, max_jitter_secs: u64) -> Duration {
    let mut rng = rand::thread_rng();
    let jitter: i64 = rng.gen_range(-(max_jitter_secs as i64)..=(max_jitter_secs as i64));
    let result = (base_secs as i64) + jitter;
    Duration::from_secs(result.max(0) as u64)
}

/// Exponential backoff with jitter
pub fn backoff(attempt: u32, base_secs: u64, max_secs: u64) -> Duration {
    let exp = base_secs * (2_u64.pow(attempt.min(10)));
    let capped = exp.min(max_secs);
    jitter(capped, capped / 4)
}

/// Generate random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}
