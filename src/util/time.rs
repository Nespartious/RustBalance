//! Time utilities

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Get current Unix timestamp
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Get current Unix timestamp in milliseconds
pub fn unix_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis()
}

/// Convert Unix timestamp to SystemTime
pub fn from_unix_timestamp(ts: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(ts)
}

/// Check if timestamp is within tolerance of current time
pub fn is_time_valid(ts: u64, tolerance_secs: u64) -> bool {
    let now = unix_timestamp();
    let diff = if now > ts { now - ts } else { ts - now };
    diff <= tolerance_secs
}

/// Format duration as human-readable string
pub fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}
