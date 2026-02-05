//! Logging configuration
//!
//! Structured logging with tracing.

use tracing::Level;
use tracing_subscriber::fmt;
use tracing_subscriber::EnvFilter;

/// Initialize logging with environment-based filtering
pub fn init() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("rustbalance=info"));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();
}

/// Initialize logging with specific level
pub fn init_with_level(level: Level) {
    let filter = EnvFilter::new(format!("rustbalance={}", level));

    fmt().with_env_filter(filter).with_target(true).init();
}
