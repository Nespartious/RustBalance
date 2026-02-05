//! Backend instance representation

use crate::tor::HsDescriptor;
use std::time::SystemTime;

/// Runtime state of a backend instance
#[derive(Debug, Clone)]
pub struct Backend {
    /// Configured name
    pub name: String,
    /// Onion address (.onion)
    pub onion_address: String,
    /// Current state
    pub state: BackendState,
    /// Last seen timestamp
    pub last_seen: Option<SystemTime>,
    /// Most recent descriptor
    pub descriptor: Option<HsDescriptor>,
    /// Consecutive failure count
    pub failure_count: u32,
}

/// Backend health state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendState {
    /// Never contacted
    Unknown,
    /// Descriptor fetched, healthy
    Healthy,
    /// Descriptor stale but not yet dead
    Stale,
    /// Backend considered down
    Dead,
    /// Temporarily excluded (e.g., after failure)
    Excluded,
}

impl Backend {
    /// Create a new backend from configuration
    pub fn new(name: String, onion_address: String) -> Self {
        Self {
            name,
            onion_address,
            state: BackendState::Unknown,
            last_seen: None,
            descriptor: None,
            failure_count: 0,
        }
    }

    /// Update with a fresh descriptor
    pub fn update_descriptor(&mut self, descriptor: HsDescriptor) {
        self.last_seen = Some(SystemTime::now());
        self.descriptor = Some(descriptor);
        self.state = BackendState::Healthy;
        self.failure_count = 0;
    }

    /// Mark as stale (descriptor too old)
    pub fn mark_stale(&mut self) {
        self.state = BackendState::Stale;
    }

    /// Mark as dead (no valid descriptor)
    pub fn mark_dead(&mut self) {
        self.failure_count += 1;
        self.state = BackendState::Dead;
    }

    /// Check if this backend should be included in merge
    pub fn is_usable(&self) -> bool {
        matches!(self.state, BackendState::Healthy | BackendState::Stale)
    }

    /// Get age of last descriptor in seconds
    pub fn descriptor_age_secs(&self) -> Option<u64> {
        self.last_seen
            .and_then(|t| t.elapsed().ok().map(|d| d.as_secs()))
    }
}
