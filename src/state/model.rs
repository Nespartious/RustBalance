//! Runtime state model

use crate::config::Config;
use crate::coord::lease::Lease;
use crate::coord::messages::NodeRole;
use crate::tor::IntroductionPoint;
use std::collections::HashMap;
use std::time::SystemTime;

/// Shared runtime state
#[derive(Debug)]
pub struct RuntimeState {
    /// Current role (publisher or standby)
    pub role: NodeRole,
    /// Last successful publish time
    pub last_publish: Option<SystemTime>,
    /// Our own introduction points (parsed from our hidden service descriptor)
    pub own_intro_points: Vec<IntroductionPoint>,
    /// Introduction points from peer nodes (for merging when we're publisher)
    pub peer_intro_points: HashMap<String, Vec<IntroductionPoint>>,
    /// Current lease (if held)
    pub lease: Option<Lease>,
    /// Is our hidden service running?
    pub hs_running: bool,
    /// Target service health status
    pub target_healthy: bool,
    /// Has Tor's automatic descriptor publishing been disabled?
    /// This is set to true when we enter multi-node mode to prevent
    /// Tor from overwriting our HSPOST descriptors.
    pub tor_publish_disabled: bool,
}

impl RuntimeState {
    /// Create initial state from configuration
    pub fn new(_config: &Config) -> Self {
        Self {
            role: NodeRole::Standby,
            last_publish: None,
            own_intro_points: Vec::new(),
            peer_intro_points: HashMap::new(),
            lease: None,
            hs_running: false,
            target_healthy: false,
            tor_publish_disabled: false,
        }
    }

    /// Update last publish time
    pub fn record_publish(&mut self) {
        self.last_publish = Some(SystemTime::now());
    }

    /// Get seconds since last publish
    pub fn since_last_publish(&self) -> Option<u64> {
        self.last_publish
            .and_then(|t| t.elapsed().ok().map(|d| d.as_secs()))
    }

    /// Get total intro point count (ours + peers)
    pub fn total_intro_point_count(&self) -> usize {
        let peer_count: usize = self.peer_intro_points.values().map(|v| v.len()).sum();
        self.own_intro_points.len() + peer_count
    }
}
