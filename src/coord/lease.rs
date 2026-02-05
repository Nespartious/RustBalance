//! Publisher lease management
//!
//! Leases prevent split-brain by adding time-based exclusivity.

use std::time::{Duration, SystemTime};

/// A publisher lease
#[derive(Debug, Clone)]
pub struct Lease {
    /// Node holding the lease
    pub holder: String,
    /// When the lease was acquired
    pub acquired: SystemTime,
    /// Lease duration
    pub duration: Duration,
    /// Lease expiry time
    pub expires: SystemTime,
}

impl Lease {
    /// Create a new lease
    pub fn new(holder: String, duration_secs: u64) -> Self {
        let now = SystemTime::now();
        let duration = Duration::from_secs(duration_secs);

        Self {
            holder,
            acquired: now,
            duration,
            expires: now + duration,
        }
    }

    /// Check if lease is still valid
    pub fn is_valid(&self) -> bool {
        SystemTime::now() < self.expires
    }

    /// Check if lease is expired
    pub fn is_expired(&self) -> bool {
        !self.is_valid()
    }

    /// Time remaining on lease
    pub fn remaining(&self) -> Duration {
        self.expires
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO)
    }

    /// Renew the lease
    pub fn renew(&mut self) {
        let now = SystemTime::now();
        self.expires = now + self.duration;
    }

    /// Check if lease belongs to given node
    pub fn is_held_by(&self, node_id: &str) -> bool {
        self.holder == node_id
    }
}

/// Lease manager
pub struct LeaseManager {
    /// Current lease (if any)
    current: Option<Lease>,
    /// Default lease duration
    duration_secs: u64,
}

impl LeaseManager {
    pub fn new(duration_secs: u64) -> Self {
        Self {
            current: None,
            duration_secs,
        }
    }

    /// Try to acquire a lease
    pub fn acquire(&mut self, node_id: &str) -> bool {
        // Check if existing lease is valid
        if let Some(ref lease) = self.current {
            if lease.is_valid() && !lease.is_held_by(node_id) {
                // Someone else holds a valid lease
                return false;
            }
        }

        // Acquire or renew lease
        if let Some(ref mut lease) = self.current {
            if lease.is_held_by(node_id) {
                lease.renew();
                return true;
            }
        }

        self.current = Some(Lease::new(node_id.to_string(), self.duration_secs));
        true
    }

    /// Release the current lease
    pub fn release(&mut self, node_id: &str) {
        if let Some(ref lease) = self.current {
            if lease.is_held_by(node_id) {
                self.current = None;
            }
        }
    }

    /// Get current lease holder
    pub fn holder(&self) -> Option<&str> {
        self.current
            .as_ref()
            .filter(|l| l.is_valid())
            .map(|l| l.holder.as_str())
    }

    /// Check if lease is held by node
    pub fn is_held_by(&self, node_id: &str) -> bool {
        self.holder() == Some(node_id)
    }
}
