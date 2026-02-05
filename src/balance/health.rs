//! Backend health checking
//!
//! Evaluates backend health via descriptor freshness and optional HTTP probes.

use crate::balance::backend::{Backend, BackendState};
use crate::config::HealthConfig;
use anyhow::Result;
use tracing::{debug, warn};

/// Health check result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Backend is healthy
    Healthy,
    /// Backend is degraded but usable
    Degraded,
    /// Backend is unhealthy
    Unhealthy,
    /// Health check failed (network error)
    CheckFailed,
}

/// Health checker for backends
pub struct HealthChecker {
    config: HealthConfig,
}

impl HealthChecker {
    pub fn new(config: HealthConfig) -> Self {
        Self { config }
    }

    /// Evaluate health of a backend
    pub fn evaluate(&self, backend: &Backend) -> HealthStatus {
        // Check descriptor age
        match backend.descriptor_age_secs() {
            None => {
                // Never fetched
                return HealthStatus::Unhealthy;
            },
            Some(age) if age > self.config.descriptor_max_age_secs => {
                // Descriptor too old
                debug!("Backend {} descriptor stale ({}s old)", backend.name, age);
                return HealthStatus::Unhealthy;
            },
            Some(age) if age > (self.config.descriptor_max_age_secs * 2 / 3) => {
                // Getting stale
                return HealthStatus::Degraded;
            },
            _ => {},
        }

        // Check descriptor validity
        if let Some(ref desc) = backend.descriptor {
            if !desc.is_valid() {
                return HealthStatus::Unhealthy;
            }
            if desc.introduction_points.is_empty() {
                warn!("Backend {} has no introduction points", backend.name);
                return HealthStatus::Unhealthy;
            }
        } else {
            return HealthStatus::Unhealthy;
        }

        HealthStatus::Healthy
    }

    /// Perform active HTTP probe (if enabled)
    ///
    /// This requires building a Tor circuit to the backend.
    /// Currently a placeholder - real implementation needs SOCKS proxy.
    pub async fn probe_http(&self, backend: &Backend) -> Result<HealthStatus> {
        if !self.config.http_probe_enabled {
            return Ok(HealthStatus::Healthy);
        }

        // TODO: Implement actual HTTP probe via Tor SOCKS
        // This would:
        // 1. Build circuit to backend.onion_address
        // 2. Send GET request to self.config.http_probe_path
        // 3. Check for 200 OK response
        // 4. Timeout after self.config.http_probe_timeout_secs

        debug!(
            "HTTP probe for {} (not yet implemented)",
            backend.onion_address
        );

        Ok(HealthStatus::Healthy)
    }

    /// Update backend state based on health
    pub fn update_state(&self, backend: &mut Backend) {
        let status = self.evaluate(backend);

        match status {
            HealthStatus::Healthy => {
                backend.state = BackendState::Healthy;
            },
            HealthStatus::Degraded => {
                backend.state = BackendState::Stale;
            },
            HealthStatus::Unhealthy | HealthStatus::CheckFailed => {
                backend.mark_dead();
            },
        }
    }
}
