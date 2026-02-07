//! Descriptor publishing
//!
//! Builds and uploads the master descriptor to HSDirs.

use crate::crypto::{DescriptorBuilder, MasterIdentity};
use crate::crypto::blinding::current_and_next_time_periods;
use crate::tor::{IntroductionPoint, TorController};
use anyhow::Result;
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Publisher state
pub struct Publisher {
    /// Master identity key
    identity: MasterIdentity,
    /// Last publish timestamp
    last_publish: Option<SystemTime>,
    /// Current revision counter
    revision_counter: u64,
}

impl Publisher {
    pub fn new(identity: MasterIdentity) -> Self {
        // Initialize revision counter to be HIGHER than Tor's automatic revision counter.
        // Tor appears to use approximately (timestamp * 2.7) for revisions.
        // We use (timestamp * 3) to ensure we always override Tor's descriptors.
        // This is critical for multi-node mode where we HSPOST our own merged descriptor.
        let initial_revision = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() * 3) // Multiply by 3 to always be higher than Tor's ~2.7x formula
            .unwrap_or(6_000_000_000);

        Self {
            identity,
            last_publish: None,
            revision_counter: initial_revision,
        }
    }

    /// Publish a descriptor with the given introduction points
    pub async fn publish(
        &mut self,
        tor: &mut TorController,
        intro_points: Vec<IntroductionPoint>,
    ) -> Result<()> {
        if intro_points.is_empty() {
            warn!("No introduction points to publish");
            return Ok(());
        }

        info!(
            "Publishing descriptor with {} introduction points",
            intro_points.len()
        );

        // Build and upload descriptors for BOTH time periods
        // Per rend-spec-v3 §2.2.1: "A service MUST generate and upload descriptors
        // for the current and the following time period."
        let (tp_current, tp_next) = current_and_next_time_periods();
        let time_periods = [tp_current, tp_next];

        for (i, &tp) in time_periods.iter().enumerate() {
            let period_label = if i == 0 { "current" } else { "next" };

            // Each time period needs its own revision counter and signing key
            self.revision_counter += 1;
            info!(
                "Building descriptor for {} time period (tp={}) with revision counter {}",
                period_label, tp, self.revision_counter
            );

            let builder = DescriptorBuilder::new(&self.identity, self.revision_counter);
            let output = builder.build_for_period(&intro_points, tp)?;

            info!(
                "Built descriptor for {} period: blinded key {:?}, revision {}, len {}",
                period_label,
                &output.blinded_key[..8],
                output.revision_counter,
                output.descriptor.len()
            );

            // Upload via Tor control port
            let onion_addr = self.identity.onion_address();
            info!(
                "Uploading {} period descriptor via HSPOST for {}...",
                period_label, onion_addr
            );
            tor.upload_hs_descriptor(&output.descriptor, &onion_addr, &[])
                .await?;
            info!("HSPOST for {} period accepted (rev {})", period_label, self.revision_counter);
        }

        self.last_publish = Some(SystemTime::now());

        info!(
            "Descriptors published for both time periods (tp {} and {}, latest rev {})",
            tp_current, tp_next, self.revision_counter
        );

        Ok(())
    }

    /// Get time since last publish
    pub fn time_since_publish(&self) -> Option<u64> {
        self.last_publish
            .and_then(|t| t.elapsed().ok().map(|d| d.as_secs()))
    }

    /// Check if we should republish
    pub fn should_republish(&self, interval_secs: u64) -> bool {
        match self.time_since_publish() {
            None => true, // Never published
            Some(elapsed) => elapsed >= interval_secs,
        }
    }

    /// Get the current revision counter
    pub fn revision_counter(&self) -> u64 {
        self.revision_counter
    }

    /// Get the onion address for this publisher
    pub fn onion_address(&self) -> String {
        self.identity.onion_address()
    }
}
