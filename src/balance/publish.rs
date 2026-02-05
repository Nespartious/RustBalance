//! Descriptor publishing
//!
//! Builds and uploads the master descriptor to HSDirs.

use crate::crypto::{DescriptorBuilder, MasterIdentity};
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
        // Initialize revision counter based on current time to ensure it's
        // higher than any existing descriptors (which use timestamp-based revisions)
        // Note: Using (time + large offset) to overcome any stale high-revision descriptors
        let initial_revision = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + 1_000_000_000) // Add 1 billion to ensure higher than stale descriptors
            .unwrap_or(3_000_000_000);

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

        // Increment revision counter
        self.revision_counter += 1;
        info!(
            "Building descriptor with revision counter {}",
            self.revision_counter
        );

        // Build the complete descriptor using the crypto module
        let builder = DescriptorBuilder::new(&self.identity, self.revision_counter);
        let output = builder.build(&intro_points)?;

        info!(
            "Built descriptor with blinded key {:?}, revision {}, descriptor len {}",
            &output.blinded_key[..8],
            output.revision_counter,
            output.descriptor.len()
        );

        // Debug: show last 500 chars of descriptor to see the signature
        let preview = if output.descriptor.len() > 500 {
            &output.descriptor[output.descriptor.len() - 500..]
        } else {
            &output.descriptor
        };
        info!("Descriptor end:\n{}", preview);

        // Upload via Tor control port
        let onion_addr = self.identity.onion_address();
        info!(
            "Uploading descriptor via Tor control port for {}...",
            onion_addr
        );
        tor.upload_hs_descriptor(&output.descriptor, &onion_addr, &[])
            .await?;
        info!("Tor upload_hs_descriptor returned");

        self.last_publish = Some(SystemTime::now());

        info!(
            "Descriptor published successfully (rev {})",
            self.revision_counter
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
