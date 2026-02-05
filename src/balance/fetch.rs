//! Backend descriptor fetching
//!
//! Fetches and parses v3 Hidden Service descriptors from backend onion services.

use crate::balance::backend::Backend;
use crate::config::TorConfig;
use crate::crypto::pubkey_from_onion_address;
use crate::tor::{HsDescriptor, TorController};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Descriptor cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    descriptor: HsDescriptor,
    fetched_at: SystemTime,
}

/// Backend descriptor fetcher
pub struct DescriptorFetcher {
    /// Tor controller for making requests
    tor_config: TorConfig,
    /// Cached descriptors by onion address
    cache: HashMap<String, CacheEntry>,
    /// Maximum descriptor age before refetch (seconds)
    max_age_secs: u64,
    /// Fetch timeout (seconds)
    #[allow(dead_code)]
    timeout_secs: u64,
}

impl DescriptorFetcher {
    /// Create a new fetcher
    pub fn new(tor_config: TorConfig, max_age_secs: u64) -> Self {
        Self {
            tor_config,
            cache: HashMap::new(),
            max_age_secs,
            timeout_secs: 30,
        }
    }

    /// Fetch descriptor for a single backend
    pub async fn fetch_one(&mut self, onion_address: &str) -> Result<HsDescriptor> {
        let addr = normalize_onion_address(onion_address);

        // Check cache first
        if let Some(entry) = self.cache.get(&addr) {
            if let Ok(elapsed) = entry.fetched_at.elapsed() {
                if elapsed.as_secs() < self.max_age_secs {
                    debug!("Using cached descriptor for {}", addr);
                    return Ok(entry.descriptor.clone());
                }
            }
        }

        // Need to fetch fresh descriptor
        info!("Fetching descriptor for {}", addr);

        let mut tor = TorController::connect(&self.tor_config)
            .await
            .context("Failed to connect to Tor")?;

        // Trigger HSFETCH
        tor.get_hs_descriptor(&addr).await?;
        info!(
            "HSFETCH triggered for {}, waiting 5 seconds before polling",
            addr
        );

        // Wait for descriptor to arrive (Tor fetches asynchronously)
        // In a full implementation, we'd listen for HS_DESC events
        // For now, poll with a delay
        tokio::time::sleep(Duration::from_secs(5)).await;
        info!("Starting to poll for descriptor");

        // Try to retrieve the fetched descriptor
        let desc = self.wait_for_descriptor(&mut tor, &addr).await?;

        // Cache it
        self.cache.insert(
            addr.clone(),
            CacheEntry {
                descriptor: desc.clone(),
                fetched_at: SystemTime::now(),
            },
        );

        Ok(desc)
    }

    /// Wait for a descriptor to be fetched
    async fn wait_for_descriptor(
        &self,
        tor: &mut TorController,
        onion_addr: &str,
    ) -> Result<HsDescriptor> {
        // In a full implementation, we'd use SETEVENTS HS_DESC_CONTENT
        // and wait for the event callback
        //
        // For now, we'll use a simplified approach that queries
        // via GETINFO hs/client/desc/id/<address>

        let info_key = format!("hs/client/desc/id/{}", onion_addr);

        // Extract identity public key from the onion address for decryption
        let identity_pubkey = pubkey_from_onion_address(onion_addr)
            .context("Failed to extract public key from onion address")?;

        for attempt in 0..6 {
            tokio::time::sleep(Duration::from_secs(2)).await;

            info!(
                "Attempt {} to get descriptor for {}",
                attempt + 1,
                onion_addr
            );

            match tor.get_info(&info_key).await {
                Ok(response) => {
                    info!("GETINFO response length: {} bytes", response.len());
                    info!(
                        "GETINFO response preview: {}",
                        &response.chars().take(200).collect::<String>()
                    );

                    if response.contains("hs-descriptor 3") {
                        debug!(
                            "Got descriptor for {} on attempt {}",
                            onion_addr,
                            attempt + 1
                        );
                        // Decrypt using identity pubkey - derives subcredential from descriptor's blinded key
                        match HsDescriptor::parse_and_decrypt_with_pubkey(
                            &response,
                            &identity_pubkey,
                        ) {
                            Ok(desc) => {
                                info!(
                                    "Successfully decrypted descriptor with {} intro points",
                                    desc.introduction_points.len()
                                );
                                return Ok(desc);
                            },
                            Err(e) => {
                                warn!("Failed to decrypt descriptor: {}. Trying plain parse.", e);
                                return HsDescriptor::parse(&response);
                            },
                        }
                    }
                },
                Err(e) => {
                    info!("GETINFO error: {}", e);
                },
            }
        }

        anyhow::bail!("Timeout waiting for descriptor from {}", onion_addr)
    }

    /// Fetch descriptors for all backends
    pub async fn fetch_all(&mut self, backends: &mut [Backend]) -> FetchResults {
        let mut results = FetchResults::default();

        for backend in backends.iter_mut() {
            match self.fetch_one(&backend.onion_address).await {
                Ok(desc) => {
                    info!(
                        "Fetched descriptor for {} with {} intro points",
                        backend.name,
                        desc.introduction_points.len()
                    );
                    backend.update_descriptor(desc);
                    results.success += 1;
                },
                Err(e) => {
                    warn!("Failed to fetch descriptor for {}: {}", backend.name, e);
                    results.failed += 1;
                    results.errors.push((backend.name.clone(), e.to_string()));
                },
            }
        }

        results
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Remove stale entries from cache
    pub fn prune_cache(&mut self) {
        let max_age = Duration::from_secs(self.max_age_secs * 2);

        self.cache.retain(|_, entry| {
            entry
                .fetched_at
                .elapsed()
                .map(|e| e < max_age)
                .unwrap_or(false)
        });
    }
}

/// Results from a batch fetch operation
#[derive(Debug, Default)]
pub struct FetchResults {
    /// Number of successful fetches
    pub success: usize,
    /// Number of failed fetches
    pub failed: usize,
    /// Error details (backend name, error message)
    pub errors: Vec<(String, String)>,
}

impl FetchResults {
    pub fn is_success(&self) -> bool {
        self.failed == 0 && self.success > 0
    }

    pub fn is_partial(&self) -> bool {
        self.failed > 0 && self.success > 0
    }

    pub fn is_failure(&self) -> bool {
        self.success == 0
    }
}

/// Normalize onion address (remove .onion suffix, lowercase)
fn normalize_onion_address(addr: &str) -> String {
    addr.trim()
        .to_lowercase()
        .trim_end_matches(".onion")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_address() {
        assert_eq!(normalize_onion_address("example.ONION"), "example");
        assert_eq!(normalize_onion_address("ABCDEF.onion"), "abcdef");
        assert_eq!(normalize_onion_address("test"), "test");
    }
}
