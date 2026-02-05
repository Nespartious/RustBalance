//! Descriptor merging logic
//!
//! Implements Tor Proposal 307: aggregating introduction points
//! from multiple backend descriptors into a single master descriptor.

use crate::balance::backend::Backend;
use crate::config::PublishConfig;
use crate::tor::IntroductionPoint;
use rand::seq::SliceRandom;
use tracing::{debug, info};

/// Descriptor merger
pub struct DescriptorMerger {
    config: PublishConfig,
}

impl DescriptorMerger {
    pub fn new(config: PublishConfig) -> Self {
        Self { config }
    }

    /// Merge introduction points from multiple backends
    ///
    /// Returns a list of IPs suitable for the master descriptor
    pub fn merge(&self, backends: &[Backend]) -> Vec<IntroductionPoint> {
        let usable: Vec<_> = backends.iter().filter(|b| b.is_usable()).collect();

        if usable.is_empty() {
            info!("No usable backends for merge");
            return Vec::new();
        }

        // Collect all introduction points
        let mut all_ips: Vec<(IntroductionPoint, &str)> = Vec::new();

        for backend in &usable {
            if let Some(ref desc) = backend.descriptor {
                for ip in &desc.introduction_points {
                    all_ips.push((ip.clone(), &backend.name));
                }
            }
        }

        debug!(
            "Collected {} IPs from {} backends",
            all_ips.len(),
            usable.len()
        );

        // Select IPs respecting the limit
        let selected = self.select_ips(all_ips);

        info!(
            "Selected {} introduction points for master descriptor",
            selected.len()
        );

        selected
    }

    /// Select introduction points for the master descriptor
    ///
    /// Strategy:
    /// 1. Ensure representation from each backend
    /// 2. Fill remaining slots randomly
    /// 3. Cap at max_intro_points
    fn select_ips(&self, all_ips: Vec<(IntroductionPoint, &str)>) -> Vec<IntroductionPoint> {
        let max = self.config.max_intro_points;

        if all_ips.len() <= max {
            // All IPs fit, use them all
            return all_ips.into_iter().map(|(ip, _)| ip).collect();
        }

        // Count IPs per backend
        let mut backend_ips: std::collections::HashMap<&str, Vec<IntroductionPoint>> =
            std::collections::HashMap::new();

        for (ip, name) in all_ips {
            backend_ips.entry(name).or_default().push(ip);
        }

        let backend_count = backend_ips.len();
        let per_backend = max / backend_count;
        let mut remaining = max % backend_count;

        let mut selected = Vec::with_capacity(max);
        let mut rng = rand::thread_rng();

        for (_name, mut ips) in backend_ips {
            // Shuffle to randomize which IPs we pick
            ips.shuffle(&mut rng);

            // Take base allocation
            let mut take = per_backend;

            // Distribute remainder
            if remaining > 0 {
                take += 1;
                remaining -= 1;
            }

            for ip in ips.into_iter().take(take) {
                selected.push(ip);
            }
        }

        // Final shuffle for load distribution
        selected.shuffle(&mut rng);

        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_backends() {
        let config = PublishConfig {
            refresh_interval_secs: 600,
            takeover_grace_secs: 90,
            max_intro_points: 20,
        };
        let merger = DescriptorMerger::new(config);
        let result = merger.merge(&[]);
        assert!(result.is_empty());
    }
}
