//! Configuration validation
//!
//! Fail-fast validation of configuration invariants.

use super::Config;
use anyhow::{bail, Result};
use std::path::Path;

/// Validate configuration invariants
pub fn validate(config: &Config) -> Result<()> {
    validate_node(config)?;
    validate_master(config)?;
    validate_target(config)?;
    validate_coordination(config)?;
    validate_timing(config)?;
    Ok(())
}

fn validate_node(config: &Config) -> Result<()> {
    if config.node.id.is_empty() {
        bail!("node.id cannot be empty");
    }
    if config.node.id.len() > 64 {
        bail!("node.id too long (max 64 chars)");
    }

    // Validate node hidden_service_dir is non-empty
    if config.node.hidden_service_dir.is_empty() {
        bail!("node.hidden_service_dir cannot be empty");
    }

    Ok(())
}

fn validate_master(config: &Config) -> Result<()> {
    // Validate onion address format
    let addr = &config.master.onion_address;
    if !addr.ends_with(".onion") {
        bail!("master.onion_address must end with .onion");
    }

    // v3 onion addresses are 56 chars + .onion
    let prefix = addr.trim_end_matches(".onion");
    if prefix.len() != 56 {
        bail!("master.onion_address must be a v3 address (56 chars before .onion)");
    }

    // Check key file exists
    if !Path::new(&config.master.identity_key_path).exists() {
        bail!(
            "Master identity key not found: {:?}",
            config.master.identity_key_path
        );
    }

    Ok(())
}

fn validate_target(config: &Config) -> Result<()> {
    let addr = &config.target.onion_address;
    if !addr.ends_with(".onion") {
        bail!("target.onion_address must end with .onion");
    }

    // v3 onion addresses are 56 chars + .onion
    let prefix = addr.trim_end_matches(".onion");
    if prefix.len() != 56 {
        bail!("target.onion_address must be a v3 address (56 chars before .onion)");
    }

    if config.target.port == 0 {
        bail!("target.port cannot be 0");
    }

    Ok(())
}

fn validate_coordination(config: &Config) -> Result<()> {
    match config.coordination.mode.as_str() {
        "wireguard" => {
            if config.wireguard.is_none() {
                bail!("wireguard section required when mode=wireguard");
            }
        },
        "tor" => {
            // Tor-only coordination, no extra config needed
        },
        other => {
            bail!(
                "Unknown coordination mode: {} (use 'wireguard' or 'tor')",
                other
            );
        },
    }
    Ok(())
}

fn validate_timing(config: &Config) -> Result<()> {
    // Heartbeat timeout must be greater than interval
    if config.coordination.heartbeat_timeout_secs <= config.coordination.heartbeat_interval_secs {
        bail!(
            "heartbeat_timeout_secs ({}) must be greater than heartbeat_interval_secs ({})",
            config.coordination.heartbeat_timeout_secs,
            config.coordination.heartbeat_interval_secs
        );
    }

    // Grace period should be reasonable
    if config.publish.takeover_grace_secs < config.coordination.heartbeat_timeout_secs {
        bail!(
            "takeover_grace_secs ({}) should be >= heartbeat_timeout_secs ({})",
            config.publish.takeover_grace_secs,
            config.coordination.heartbeat_timeout_secs
        );
    }

    Ok(())
}
