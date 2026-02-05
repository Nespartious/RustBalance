//! Process restart utilities

use anyhow::Result;
use std::process::Command;
use tracing::{error, info};

/// Restart the Tor daemon
pub async fn restart_tor() -> Result<()> {
    // Try systemd first
    let result = Command::new("systemctl").args(["restart", "tor"]).status();

    match result {
        Ok(status) if status.success() => {
            info!("Tor restarted via systemctl");
            return Ok(());
        },
        Ok(status) => {
            error!("systemctl restart tor failed with {}", status);
        },
        Err(_) => {
            // systemctl not available, try service
            let result = Command::new("service").args(["tor", "restart"]).status();

            match result {
                Ok(status) if status.success() => {
                    info!("Tor restarted via service command");
                    return Ok(());
                },
                _ => {},
            }
        },
    }

    anyhow::bail!("Failed to restart Tor - no suitable init system found")
}

/// Restart a backend service
pub async fn restart_backend(name: &str) -> Result<()> {
    // This would typically call a custom script or systemd unit
    // named after the backend

    let service_name = format!("rustbalance-backend-{}", name);

    let result = Command::new("systemctl")
        .args(["restart", &service_name])
        .status();

    match result {
        Ok(status) if status.success() => {
            info!("Backend {} restarted", name);
            Ok(())
        },
        Ok(status) => {
            anyhow::bail!("Failed to restart backend {}: exit code {}", name, status)
        },
        Err(e) => {
            anyhow::bail!("Failed to restart backend {}: {}", name, e)
        },
    }
}

/// Check if Tor is running
pub fn is_tor_running() -> bool {
    let result = Command::new("systemctl")
        .args(["is-active", "--quiet", "tor"])
        .status();

    matches!(result, Ok(status) if status.success())
}
