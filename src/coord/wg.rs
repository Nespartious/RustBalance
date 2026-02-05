//! WireGuard interface management via CLI
//!
//! Manages WireGuard interfaces using the `wg` and `ip` commands.
//! This is the recommended approach for production deployments.

use anyhow::{bail, Context, Result};
use std::process::Command;
use tracing::{debug, info, warn};

/// WireGuard interface manager
pub struct WgInterface {
    /// Interface name (e.g., "wg-rustbalance")
    name: String,
    /// Listen port
    listen_port: u16,
    /// Private key (base64)
    private_key: String,
}

/// Peer configuration
#[derive(Debug, Clone)]
pub struct WgPeer {
    /// Peer's public key (base64)
    pub public_key: String,
    /// Peer's endpoint (IP:port)
    pub endpoint: Option<String>,
    /// Allowed IPs (CIDR notation)
    pub allowed_ips: Vec<String>,
    /// Persistent keepalive interval (seconds)
    pub keepalive: Option<u16>,
}

impl WgInterface {
    /// Create a new interface manager
    pub fn new(name: &str, listen_port: u16, private_key: &str) -> Self {
        Self {
            name: name.to_string(),
            listen_port,
            private_key: private_key.to_string(),
        }
    }

    /// Check if the interface exists
    pub fn exists(&self) -> bool {
        Command::new("ip")
            .args(["link", "show", &self.name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Create the WireGuard interface
    pub fn create(&self) -> Result<()> {
        if self.exists() {
            info!("Interface {} already exists", self.name);
            return Ok(());
        }

        // Create the interface
        let status = Command::new("ip")
            .args(["link", "add", &self.name, "type", "wireguard"])
            .status()
            .context("Failed to run 'ip link add'")?;

        if !status.success() {
            bail!("Failed to create WireGuard interface {}", self.name);
        }

        info!("Created WireGuard interface {}", self.name);
        Ok(())
    }

    /// Configure the interface with private key and listen port
    pub fn configure(&self) -> Result<()> {
        // Write private key to temp file (wg requires file input)
        let key_file = format!("/tmp/wg-{}-key", self.name);
        std::fs::write(&key_file, &self.private_key)?;

        let status = Command::new("wg")
            .args([
                "set",
                &self.name,
                "listen-port",
                &self.listen_port.to_string(),
                "private-key",
                &key_file,
            ])
            .status()
            .context("Failed to run 'wg set'")?;

        // Clean up key file
        let _ = std::fs::remove_file(&key_file);

        if !status.success() {
            bail!("Failed to configure WireGuard interface {}", self.name);
        }

        debug!("Configured {} on port {}", self.name, self.listen_port);
        Ok(())
    }

    /// Set the interface IP address
    pub fn set_address(&self, addr: &str) -> Result<()> {
        let status = Command::new("ip")
            .args(["addr", "add", addr, "dev", &self.name])
            .status()
            .context("Failed to run 'ip addr add'")?;

        if !status.success() {
            // May already have the address
            warn!(
                "Failed to add address {} to {} (may already exist)",
                addr, self.name
            );
        }

        Ok(())
    }

    /// Bring the interface up
    pub fn up(&self) -> Result<()> {
        let status = Command::new("ip")
            .args(["link", "set", &self.name, "up"])
            .status()
            .context("Failed to run 'ip link set up'")?;

        if !status.success() {
            bail!("Failed to bring up interface {}", self.name);
        }

        info!("Interface {} is up", self.name);
        Ok(())
    }

    /// Bring the interface down
    pub fn down(&self) -> Result<()> {
        let status = Command::new("ip")
            .args(["link", "set", &self.name, "down"])
            .status()
            .context("Failed to run 'ip link set down'")?;

        if !status.success() {
            warn!("Failed to bring down interface {}", self.name);
        }

        Ok(())
    }

    /// Delete the interface
    pub fn delete(&self) -> Result<()> {
        if !self.exists() {
            return Ok(());
        }

        let status = Command::new("ip")
            .args(["link", "del", &self.name])
            .status()
            .context("Failed to run 'ip link del'")?;

        if !status.success() {
            bail!("Failed to delete interface {}", self.name);
        }

        info!("Deleted interface {}", self.name);
        Ok(())
    }

    /// Add a peer to the interface
    pub fn add_peer(&self, peer: &WgPeer) -> Result<()> {
        let mut args = vec!["set", &self.name, "peer", &peer.public_key];

        let endpoint_str;
        if let Some(ep) = &peer.endpoint {
            endpoint_str = ep.clone();
            args.push("endpoint");
            args.push(&endpoint_str);
        }

        let allowed_ips_str;
        if !peer.allowed_ips.is_empty() {
            allowed_ips_str = peer.allowed_ips.join(",");
            args.push("allowed-ips");
            args.push(&allowed_ips_str);
        }

        let keepalive_str;
        if let Some(ka) = peer.keepalive {
            keepalive_str = ka.to_string();
            args.push("persistent-keepalive");
            args.push(&keepalive_str);
        }

        let status = Command::new("wg")
            .args(&args)
            .status()
            .context("Failed to run 'wg set peer'")?;

        if !status.success() {
            bail!("Failed to add peer {}", peer.public_key);
        }

        debug!("Added peer {}", peer.public_key);
        Ok(())
    }

    /// Remove a peer from the interface
    pub fn remove_peer(&self, public_key: &str) -> Result<()> {
        let status = Command::new("wg")
            .args(["set", &self.name, "peer", public_key, "remove"])
            .status()
            .context("Failed to run 'wg set peer remove'")?;

        if !status.success() {
            warn!("Failed to remove peer {}", public_key);
        }

        debug!("Removed peer {}", public_key);
        Ok(())
    }

    /// Get interface status as JSON-like output
    pub fn status(&self) -> Result<WgStatus> {
        let output = Command::new("wg")
            .args(["show", &self.name, "dump"])
            .output()
            .context("Failed to run 'wg show'")?;

        if !output.status.success() {
            bail!("Failed to get status for {}", self.name);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_wg_dump(&stdout)
    }

    /// Full setup: create, configure, set address, and bring up
    pub fn setup(&self, address: &str) -> Result<()> {
        self.create()?;
        self.configure()?;
        self.set_address(address)?;
        self.up()?;
        Ok(())
    }
}

/// Parsed WireGuard status
#[derive(Debug, Clone)]
pub struct WgStatus {
    /// Interface public key
    pub public_key: String,
    /// Listen port
    pub listen_port: u16,
    /// Connected peers
    pub peers: Vec<WgPeerStatus>,
}

/// Peer status from wg show
#[derive(Debug, Clone)]
pub struct WgPeerStatus {
    /// Peer public key
    pub public_key: String,
    /// Endpoint (if known)
    pub endpoint: Option<String>,
    /// Allowed IPs
    pub allowed_ips: Vec<String>,
    /// Latest handshake (Unix timestamp)
    pub latest_handshake: Option<u64>,
    /// Transfer RX bytes
    pub rx_bytes: u64,
    /// Transfer TX bytes
    pub tx_bytes: u64,
}

/// Parse `wg show <iface> dump` output
fn parse_wg_dump(output: &str) -> Result<WgStatus> {
    let mut lines = output.lines();

    // First line is interface info
    let iface_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty wg output"))?;
    let iface_parts: Vec<&str> = iface_line.split('\t').collect();

    if iface_parts.len() < 3 {
        bail!("Invalid interface line format");
    }

    let public_key = iface_parts[1].to_string();
    let listen_port: u16 = iface_parts[2].parse().unwrap_or(0);

    // Remaining lines are peers
    let mut peers = Vec::new();
    for line in lines {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 5 {
            let peer = WgPeerStatus {
                public_key: parts[0].to_string(),
                endpoint: if parts[2] == "(none)" {
                    None
                } else {
                    Some(parts[2].to_string())
                },
                allowed_ips: parts[3]
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                latest_handshake: parts[4].parse().ok(),
                rx_bytes: parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0),
                tx_bytes: parts.get(6).and_then(|s| s.parse().ok()).unwrap_or(0),
            };
            peers.push(peer);
        }
    }

    Ok(WgStatus {
        public_key,
        listen_port,
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wg_dump() {
        let output = "wg0\tpubkey123=\t51820\tfwmark\n\
                      peerpubkey456=\tpreshared\t192.168.1.1:51820\t10.0.0.2/32\t1234567890\t1000\t2000\n";

        let status = parse_wg_dump(output).unwrap();
        assert_eq!(status.public_key, "pubkey123=");
        assert_eq!(status.listen_port, 51820);
        assert_eq!(status.peers.len(), 1);
        assert_eq!(
            status.peers[0].endpoint,
            Some("192.168.1.1:51820".to_string())
        );
    }
}
