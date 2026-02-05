//! WireGuard transport for coordination
//!
//! Automatically sets up WireGuard interface and manages peer connections.
//! Coordination messages flow through the encrypted WireGuard tunnel.

use crate::config::WireguardConfig;
use crate::coord::messages::CoordMessage;
use anyhow::{Context, Result};
use std::process::Command;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Default coordination port (used over the WireGuard tunnel)
const COORD_PORT: u16 = 51821;

/// WireGuard transport - manages WireGuard interface and coordination messaging
pub struct WgTransport {
    /// UDP socket bound to the tunnel IP for coordination
    socket: UdpSocket,
    /// Peer information for routing messages
    peers: Vec<PeerInfo>,
    /// Our tunnel IP address
    tunnel_ip: String,
    /// Interface name
    interface: String,
}

/// Peer connection info
#[derive(Clone)]
struct PeerInfo {
    id: String,
    /// Tunnel IP with coordination port (e.g., "10.200.200.2:51821")
    tunnel_endpoint: String,
    /// External WireGuard endpoint (e.g., "192.168.1.2:51820")
    wg_endpoint: Option<String>,
    /// WireGuard public key
    wg_pubkey: Option<String>,
}

impl WgTransport {
    /// Create new WireGuard transport with automatic interface setup
    pub async fn new(config: &WireguardConfig) -> Result<Self> {
        let interface = &config.interface;

        // Set up WireGuard interface
        Self::setup_interface(config).await?;

        // Determine our tunnel IP from config (first peer's allowed IPs tells us the network)
        // Convention: node-a gets .1, node-b gets .2, etc. based on config order
        let tunnel_ip = config
            .tunnel_ip
            .clone()
            .unwrap_or_else(|| "10.200.200.1".to_string());

        // Bind to our tunnel IP on the coordination port
        let bind_addr = format!("{}:{}", tunnel_ip, COORD_PORT);
        info!("Binding coordination socket to {}", bind_addr);

        let socket = UdpSocket::bind(&bind_addr)
            .await
            .with_context(|| format!("Failed to bind UDP socket on {}", bind_addr))?;

        // Build peer list with tunnel endpoints
        let peers: Vec<PeerInfo> = config
            .peers
            .iter()
            .map(|p| PeerInfo {
                id: p.id.clone(),
                // Peer tunnel IP with coordination port
                tunnel_endpoint: format!("{}:{}", p.tunnel_ip, COORD_PORT),
                wg_endpoint: Some(p.endpoint.clone()),
                wg_pubkey: Some(p.public_key.clone()),
            })
            .collect();

        info!(
            "WireGuard transport ready on {} with {} peers",
            bind_addr,
            peers.len()
        );

        Ok(Self {
            socket,
            peers,
            tunnel_ip,
            interface: interface.clone(),
        })
    }

    /// Set up the WireGuard interface using system commands
    async fn setup_interface(config: &WireguardConfig) -> Result<()> {
        let interface = &config.interface;
        let tunnel_ip = config.tunnel_ip.as_deref().unwrap_or("10.200.200.1");

        info!("Setting up WireGuard interface: {}", interface);

        // Check if interface already exists and is up
        let check = Command::new("wg").args(["show", interface]).output();

        let interface_configured = check.map(|o| o.status.success()).unwrap_or(false);

        if interface_configured {
            info!(
                "WireGuard interface {} already configured, skipping setup",
                interface
            );
        } else {
            // Check if interface exists at all
            let link_check = Command::new("ip")
                .args(["link", "show", interface])
                .output();

            let interface_exists = link_check.map(|o| o.status.success()).unwrap_or(false);

            if !interface_exists {
                // Create the WireGuard interface
                Self::run_cmd(
                    "ip",
                    &["link", "add", "dev", interface, "type", "wireguard"],
                )?;
            }

            // Configure WireGuard with private key using echo and pipe via shell
            // This avoids needing to write to a temp file
            let cmd = format!(
                "echo '{}' | wg set {} listen-port {} private-key /dev/stdin",
                config.private_key, interface, config.listen_port
            );
            Self::run_shell(&cmd).context("Failed to configure WireGuard private key")?;

            // Add peers
            for peer in &config.peers {
                info!("Adding WireGuard peer: {} at {}", peer.id, peer.endpoint);

                // allowed-ips is the peer's tunnel IP
                let allowed_ips = format!("{}/32", peer.tunnel_ip);

                Self::run_cmd(
                    "wg",
                    &[
                        "set",
                        interface,
                        "peer",
                        &peer.public_key,
                        "endpoint",
                        &peer.endpoint,
                        "allowed-ips",
                        &allowed_ips,
                        "persistent-keepalive",
                        "25",
                    ],
                )?;
            }

            // Add IP address and bring up the interface
            let tunnel_cidr = format!("{}/24", tunnel_ip);
            let _ = Self::run_cmd("ip", &["addr", "add", &tunnel_cidr, "dev", interface]);
            Self::run_cmd("ip", &["link", "set", interface, "up"])?;

            info!("WireGuard interface {} configured successfully", interface);
        }

        // Brief delay for interface to be ready
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        Ok(())
    }

    /// Run a system command and check for errors
    fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
        debug!("Running: {} {}", cmd, args.join(" "));

        let output = Command::new(cmd)
            .args(args)
            .output()
            .with_context(|| format!("Failed to execute {}", cmd))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("{} failed: {}", cmd, stderr);
        }

        Ok(())
    }

    /// Run a shell command (for pipes and redirection)
    fn run_shell(cmd: &str) -> Result<()> {
        debug!("Running shell: {}", cmd);

        let output = Command::new("sh")
            .args(["-c", cmd])
            .output()
            .with_context(|| format!("Failed to execute shell: {}", cmd))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("shell command failed: {}", stderr);
        }

        Ok(())
    }

    /// Broadcast a message to all peers
    pub async fn broadcast(&self, msg: &CoordMessage) -> Result<()> {
        let data = msg.to_bytes();

        for peer in &self.peers {
            match self.socket.send_to(&data, &peer.tunnel_endpoint).await {
                Ok(n) => {
                    debug!("Sent {} bytes to {} ({})", n, peer.id, peer.tunnel_endpoint);
                },
                Err(e) => {
                    warn!("Failed to send to {}: {}", peer.id, e);
                },
            }
        }

        Ok(())
    }

    /// Receive a message from any peer
    pub async fn receive(&self) -> Result<CoordMessage> {
        let mut buf = [0u8; 4096];

        loop {
            let (n, addr) = self.socket.recv_from(&mut buf).await?;

            match CoordMessage::from_bytes(&buf[..n]) {
                Some(msg) => {
                    debug!("Received message from {} ({} bytes)", addr, n);
                    return Ok(msg);
                },
                None => {
                    warn!("Invalid message from {}", addr);
                    continue;
                },
            }
        }
    }

    /// Send to a specific peer
    pub async fn send_to(&self, msg: &CoordMessage, peer_id: &str) -> Result<()> {
        let data = msg.to_bytes();

        if let Some(peer) = self.peers.iter().find(|p| p.id == peer_id) {
            self.socket.send_to(&data, &peer.tunnel_endpoint).await?;
            debug!("Sent {} bytes to {}", data.len(), peer_id);
        } else {
            warn!("Unknown peer: {}", peer_id);
        }

        Ok(())
    }

    /// Send to a specific tunnel IP (for newly discovered peers)
    pub async fn send_to_tunnel_ip(&self, msg: &CoordMessage, tunnel_ip: &str) -> Result<()> {
        let data = msg.to_bytes();
        let endpoint = format!("{}:{}", tunnel_ip, COORD_PORT);

        self.socket.send_to(&data, &endpoint).await?;
        debug!("Sent {} bytes to tunnel IP {}", data.len(), tunnel_ip);

        Ok(())
    }

    /// Add a new peer at runtime (for gossip-based discovery)
    /// This adds the peer to both WireGuard and our internal peer list
    pub fn add_peer_runtime(
        &mut self,
        node_id: &str,
        wg_pubkey: &str,
        wg_endpoint: &str,
        tunnel_ip: &str,
    ) -> Result<bool> {
        // Check if we already have this peer
        if self.peers.iter().any(|p| p.id == node_id) {
            debug!("Peer {} already known, skipping", node_id);
            return Ok(false);
        }

        info!(
            "Adding runtime peer: {} (endpoint: {}, tunnel: {})",
            node_id, wg_endpoint, tunnel_ip
        );

        // Add to WireGuard
        let allowed_ips = format!("{}/32", tunnel_ip);
        Self::run_cmd(
            "wg",
            &[
                "set",
                &self.interface,
                "peer",
                wg_pubkey,
                "endpoint",
                wg_endpoint,
                "allowed-ips",
                &allowed_ips,
                "persistent-keepalive",
                "25",
            ],
        )?;

        // Add to our peer list
        self.peers.push(PeerInfo {
            id: node_id.to_string(),
            tunnel_endpoint: format!("{}:{}", tunnel_ip, COORD_PORT),
            wg_endpoint: Some(wg_endpoint.to_string()),
            wg_pubkey: Some(wg_pubkey.to_string()),
        });

        info!("Successfully added runtime peer: {}", node_id);
        Ok(true)
    }

    /// Check if we know a peer by node ID
    pub fn has_peer(&self, node_id: &str) -> bool {
        self.peers.iter().any(|p| p.id == node_id)
    }

    /// Get our tunnel IP
    pub fn tunnel_ip(&self) -> &str {
        &self.tunnel_ip
    }

    /// Get our interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Cleanup WireGuard interface on shutdown
    pub fn cleanup(&self) {
        info!("Cleaning up WireGuard interface: {}", self.interface);
        let _ = Command::new("ip")
            .args(["link", "del", &self.interface])
            .output();
    }
}

impl Drop for WgTransport {
    fn drop(&mut self) {
        self.cleanup();
    }
}
