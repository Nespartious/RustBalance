//! Coordination layer
//!
//! Handles inter-node communication, lease-based publisher election,
//! and heartbeat monitoring via WireGuard or Tor.

#![allow(unused_imports)] // Re-exports for public API

pub mod election;
pub mod lease;
pub mod messages;
pub mod peers;
pub mod wg;
pub mod wireguard;

pub use election::Election;
pub use lease::Lease;
pub use messages::{
    CoordMessage, IntroPointData, IntroPointsPayload, KnownPeerInfo, MessageType,
    PeerAnnouncePayload,
};
pub use peers::{PeerState, PeerTracker};
pub use wg::{WgInterface, WgPeer, WgPeerStatus, WgStatus};

use crate::config::{CoordinationConfig, WireguardConfig};
use anyhow::Result;

/// Coordination coordinator (manages all coordination tasks)
pub struct Coordinator {
    #[allow(dead_code)]
    config: CoordinationConfig,
    transport: CoordTransport,
    election: Election,
    peers: PeerTracker,
}

/// Transport abstraction for coordination messages
pub enum CoordTransport {
    WireGuard(wireguard::WgTransport),
    Tor, // TODO: Tor-based transport
}

impl Coordinator {
    /// Create new coordinator
    pub async fn new(
        config: &CoordinationConfig,
        wg_config: &Option<WireguardConfig>,
    ) -> Result<Self> {
        let transport = match config.mode.as_str() {
            "wireguard" => {
                let wg = wg_config
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("WireGuard config required"))?;
                CoordTransport::WireGuard(wireguard::WgTransport::new(wg).await?)
            },
            "tor" => CoordTransport::Tor,
            _ => anyhow::bail!("Unknown coordination mode"),
        };

        let peers = PeerTracker::new(
            config.heartbeat_interval_secs,
            3, // Dead after 3 missed heartbeats
        );

        Ok(Self {
            config: config.clone(),
            transport,
            election: Election::new(),
            peers,
        })
    }

    /// Send a message to all peers
    pub async fn broadcast(&self, msg: &CoordMessage) -> Result<()> {
        match &self.transport {
            CoordTransport::WireGuard(wg) => wg.broadcast(msg).await,
            CoordTransport::Tor => {
                // TODO: Tor-based broadcast
                Ok(())
            },
        }
    }

    /// Receive incoming messages
    pub async fn receive(&self) -> Result<CoordMessage> {
        match &self.transport {
            CoordTransport::WireGuard(wg) => wg.receive().await,
            CoordTransport::Tor => {
                // TODO: Tor-based receive
                anyhow::bail!("Tor transport not implemented")
            },
        }
    }

    /// Get the election state
    pub fn election(&self) -> &Election {
        &self.election
    }

    /// Get mutable election state
    pub fn election_mut(&mut self) -> &mut Election {
        &mut self.election
    }

    /// Get peer tracker
    pub fn peers(&self) -> &PeerTracker {
        &self.peers
    }

    /// Get mutable peer tracker
    pub fn peers_mut(&mut self) -> &mut PeerTracker {
        &mut self.peers
    }

    /// Process an incoming message (updates both election and peer state)
    pub fn process_message(&mut self, msg: &CoordMessage) {
        // Update peer tracking
        self.peers.process_heartbeat(msg);

        // Update election state
        self.election.process_message(msg);
    }

    /// Check for timed out peers
    pub fn check_peer_timeouts(&mut self) -> Vec<String> {
        self.peers.check_timeouts()
    }

    /// Add a new peer at runtime (for gossip-based discovery and bootstrap)
    /// This adds the peer to BOTH WireGuard transport AND the PeerTracker
    pub fn add_runtime_peer(
        &mut self,
        node_id: &str,
        wg_pubkey: &str,
        wg_endpoint: &str,
        tunnel_ip: &str,
    ) -> Result<bool> {
        // Add to WireGuard transport
        let added_to_wg = match &mut self.transport {
            CoordTransport::WireGuard(wg) => {
                wg.add_peer_runtime(node_id, wg_pubkey, wg_endpoint, tunnel_ip)?
            },
            CoordTransport::Tor => false,
        };

        // Also add to PeerTracker so heartbeat/election can find this peer
        if added_to_wg {
            self.peers
                .add_peer(node_id, wg_pubkey, wg_endpoint, tunnel_ip);
        }

        Ok(added_to_wg)
    }

    /// Send to a specific tunnel IP (for newly discovered peers)
    pub async fn send_to_tunnel_ip(&self, msg: &CoordMessage, tunnel_ip: &str) -> Result<()> {
        match &self.transport {
            CoordTransport::WireGuard(wg) => wg.send_to_tunnel_ip(msg, tunnel_ip).await,
            CoordTransport::Tor => {
                // TODO: Tor-based send
                Ok(())
            },
        }
    }

    /// Check if we have a specific peer in WireGuard
    pub fn has_wg_peer(&self, node_id: &str) -> bool {
        match &self.transport {
            CoordTransport::WireGuard(wg) => wg.has_peer(node_id),
            CoordTransport::Tor => false,
        }
    }
}
