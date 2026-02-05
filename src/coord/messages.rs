//! Coordination message protocol
//!
//! Simple, authenticated messages for heartbeats, lease claims, peer announcements,
//! and intro point sharing. Transport-agnostic - works over WireGuard or Tor.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Coordination message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordMessage {
    /// Sender node ID
    pub node_id: String,
    /// Unix timestamp
    pub timestamp: u64,
    /// Message type and payload
    #[serde(flatten)]
    pub message: MessageType,
}

/// Message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum MessageType {
    /// Heartbeat from a node
    #[serde(rename = "heartbeat")]
    Heartbeat(HeartbeatPayload),

    /// Claim publisher lease
    #[serde(rename = "lease_claim")]
    LeaseClaim(LeaseClaimPayload),

    /// Release publisher lease
    #[serde(rename = "lease_release")]
    LeaseRelease,

    /// Report unhealthy backend
    #[serde(rename = "backend_unhealthy")]
    BackendUnhealthy(BackendUnhealthyPayload),

    /// Peer announcement (for auto-joining mesh)
    #[serde(rename = "peer_announce")]
    PeerAnnounce(PeerAnnouncePayload),

    /// Introduction points from a node
    #[serde(rename = "intro_points")]
    IntroPoints(IntroPointsPayload),

    /// Join request via Tor bootstrap channel (new node joining cluster)
    #[serde(rename = "join_request")]
    JoinRequest(JoinRequestPayload),

    /// Join response from existing node
    #[serde(rename = "join_response")]
    JoinResponse(JoinResponsePayload),
}

/// Heartbeat payload with peer gossip for mesh self-healing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    /// Current role
    pub role: NodeRole,
    /// Timestamp of last publish (if publisher)
    pub last_publish_ts: Option<u64>,
    /// Known peers for gossip protocol (mesh self-healing)
    #[serde(default)]
    pub known_peers: Vec<KnownPeerInfo>,
    /// Our introduction point count (for publisher to know if we have IPs)
    #[serde(default)]
    pub intro_point_count: usize,
}

/// Information about a known peer for gossip
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownPeerInfo {
    /// Peer's node ID
    pub node_id: String,
    /// Peer's WireGuard public key
    pub wg_pubkey: String,
    /// Peer's external endpoint (public IP:port)
    pub wg_endpoint: String,
    /// Peer's tunnel IP
    pub tunnel_ip: String,
}

/// Peer announcement payload for joining the mesh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnouncePayload {
    /// Cluster join token (validated by existing nodes)
    pub cluster_token: String,
    /// Announcing node's WireGuard public key
    pub wg_pubkey: String,
    /// Announcing node's external endpoint
    pub wg_endpoint: String,
    /// Announcing node's tunnel IP
    pub tunnel_ip: String,
}

/// Introduction points payload for descriptor merging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroPointsPayload {
    /// Raw introduction point data (base64 encoded)
    pub intro_points: Vec<IntroPointData>,
    /// Timestamp when these intro points were fetched
    pub fetched_at: u64,
}

/// Single introduction point data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroPointData {
    /// Base64-encoded raw intro point data
    pub data: String,
}

/// Node role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Publisher,
    Standby,
}

/// Lease claim payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseClaimPayload {
    /// Node's election priority (lower = higher priority)
    pub priority: u32,
}

/// Backend unhealthy notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendUnhealthyPayload {
    /// Backend name
    pub backend: String,
}

/// Join request payload - sent via Tor bootstrap channel
/// New node sends this to master.onion to register with the cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequestPayload {
    /// Cluster token for authentication
    pub cluster_token: String,
    /// Node's WireGuard public key
    pub wg_pubkey: String,
    /// Node's external endpoint (IP:port for WireGuard)
    pub wg_endpoint: String,
    /// Node's tunnel IP (e.g., "10.200.200.11")
    pub tunnel_ip: String,
    /// Request timestamp (for replay protection)
    pub request_time: u64,
}

/// Join response payload - sent back to joining node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponsePayload {
    /// Whether join was successful
    pub success: bool,
    /// Error message if not successful
    pub error: Option<String>,
    /// Responding node's ID
    pub responder_node_id: String,
    /// Responding node's WireGuard public key
    pub responder_wg_pubkey: String,
    /// Responding node's external endpoint
    pub responder_wg_endpoint: String,
    /// Responding node's tunnel IP
    pub responder_tunnel_ip: String,
    /// List of other known peers (for mesh discovery)
    pub known_peers: Vec<KnownPeerInfo>,
}

impl CoordMessage {
    /// Create a new message with current timestamp
    pub fn new(node_id: String, message: MessageType) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            node_id,
            timestamp,
            message,
        }
    }

    /// Create a heartbeat message with peer gossip
    pub fn heartbeat(
        node_id: String,
        role: NodeRole,
        last_publish: Option<u64>,
        known_peers: Vec<KnownPeerInfo>,
        intro_point_count: usize,
    ) -> Self {
        Self::new(
            node_id,
            MessageType::Heartbeat(HeartbeatPayload {
                role,
                last_publish_ts: last_publish,
                known_peers,
                intro_point_count,
            }),
        )
    }

    /// Create a peer announcement message
    pub fn peer_announce(
        node_id: String,
        cluster_token: String,
        wg_pubkey: String,
        wg_endpoint: String,
        tunnel_ip: String,
    ) -> Self {
        Self::new(
            node_id,
            MessageType::PeerAnnounce(PeerAnnouncePayload {
                cluster_token,
                wg_pubkey,
                wg_endpoint,
                tunnel_ip,
            }),
        )
    }

    /// Create an intro points message
    pub fn intro_points(node_id: String, intro_points: Vec<IntroPointData>) -> Self {
        let fetched_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self::new(
            node_id,
            MessageType::IntroPoints(IntroPointsPayload {
                intro_points,
                fetched_at,
            }),
        )
    }

    /// Create a lease claim message
    pub fn lease_claim(node_id: String, priority: u32) -> Self {
        Self::new(
            node_id,
            MessageType::LeaseClaim(LeaseClaimPayload { priority }),
        )
    }

    /// Create a lease release message
    pub fn lease_release(node_id: String) -> Self {
        Self::new(node_id, MessageType::LeaseRelease)
    }

    /// Check if message is within time window
    pub fn is_valid_time(&self, tolerance_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let diff = if now > self.timestamp {
            now - self.timestamp
        } else {
            self.timestamp - now
        };

        diff <= tolerance_secs
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_serialization() {
        let msg = CoordMessage::heartbeat(
            "node-a".to_string(),
            NodeRole::Publisher,
            Some(1_234_567_890),
            vec![],
            3,
        );

        let bytes = msg.to_bytes();
        let parsed = CoordMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.node_id, "node-a");
    }
}
