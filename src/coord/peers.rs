//! Peer state tracking
//!
//! Tracks the state of cluster peers based on heartbeats.
//! Supports gossip-based peer discovery for mesh self-healing.

use crate::coord::messages::{CoordMessage, IntroPointData, KnownPeerInfo, MessageType, NodeRole};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

/// Peer lifecycle state - tracks where the peer is in its join/health lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerLifecycle {
    /// Just received JoinRequest via Tor, added to WireGuard, awaiting first heartbeat
    #[default]
    Joining,
    /// Receiving heartbeats but intro_point_count == 0 (Tor still bootstrapping)
    Initializing,
    /// Healthy with intro points, eligible for descriptor inclusion
    Healthy,
    /// Was healthy, now missing heartbeats - grace period before removal
    Unhealthy,
    /// Timed out, should be removed from descriptor
    Dead,
}

/// Peer state information
#[derive(Debug, Clone)]
pub struct PeerState {
    /// Peer node ID
    pub node_id: String,
    /// Peer's WireGuard public key
    pub wg_pubkey: Option<String>,
    /// Peer's external endpoint (public IP:port)
    pub endpoint: Option<String>,
    /// Peer's tunnel IP
    pub tunnel_ip: Option<String>,
    /// Last known role
    pub role: NodeRole,
    /// Last heartbeat received
    pub last_heartbeat: SystemTime,
    /// Last publish timestamp (if publisher)
    pub last_publish_ts: Option<u64>,
    /// Number of missed heartbeats
    pub missed_heartbeats: u32,
    /// Is the peer considered alive?
    pub alive: bool,
    /// Peer's introduction points (for descriptor merging)
    pub intro_points: Vec<IntroPointData>,
    /// When intro points were last updated
    pub intro_points_updated: Option<SystemTime>,
    /// Peer lifecycle state
    pub lifecycle: PeerLifecycle,
    /// When the peer entered current lifecycle state
    pub lifecycle_since: Instant,
    /// Number of intro points reported in last heartbeat
    pub last_intro_point_count: usize,
}

impl PeerState {
    /// Create new peer state from a heartbeat
    pub fn from_heartbeat(msg: &CoordMessage) -> Option<Self> {
        if let MessageType::Heartbeat(payload) = &msg.message {
            let intro_count = payload.intro_point_count;
            let lifecycle = if intro_count > 0 {
                PeerLifecycle::Healthy
            } else {
                PeerLifecycle::Initializing
            };
            Some(Self {
                node_id: msg.node_id.clone(),
                wg_pubkey: None,
                endpoint: None,
                tunnel_ip: None,
                role: payload.role,
                last_heartbeat: SystemTime::now(),
                last_publish_ts: payload.last_publish_ts,
                missed_heartbeats: 0,
                alive: true,
                intro_points: Vec::new(),
                intro_points_updated: None,
                lifecycle,
                lifecycle_since: Instant::now(),
                last_intro_point_count: intro_count,
            })
        } else {
            None
        }
    }

    /// Create peer state from a peer announcement
    pub fn from_peer_announce(msg: &CoordMessage) -> Option<Self> {
        if let MessageType::PeerAnnounce(payload) = &msg.message {
            Some(Self {
                node_id: msg.node_id.clone(),
                wg_pubkey: Some(payload.wg_pubkey.clone()),
                endpoint: Some(payload.wg_endpoint.clone()),
                tunnel_ip: Some(payload.tunnel_ip.clone()),
                role: NodeRole::Standby,
                last_heartbeat: SystemTime::now(),
                last_publish_ts: None,
                missed_heartbeats: 0,
                alive: true,
                intro_points: Vec::new(),
                intro_points_updated: None,
                lifecycle: PeerLifecycle::Joining,
                lifecycle_since: Instant::now(),
                last_intro_point_count: 0,
            })
        } else {
            None
        }
    }

    /// Create peer state from gossip info
    pub fn from_gossip(info: &KnownPeerInfo) -> Self {
        Self {
            node_id: info.node_id.clone(),
            wg_pubkey: Some(info.wg_pubkey.clone()),
            endpoint: Some(info.wg_endpoint.clone()),
            tunnel_ip: Some(info.tunnel_ip.clone()),
            role: NodeRole::Standby,
            last_heartbeat: SystemTime::now(),
            last_publish_ts: None,
            missed_heartbeats: 0,
            alive: false, // Not confirmed until we get a direct heartbeat
            intro_points: Vec::new(),
            intro_points_updated: None,
            lifecycle: PeerLifecycle::Joining,
            lifecycle_since: Instant::now(),
            last_intro_point_count: 0,
        }
    }

    /// Create peer state from a JoinRequest (Tor bootstrap)
    pub fn from_join_request(
        node_id: &str,
        wg_pubkey: &str,
        wg_endpoint: &str,
        tunnel_ip: &str,
    ) -> Self {
        Self {
            node_id: node_id.to_string(),
            wg_pubkey: Some(wg_pubkey.to_string()),
            endpoint: Some(wg_endpoint.to_string()),
            tunnel_ip: Some(tunnel_ip.to_string()),
            role: NodeRole::Standby,
            last_heartbeat: SystemTime::now(),
            last_publish_ts: None,
            missed_heartbeats: 0,
            alive: false, // Not confirmed until heartbeat received over WireGuard
            intro_points: Vec::new(),
            intro_points_updated: None,
            lifecycle: PeerLifecycle::Joining,
            lifecycle_since: Instant::now(),
            last_intro_point_count: 0,
        }
    }

    /// Update from a new heartbeat
    pub fn update_heartbeat(&mut self, msg: &CoordMessage) {
        if let MessageType::Heartbeat(payload) = &msg.message {
            self.role = payload.role;
            self.last_heartbeat = SystemTime::now();
            self.last_publish_ts = payload.last_publish_ts;
            self.missed_heartbeats = 0;
            self.alive = true;
            self.last_intro_point_count = payload.intro_point_count;

            // Update lifecycle based on intro point count
            let new_lifecycle = if payload.intro_point_count > 0 {
                PeerLifecycle::Healthy
            } else {
                PeerLifecycle::Initializing
            };

            if self.lifecycle != new_lifecycle {
                tracing::info!(
                    "Peer {} lifecycle: {:?} -> {:?} (intro_points: {})",
                    self.node_id,
                    self.lifecycle,
                    new_lifecycle,
                    payload.intro_point_count
                );
                self.lifecycle = new_lifecycle;
                self.lifecycle_since = Instant::now();
            }
        }
    }

    /// Update introduction points
    pub fn update_intro_points(&mut self, intro_points: Vec<IntroPointData>) {
        self.intro_points = intro_points;
        self.intro_points_updated = Some(SystemTime::now());
    }

    /// Check if peer is eligible for inclusion in descriptor
    pub fn is_eligible_for_publish(&self) -> bool {
        matches!(self.lifecycle, PeerLifecycle::Healthy) && self.last_intro_point_count > 0
    }

    /// Convert to KnownPeerInfo for gossip
    pub fn to_known_peer_info(&self) -> Option<KnownPeerInfo> {
        match (&self.wg_pubkey, &self.endpoint, &self.tunnel_ip) {
            (Some(pubkey), Some(endpoint), Some(tunnel_ip)) => Some(KnownPeerInfo {
                node_id: self.node_id.clone(),
                wg_pubkey: pubkey.clone(),
                wg_endpoint: endpoint.clone(),
                tunnel_ip: tunnel_ip.clone(),
            }),
            _ => None,
        }
    }

    /// Time since last heartbeat
    pub fn since_last_heartbeat(&self) -> Duration {
        self.last_heartbeat.elapsed().unwrap_or(Duration::ZERO)
    }

    /// Mark as having missed a heartbeat
    pub fn mark_missed(&mut self) {
        self.missed_heartbeats += 1;
    }

    /// Check if peer should be considered dead
    pub fn is_dead(&self, threshold: u32) -> bool {
        self.missed_heartbeats >= threshold
    }
}

/// Peer tracker - manages all known peers
#[derive(Debug)]
pub struct PeerTracker {
    /// Known peers
    peers: HashMap<String, PeerState>,
    /// Heartbeat interval (seconds)
    heartbeat_interval: u64,
    /// Number of missed heartbeats before considered dead
    dead_threshold: u32,
}

impl PeerTracker {
    /// Create new peer tracker
    pub fn new(heartbeat_interval: u64, dead_threshold: u32) -> Self {
        Self {
            peers: HashMap::new(),
            heartbeat_interval,
            dead_threshold,
        }
    }

    /// Process an incoming heartbeat
    pub fn process_heartbeat(&mut self, msg: &CoordMessage) {
        if let Some(existing) = self.peers.get_mut(&msg.node_id) {
            existing.update_heartbeat(msg);
        } else if let Some(state) = PeerState::from_heartbeat(msg) {
            self.peers.insert(msg.node_id.clone(), state);
        }
    }

    /// Add a peer with known WireGuard info
    pub fn add_peer(&mut self, node_id: &str, wg_pubkey: &str, endpoint: &str, tunnel_ip: &str) {
        if !self.peers.contains_key(node_id) {
            self.peers.insert(
                node_id.to_string(),
                PeerState {
                    node_id: node_id.to_string(),
                    wg_pubkey: Some(wg_pubkey.to_string()),
                    endpoint: Some(endpoint.to_string()),
                    tunnel_ip: Some(tunnel_ip.to_string()),
                    role: NodeRole::Standby,
                    last_heartbeat: SystemTime::now(),
                    last_publish_ts: None,
                    missed_heartbeats: 0,
                    alive: false, // Not confirmed until heartbeat received
                    intro_points: Vec::new(),
                    intro_points_updated: None,
                    lifecycle: PeerLifecycle::Joining,
                    lifecycle_since: Instant::now(),
                    last_intro_point_count: 0,
                },
            );
        }
    }

    /// Add or update peer from gossip
    pub fn process_gossip(&mut self, info: &KnownPeerInfo) -> bool {
        if self.peers.contains_key(&info.node_id) {
            // Already know this peer
            false
        } else {
            // New peer from gossip - add it
            self.peers
                .insert(info.node_id.clone(), PeerState::from_gossip(info));
            true
        }
    }

    /// Process peer announcement
    pub fn process_peer_announce(&mut self, msg: &CoordMessage) -> bool {
        if let Some(state) = PeerState::from_peer_announce(msg) {
            if self.peers.contains_key(&msg.node_id) {
                // Update WireGuard info for existing peer
                if let (Some(existing), MessageType::PeerAnnounce(payload)) =
                    (self.peers.get_mut(&msg.node_id), &msg.message)
                {
                    existing.wg_pubkey = Some(payload.wg_pubkey.clone());
                    existing.endpoint = Some(payload.wg_endpoint.clone());
                    existing.tunnel_ip = Some(payload.tunnel_ip.clone());
                }
            } else {
                self.peers.insert(msg.node_id.clone(), state);
                return true;
            }
        }
        false
    }

    /// Update peer's intro points
    pub fn update_intro_points(&mut self, node_id: &str, intro_points: Vec<IntroPointData>) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.update_intro_points(intro_points);
        }
    }

    /// Get all known peers as gossip info (for heartbeat)
    pub fn get_known_peer_infos(&self) -> Vec<KnownPeerInfo> {
        self.peers
            .values()
            .filter_map(|p| p.to_known_peer_info())
            .collect()
    }

    /// Get new peers from gossip list (peers we don't know about)
    pub fn find_unknown_peers(&self, gossip_peers: &[KnownPeerInfo]) -> Vec<KnownPeerInfo> {
        gossip_peers
            .iter()
            .filter(|p| !self.peers.contains_key(&p.node_id))
            .cloned()
            .collect()
    }

    /// Get total intro point count from all alive peers
    pub fn total_peer_intro_points(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.alive)
            .map(|p| p.last_intro_point_count)
            .sum()
    }

    /// Get all intro points from alive peers (for merging)
    pub fn collect_peer_intro_points(&self) -> Vec<&IntroPointData> {
        self.peers
            .values()
            .filter(|p| p.alive)
            .flat_map(|p| p.intro_points.iter())
            .collect()
    }

    /// Check for timed out peers (call periodically)
    pub fn check_timeouts(&mut self) -> Vec<String> {
        let timeout = Duration::from_secs(self.heartbeat_interval * 2);
        let mut dead_peers = Vec::new();

        for (node_id, peer) in self.peers.iter_mut() {
            if peer.since_last_heartbeat() > timeout {
                peer.mark_missed();

                if peer.is_dead(self.dead_threshold) && peer.alive {
                    peer.alive = false;
                    dead_peers.push(node_id.clone());
                }
            }
        }

        dead_peers
    }

    /// Get all alive peers
    pub fn alive_peers(&self) -> Vec<&PeerState> {
        self.peers.values().filter(|p| p.alive).collect()
    }

    /// Get a specific peer
    pub fn get_peer(&self, node_id: &str) -> Option<&PeerState> {
        self.peers.get(node_id)
    }

    /// Get the current publisher (if any)
    pub fn current_publisher(&self) -> Option<&PeerState> {
        self.peers
            .values()
            .find(|p| p.alive && p.role == NodeRole::Publisher)
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get alive peer count
    pub fn alive_count(&self) -> usize {
        self.peers.values().filter(|p| p.alive).count()
    }

    /// Remove dead peers
    pub fn prune_dead(&mut self) -> Vec<String> {
        let dead: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| !p.alive && p.is_dead(self.dead_threshold * 2))
            .map(|(id, _)| id.clone())
            .collect();

        for id in &dead {
            self.peers.remove(id);
        }

        dead
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_tracking() {
        let mut tracker = PeerTracker::new(5, 3);

        let msg = CoordMessage::heartbeat(
            "node-a".to_string(),
            NodeRole::Publisher,
            Some(12345),
            vec![],
            3,
        );

        tracker.process_heartbeat(&msg);

        assert_eq!(tracker.peer_count(), 1);
        assert_eq!(tracker.alive_count(), 1);

        let publisher = tracker.current_publisher();
        assert!(publisher.is_some());
        assert_eq!(publisher.unwrap().node_id, "node-a");
    }

    #[test]
    fn test_gossip_discovery() {
        let mut tracker = PeerTracker::new(5, 3);

        let gossip_info = KnownPeerInfo {
            node_id: "node-b".to_string(),
            wg_pubkey: "pubkey123".to_string(),
            wg_endpoint: "192.168.1.2:51820".to_string(),
            tunnel_ip: "10.200.200.2".to_string(),
        };

        // Process gossip - should add new peer
        let added = tracker.process_gossip(&gossip_info);
        assert!(added);
        assert_eq!(tracker.peer_count(), 1);

        // Process same gossip - should not add duplicate
        let added_again = tracker.process_gossip(&gossip_info);
        assert!(!added_again);
        assert_eq!(tracker.peer_count(), 1);
    }
}
