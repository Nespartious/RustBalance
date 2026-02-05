//! Publisher election logic
//!
//! Deterministic, lease-based election without consensus.
//! Lowest priority number wins when publisher is absent.

use crate::coord::messages::{CoordMessage, MessageType, NodeRole};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Election state
#[derive(Debug)]
pub struct Election {
    /// This node's ID
    node_id: String,
    /// This node's priority
    priority: u32,
    /// Current role
    role: NodeRole,
    /// Known peers and their last heartbeat
    peers: HashMap<String, PeerState>,
    /// Current publisher (if known)
    current_publisher: Option<String>,
    /// Heartbeat timeout
    heartbeat_timeout: Duration,
    /// Grace period before takeover
    takeover_grace: Duration,
    /// When publisher was marked suspect
    publisher_suspect_since: Option<SystemTime>,
}

/// State of a peer node
#[derive(Debug, Clone)]
pub struct PeerState {
    pub priority: u32,
    pub role: NodeRole,
    pub last_seen: SystemTime,
    pub last_publish_ts: Option<u64>,
}

impl Election {
    pub fn new() -> Self {
        Self {
            node_id: String::new(),
            priority: u32::MAX,
            role: NodeRole::Standby,
            peers: HashMap::new(),
            current_publisher: None,
            heartbeat_timeout: Duration::from_secs(30),
            takeover_grace: Duration::from_secs(90),
            publisher_suspect_since: None,
        }
    }

    /// Initialize with configuration
    pub fn init(&mut self, node_id: String, priority: u32, timeout_secs: u64, grace_secs: u64) {
        self.node_id = node_id;
        self.priority = priority;
        self.heartbeat_timeout = Duration::from_secs(timeout_secs);
        self.takeover_grace = Duration::from_secs(grace_secs);
    }

    /// Process an incoming coordination message
    pub fn process_message(&mut self, msg: &CoordMessage) {
        match &msg.message {
            MessageType::Heartbeat(payload) => {
                self.process_heartbeat(&msg.node_id, payload.role, payload.last_publish_ts);
            },
            MessageType::LeaseClaim(payload) => {
                self.process_lease_claim(&msg.node_id, payload.priority);
            },
            MessageType::LeaseRelease => {
                self.process_lease_release(&msg.node_id);
            },
            _ => {},
        }
    }

    /// Process a heartbeat from a peer
    fn process_heartbeat(&mut self, node_id: &str, role: NodeRole, last_publish: Option<u64>) {
        let state = self.peers.entry(node_id.to_string()).or_insert(PeerState {
            priority: u32::MAX,
            role: NodeRole::Standby,
            last_seen: SystemTime::now(),
            last_publish_ts: None,
        });

        state.role = role;
        state.last_seen = SystemTime::now();
        state.last_publish_ts = last_publish;

        // Track current publisher
        if role == NodeRole::Publisher {
            if self.current_publisher.as_ref() != Some(&node_id.to_string()) {
                info!("Publisher is now: {}", node_id);
            }
            self.current_publisher = Some(node_id.to_string());
            self.publisher_suspect_since = None;
        }
    }

    /// Process a lease claim
    fn process_lease_claim(&mut self, node_id: &str, priority: u32) {
        if let Some(state) = self.peers.get_mut(node_id) {
            state.priority = priority;
        }

        // If this claim has higher priority (lower number) than us, back off
        if priority < self.priority && self.role == NodeRole::Publisher {
            warn!(
                "Backing off: {} has higher priority ({} < {})",
                node_id, priority, self.priority
            );
            self.role = NodeRole::Standby;
        }
    }

    /// Process a lease release
    fn process_lease_release(&mut self, node_id: &str) {
        if self.current_publisher.as_ref() == Some(&node_id.to_string()) {
            info!("Publisher {} released lease", node_id);
            self.current_publisher = None;
        }
    }

    /// Check if we should take over as publisher
    pub fn should_take_over(&mut self) -> bool {
        // Already publisher
        if self.role == NodeRole::Publisher {
            return false;
        }

        // Check if current publisher is healthy
        if let Some(ref publisher) = self.current_publisher {
            if let Some(state) = self.peers.get(publisher) {
                if let Ok(elapsed) = state.last_seen.elapsed() {
                    if elapsed < self.heartbeat_timeout {
                        // Publisher is healthy
                        self.publisher_suspect_since = None;
                        return false;
                    }
                }
            }

            // Publisher is suspect
            let now = SystemTime::now();
            if self.publisher_suspect_since.is_none() {
                debug!("Publisher {} is suspect", publisher);
                self.publisher_suspect_since = Some(now);
            }

            // Check grace period
            if let Some(suspect_time) = self.publisher_suspect_since {
                if let Ok(elapsed) = now.duration_since(suspect_time) {
                    if elapsed >= self.takeover_grace {
                        // Check if we have highest priority among candidates
                        return self.is_highest_priority_candidate();
                    }
                }
            }

            return false;
        }

        // No publisher - check if we should claim
        self.is_highest_priority_candidate()
    }

    /// Check if we have the highest priority (lowest number) among healthy nodes
    fn is_highest_priority_candidate(&self) -> bool {
        for (node_id, state) in &self.peers {
            // Skip dead nodes
            if let Ok(elapsed) = state.last_seen.elapsed() {
                if elapsed > self.heartbeat_timeout {
                    continue;
                }
            } else {
                continue;
            }

            // Check if peer has higher priority
            if state.priority < self.priority {
                debug!("Node {} has higher priority", node_id);
                return false;
            }
        }

        true
    }

    /// Become publisher
    pub fn become_publisher(&mut self) {
        info!("Taking over as publisher");
        self.role = NodeRole::Publisher;
        self.current_publisher = Some(self.node_id.clone());
        self.publisher_suspect_since = None;
    }

    /// Step down from publisher role
    pub fn become_standby(&mut self) {
        if self.role == NodeRole::Publisher {
            info!("Stepping down to standby");
        }
        self.role = NodeRole::Standby;
    }

    /// Get current role
    pub fn role(&self) -> NodeRole {
        self.role
    }

    /// Check if we are publisher
    pub fn is_publisher(&self) -> bool {
        self.role == NodeRole::Publisher
    }
}
