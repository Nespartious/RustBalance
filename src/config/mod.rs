//! Configuration loading and validation
//!
//! Handles TOML configuration parsing with strict validation.
//! No runtime mutation - configuration is immutable after load.

#![allow(unused_imports)] // Re-exports for public API

pub mod file;
mod validation;

pub use file::load_config;
pub use validation::validate;

use serde::Deserialize;
use std::path::PathBuf;

/// Root configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    pub master: MasterConfig,
    pub tor: TorConfig,
    pub publish: PublishConfig,
    pub health: HealthConfig,
    pub coordination: CoordinationConfig,
    pub wireguard: Option<WireguardConfig>,
    /// Target service to reverse proxy to
    pub target: TargetConfig,
    /// Local port to listen for hidden service connections
    #[serde(default = "default_local_port")]
    pub local_port: u16,
    /// DEPRECATED: Legacy hidden service directory field.
    /// In multi-node mode, use node.hidden_service_dir instead.
    /// This field is kept for backward compatibility but should not be used.
    #[serde(default = "default_hs_dir")]
    pub hidden_service_dir: String,
}

/// Node identity and priority
#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// Unique node identifier
    pub id: String,
    /// Election priority (lower = higher priority)
    pub priority: u32,
    /// Clock skew tolerance in seconds
    #[serde(default = "default_clock_skew")]
    pub clock_skew_tolerance_secs: u64,
    /// Node-specific hidden service directory (for this node's unique .onion address)
    /// This is where Tor stores this node's keys and creates intro points.
    /// Separate from master key dir - Tor auto-publishes for this address (not master).
    #[serde(default = "default_node_hs_dir")]
    pub hidden_service_dir: String,
}

fn default_node_hs_dir() -> String {
    "/var/lib/tor/rustbalance_node_hs".to_string()
}

fn default_clock_skew() -> u64 {
    5
}

/// Master onion identity
#[derive(Debug, Clone, Deserialize)]
pub struct MasterConfig {
    /// Master .onion address
    pub onion_address: String,
    /// Path to Ed25519 identity key
    pub identity_key_path: PathBuf,
}

/// Tor daemon connection
#[derive(Debug, Clone, Deserialize)]
pub struct TorConfig {
    #[serde(default = "default_control_host")]
    pub control_host: String,
    #[serde(default = "default_control_port")]
    pub control_port: u16,
    pub control_password: Option<String>,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
}

fn default_control_host() -> String {
    "127.0.0.1".to_string()
}
fn default_control_port() -> u16 {
    9051
}
fn default_socks_port() -> u16 {
    9050
}

/// Descriptor publishing settings
#[derive(Debug, Clone, Deserialize)]
pub struct PublishConfig {
    /// Refresh interval in seconds
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: u64,
    /// Grace period before takeover
    #[serde(default = "default_grace")]
    pub takeover_grace_secs: u64,
    /// Maximum intro points per descriptor
    #[serde(default = "default_max_ips")]
    pub max_intro_points: usize,
}

fn default_refresh() -> u64 {
    600
}
fn default_grace() -> u64 {
    90
}
fn default_max_ips() -> usize {
    20
}

/// Backend health check settings
#[derive(Debug, Clone, Deserialize)]
pub struct HealthConfig {
    /// Maximum descriptor age before considered stale
    #[serde(default = "default_max_age")]
    pub descriptor_max_age_secs: u64,
    /// Enable HTTP endpoint probing
    #[serde(default)]
    pub http_probe_enabled: bool,
    /// HTTP probe path
    #[serde(default = "default_probe_path")]
    pub http_probe_path: String,
    /// HTTP probe timeout
    #[serde(default = "default_probe_timeout")]
    pub http_probe_timeout_secs: u64,
}

fn default_max_age() -> u64 {
    900
}
fn default_probe_path() -> String {
    "/health".to_string()
}
fn default_probe_timeout() -> u64 {
    5
}

/// Coordination layer settings
#[derive(Debug, Clone, Deserialize)]
pub struct CoordinationConfig {
    /// Coordination mode: "wireguard" or "tor"
    #[serde(default = "default_coord_mode")]
    pub mode: String,
    /// Heartbeat interval
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    /// Heartbeat timeout before marking dead
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout_secs: u64,
    /// Lease duration
    #[serde(default = "default_lease_duration")]
    pub lease_duration_secs: u64,
    /// Backoff jitter
    #[serde(default = "default_backoff_jitter")]
    pub backoff_jitter_secs: u64,
    /// Cluster join token (shared secret for peer authentication)
    /// Generated on first node, shared to joining nodes
    pub cluster_token: Option<String>,
    /// Secret join path - unguessable endpoint for Tor bootstrap
    /// Format: /.rb/<join_secret> - 256-bit entropy
    /// Generated on first node, shared to joining nodes
    pub join_secret: Option<String>,
}

fn default_coord_mode() -> String {
    "wireguard".to_string()
}
fn default_heartbeat_interval() -> u64 {
    10
}
fn default_heartbeat_timeout() -> u64 {
    30
}
fn default_lease_duration() -> u64 {
    60
}
fn default_backoff_jitter() -> u64 {
    15
}

/// WireGuard tunnel configuration
#[derive(Debug, Clone, Deserialize)]
pub struct WireguardConfig {
    /// WireGuard interface name
    #[serde(default = "default_wg_interface")]
    pub interface: String,
    /// Listen port for WireGuard (external, e.g., 51820)
    pub listen_port: u16,
    /// This node's tunnel IP (e.g., "10.200.200.1")
    pub tunnel_ip: Option<String>,
    /// Private key (base64)
    pub private_key: String,
    /// Public key (base64) - derived from private key, used for PeerAnnounce
    pub public_key: Option<String>,
    /// Our external endpoint (public IP:port) for other nodes to connect
    /// If not set, nodes will use the sender's IP from packets
    pub external_endpoint: Option<String>,
    /// Peer nodes
    #[serde(default)]
    pub peers: Vec<WireguardPeer>,
}

fn default_wg_interface() -> String {
    "wg-rb".to_string()
}

/// WireGuard peer definition
#[derive(Debug, Clone, Deserialize)]
pub struct WireguardPeer {
    /// Peer node ID
    pub id: String,
    /// Peer's external endpoint (public IP:port, e.g., "192.168.40.143:51820")
    pub endpoint: String,
    /// Peer's tunnel IP (e.g., "10.200.200.2")
    pub tunnel_ip: String,
    /// Peer public key (base64)
    pub public_key: String,
}

/// Target service configuration - the service we reverse proxy to
#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    /// Target .onion address (the real service)
    pub onion_address: String,
    /// Target port (usually 80 for HTTP, 443 for HTTPS)
    #[serde(default = "default_target_port")]
    pub port: u16,
    /// Use TLS/HTTPS when connecting to target (default: false)
    /// Set to true for targets that require HTTPS (e.g., DuckDuckGo)
    #[serde(default)]
    pub use_tls: bool,
}

fn default_target_port() -> u16 {
    80
}

fn default_local_port() -> u16 {
    8080
}

fn default_hs_dir() -> String {
    "/var/lib/rustbalance/hidden_service".to_string()
}
