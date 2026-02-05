//! Command-line interface for RustBalance
//!
//! Provides main commands:
//! - `init` - Initialize a new cluster (first node)
//! - `join` - Join an existing cluster with a token
//! - `status` - Show cluster status
//! - `backend` - Manage backend onion services
//! - `debug` - Debug and diagnostic commands
//!
//! After init/join, the daemon runs automatically.

mod backend;
mod debug;
mod init;
mod join;
mod status;
mod token;

pub use backend::run_backend;
pub use debug::run_debug;
pub use init::run_init;
pub use join::run_join;
pub use status::run_status;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// RustBalance - Self-healing Onion Service load balancer
#[derive(Parser, Debug)]
#[command(name = "rustbalance")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Path to configuration directory
    #[arg(short, long, default_value = "/etc/rustbalance")]
    pub config_dir: PathBuf,

    /// Verbose output
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new RustBalance cluster (run on first node)
    Init(InitArgs),

    /// Join an existing cluster using a join token
    Join(JoinArgs),

    /// Show cluster and node status
    Status(StatusArgs),

    /// Manage backend onion services
    Backend(BackendArgs),

    /// Run the daemon (typically called by systemd)
    Run(RunArgs),

    /// Debug and diagnostic commands
    Debug(DebugArgs),
}

/// Arguments for init command
#[derive(Parser, Debug)]
pub struct InitArgs {
    /// Public endpoint for WireGuard (IP:port)
    #[arg(long)]
    pub endpoint: String,

    /// WireGuard listen port
    #[arg(long, default_value_t = 51820)]
    pub wg_port: u16,

    /// Path to existing master identity key (optional, generates if not provided)
    #[arg(long)]
    pub identity_key: Option<PathBuf>,

    /// Tor control port
    #[arg(long, default_value_t = 9051)]
    pub tor_port: u16,

    /// Tor control password (optional)
    #[arg(long)]
    pub tor_password: Option<String>,

    /// Node priority for publisher election (lower = higher priority)
    #[arg(long, default_value_t = 10)]
    pub priority: u32,

    /// Token password (for non-interactive mode)
    #[arg(long)]
    pub token_password: Option<String>,
}

/// Arguments for join command
#[derive(Parser, Debug)]
pub struct JoinArgs {
    /// Join token from another node
    #[arg(long)]
    pub token: String,

    /// Public endpoint for WireGuard (IP:port)
    #[arg(long)]
    pub endpoint: String,

    /// WireGuard listen port
    #[arg(long, default_value_t = 51820)]
    pub wg_port: u16,

    /// Tor control port
    #[arg(long, default_value_t = 9051)]
    pub tor_port: u16,

    /// Tor control password (optional)
    #[arg(long)]
    pub tor_password: Option<String>,

    /// Node priority for publisher election (lower = higher priority)
    #[arg(long, default_value_t = 20)]
    pub priority: u32,

    /// Token password (for non-interactive mode)
    #[arg(long)]
    pub token_password: Option<String>,
}

/// Arguments for status command
#[derive(Parser, Debug)]
pub struct StatusArgs {
    /// Output format
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Show detailed information
    #[arg(short, long, default_value_t = false)]
    pub detailed: bool,
}

/// Arguments for backend command
#[derive(Parser, Debug)]
pub struct BackendArgs {
    #[command(subcommand)]
    pub action: BackendAction,
}

/// Backend subcommands
#[derive(Subcommand, Debug)]
pub enum BackendAction {
    /// Add a backend onion service
    Add(BackendAddArgs),

    /// Remove a backend onion service
    Remove(BackendRemoveArgs),

    /// List all backends
    List,
}

/// Arguments for adding a backend
#[derive(Parser, Debug)]
pub struct BackendAddArgs {
    /// Backend onion address (56 chars + .onion)
    #[arg(long)]
    pub address: String,

    /// Weight for load balancing (higher = more traffic)
    #[arg(long, default_value_t = 100)]
    pub weight: u32,

    /// Optional friendly name
    #[arg(long)]
    pub name: Option<String>,
}

/// Arguments for removing a backend
#[derive(Parser, Debug)]
pub struct BackendRemoveArgs {
    /// Backend onion address or name
    #[arg(long)]
    pub address: String,
}

/// Arguments for run command (daemon mode)
#[derive(Parser, Debug)]
pub struct RunArgs {
    /// Path to config file (overrides config_dir)
    #[arg(long)]
    pub config: Option<PathBuf>,
}

/// Arguments for debug command
#[derive(Parser, Debug)]
pub struct DebugArgs {
    #[command(subcommand)]
    pub action: DebugAction,
}

/// Debug subcommands
#[derive(Subcommand, Debug)]
pub enum DebugAction {
    /// Fetch and parse a descriptor from an onion address
    Fetch(DebugFetchArgs),

    /// Test Tor control port connection
    Tor,

    /// Test SOCKS5 connectivity to an onion address
    Connect(DebugConnectArgs),

    /// Show onion address derived from master key
    ShowOnion(DebugShowOnionArgs),
}

/// Arguments for debug fetch
#[derive(Parser, Debug)]
pub struct DebugFetchArgs {
    /// Onion address to fetch descriptor for
    #[arg(long)]
    pub address: String,

    /// Tor control port
    #[arg(long, default_value_t = 9051)]
    pub tor_port: u16,
}

/// Arguments for debug connect
#[derive(Parser, Debug)]
pub struct DebugConnectArgs {
    /// Onion address to connect to (without port)
    #[arg(long)]
    pub address: String,

    /// Port to connect to on the onion service
    #[arg(long, default_value_t = 80)]
    pub port: u16,

    /// Tor SOCKS5 port
    #[arg(long, default_value_t = 9050)]
    pub socks_port: u16,
}

/// Arguments for debug show-onion
#[derive(Parser, Debug)]
pub struct DebugShowOnionArgs {
    /// Path to master key file (32-byte seed or 96-byte Tor format)
    #[arg(long)]
    pub key: Option<std::path::PathBuf>,
}

/// Parse command line arguments
pub fn parse() -> Cli {
    Cli::parse()
}
