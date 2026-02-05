//! RustBalance - Onionbalance reimplementation with self-healing capabilities
//!
//! A Rust implementation of Onion Service load balancing with:
//! - Lease-based publisher election
//! - Active health monitoring
//! - Self-repair via WireGuard coordination
//!
//! # Architecture
//!
//! RustBalance operates as a directory authority manager, not a traffic proxy.
//! It aggregates backend descriptors and publishes a unified "superdescriptor"
//! signed with the master identity key.
//!
//! # Security Model
//!
//! - Master key isolated on management nodes
//! - No inbound connections required
//! - Coordination via authenticated WireGuard tunnel
//! - No JavaScript, XML, or browser-executable content

// Allow common stylistic patterns during development.
// These can be tightened as the codebase matures.
#![allow(dead_code)]
#![allow(clippy::unused_async)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::unused_self)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::manual_abs_diff)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::format_push_string)]
#![allow(clippy::collection_is_never_read)]
#![allow(clippy::use_self)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::useless_format)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::needless_continue)]
#![allow(clippy::single_match_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::unnecessary_debug_formatting)]
#![allow(clippy::new_without_default)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::range_plus_one)]
#![allow(clippy::inefficient_to_string)]
#![allow(clippy::case_sensitive_file_extension_comparisons)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::ref_option)]

//! # Usage
//!
//! ```bash
//! # Initialize first node
//! rustbalance init --endpoint 1.2.3.4:51820
//!
//! # Join from another node
//! rustbalance join --token <TOKEN> --endpoint 5.6.7.8:51820
//!
//! # Check status
//! rustbalance status
//!
//! # Run daemon
//! rustbalance run
//! ```

use anyhow::Result;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod balance;
mod cli;
mod config;
mod coord;
mod crypto;
mod logging;
mod repair;
mod scheduler;
mod state;
mod tor;
mod util;

use clap::Parser;
use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match &cli.command {
        Commands::Init(args) => {
            cli::run_init(&cli.config_dir, args).await?;
        },
        Commands::Join(args) => {
            cli::run_join(&cli.config_dir, args).await?;
        },
        Commands::Status(args) => {
            cli::run_status(&cli.config_dir, args).await?;
        },
        Commands::Backend(args) => {
            cli::run_backend(&cli.config_dir, args).await?;
        },
        Commands::Run(args) => {
            run_daemon(&cli, args).await?;
        },
        Commands::Debug(args) => {
            cli::run_debug(&cli.config_dir, args).await?;
        },
    }

    Ok(())
}

/// Run the RustBalance daemon
async fn run_daemon(cli: &Cli, args: &cli::RunArgs) -> Result<()> {
    info!("RustBalance v{} starting", env!("CARGO_PKG_VERSION"));

    // Determine config path
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| cli.config_dir.join("config.toml"));

    // Load configuration
    let config = config::file::load_from_path(config_path.to_str().unwrap())?;

    // Initialize runtime state
    let state = state::RuntimeState::new(&config);

    // Connect to Tor control port
    let tor_client = tor::control::TorController::connect(&config.tor).await?;

    // Initialize coordination layer
    let coordinator = coord::Coordinator::new(&config.coordination, &config.wireguard).await?;

    // Start the main scheduler loops
    scheduler::run(config, state, tor_client, coordinator).await?;

    Ok(())
}
