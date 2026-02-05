//! Status command - show cluster and node status
//!
//! Displays:
//! - Node information
//! - Cluster membership
//! - Health check results
//! - Publisher election status

use super::StatusArgs;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Run the status command
pub async fn run_status(config_dir: &Path, args: &StatusArgs) -> Result<()> {
    let config_path = config_dir.join("config.toml");

    if !config_path.exists() {
        println!("❌ No RustBalance configuration found at {:?}", config_dir);
        println!("   Run 'rustbalance init' or 'rustbalance join' first.");
        return Ok(());
    }

    // Load configuration
    let config_content = fs::read_to_string(&config_path).context("Failed to read config file")?;

    let config: toml::Value =
        toml::from_str(&config_content).context("Failed to parse config file")?;

    // Extract basic info
    let node_id = config
        .get("node")
        .and_then(|n| n.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let priority = config
        .get("node")
        .and_then(|n| n.get("priority"))
        .and_then(|v| v.as_integer())
        .unwrap_or(0);

    let onion_address = config
        .get("master")
        .and_then(|m| m.get("onion_address"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let wg_port = config
        .get("wireguard")
        .and_then(|w| w.get("listen_port"))
        .and_then(|v| v.as_integer())
        .unwrap_or(51820);

    let wg_pubkey = config
        .get("wireguard")
        .and_then(|w| w.get("public_key"))
        .and_then(|v| v.as_str())
        .unwrap_or("not configured");

    // Count peers
    let peer_count = config
        .get("wireguard")
        .and_then(|w| w.get("peers"))
        .and_then(|p| p.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    // Count backends
    let backend_count = config
        .get("backends")
        .and_then(|b| b.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    if args.format == "json" {
        print_json_status(
            node_id,
            priority,
            onion_address,
            wg_port,
            wg_pubkey,
            peer_count,
            backend_count,
        )?;
    } else {
        print_text_status(
            node_id,
            priority,
            onion_address,
            wg_port,
            wg_pubkey,
            peer_count,
            backend_count,
            args.detailed,
            &config,
        );
    }

    Ok(())
}

fn print_text_status(
    node_id: &str,
    priority: i64,
    onion_address: &str,
    wg_port: i64,
    wg_pubkey: &str,
    peer_count: usize,
    backend_count: usize,
    detailed: bool,
    config: &toml::Value,
) {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║              RustBalance Status                            ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    println!("📋 Node Information:");
    println!("   ID:       {}", node_id);
    println!("   Priority: {} (lower = higher priority)", priority);
    println!();

    println!("🧅 Master Onion:");
    println!("   {}", onion_address);
    println!();

    println!("🔐 WireGuard:");
    println!("   Port:       {}", wg_port);
    println!("   Public Key: {}", wg_pubkey);
    println!("   Peers:      {}", peer_count);
    println!();

    println!("⚖️  Load Balancing:");
    println!("   Backends: {}", backend_count);
    println!();

    // TODO: Add runtime status when daemon is running
    println!("📡 Daemon Status:");
    println!("   Status: Not connected (run 'rustbalance run' to start)");
    println!();

    if detailed {
        println!("📝 Detailed Configuration:");
        println!("{}", "-".repeat(60));

        if let Some(peers) = config
            .get("wireguard")
            .and_then(|w| w.get("peers"))
            .and_then(|p| p.as_array())
        {
            println!("\n🔗 WireGuard Peers:");
            for (i, peer) in peers.iter().enumerate() {
                let id = peer.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
                let endpoint = peer
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let pubkey = peer
                    .get("public_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                println!("   {}. {} ({})", i + 1, id, endpoint);
                println!("      Key: {}", pubkey);
            }
        }

        if let Some(backends) = config.get("backends").and_then(|b| b.as_array()) {
            println!("\n🖥️  Backends:");
            for (i, backend) in backends.iter().enumerate() {
                let addr = backend
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let weight = backend
                    .get("weight")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(100);
                println!("   {}. {} (weight: {})", i + 1, addr, weight);
            }
        }
    }
}

fn print_json_status(
    node_id: &str,
    priority: i64,
    onion_address: &str,
    wg_port: i64,
    wg_pubkey: &str,
    peer_count: usize,
    backend_count: usize,
) -> Result<()> {
    let status = serde_json::json!({
        "node": {
            "id": node_id,
            "priority": priority,
        },
        "master": {
            "onion_address": onion_address,
        },
        "wireguard": {
            "port": wg_port,
            "public_key": wg_pubkey,
            "peer_count": peer_count,
        },
        "backends": {
            "count": backend_count,
        },
        "daemon": {
            "status": "not_connected",
        }
    });

    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}
