//! Debug and diagnostic commands

use super::{DebugAction, DebugArgs, DebugConnectArgs, DebugFetchArgs, DebugShowOnionArgs};
use crate::balance::DescriptorFetcher;
use crate::config::TorConfig;
use crate::crypto::keys::MasterIdentity;
use crate::crypto::pubkey_from_onion_address;
use crate::tor::TorController;
use anyhow::Result;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, info};

/// Run debug commands
pub async fn run_debug(config_dir: &Path, args: &DebugArgs) -> Result<()> {
    match &args.action {
        DebugAction::Fetch(fetch_args) => run_fetch(fetch_args).await,
        DebugAction::Tor => run_tor_test().await,
        DebugAction::Connect(connect_args) => run_connect(connect_args).await,
        DebugAction::ShowOnion(show_args) => run_show_onion(config_dir, show_args).await,
    }
}

/// Fetch and display a descriptor from an onion address
async fn run_fetch(args: &DebugFetchArgs) -> Result<()> {
    info!("=== RustBalance Debug Fetch ===");
    info!("Target address: {}", args.address);

    // Step 1: Parse the onion address and extract public key
    info!("\n[Step 1] Parsing onion address...");
    match pubkey_from_onion_address(&args.address) {
        Ok(pubkey) => {
            info!("  ✓ Valid v3 onion address");
            debug!("  Public key: {:?}", pubkey.as_bytes());
        },
        Err(e) => {
            error!("  ✗ Invalid onion address: {}", e);
            return Err(e);
        },
    }

    // Step 2: Connect to Tor
    info!(
        "\n[Step 2] Connecting to Tor control port {}...",
        args.tor_port
    );
    let tor_config = TorConfig {
        control_host: "127.0.0.1".to_string(),
        control_port: args.tor_port,
        control_password: None,
        socks_port: 9050,
    };

    let mut tor = match TorController::connect(&tor_config).await {
        Ok(t) => {
            info!("  ✓ Connected to Tor");
            t
        },
        Err(e) => {
            error!("  ✗ Failed to connect: {}", e);
            return Err(e);
        },
    };

    // Step 3: Trigger descriptor fetch
    info!("\n[Step 3] Requesting descriptor via HSFETCH...");
    let addr_stripped = args
        .address
        .trim()
        .to_lowercase()
        .trim_end_matches(".onion")
        .to_string();

    match tor.get_hs_descriptor(&addr_stripped).await {
        Ok(_) => info!("  ✓ HSFETCH command sent"),
        Err(e) => {
            error!("  ✗ HSFETCH failed: {}", e);
            return Err(e);
        },
    }

    // Step 4: Wait for and retrieve descriptor
    info!("\n[Step 4] Waiting for descriptor (up to 30 seconds)...");
    let mut fetcher = DescriptorFetcher::new(tor_config.clone(), 300);

    match fetcher.fetch_one(&args.address).await {
        Ok(desc) => {
            info!("  ✓ Descriptor received!");
            info!("\n=== Descriptor Details ===");
            info!("  Version: {}", desc.version);
            info!("  Lifetime: {} minutes", desc.lifetime);
            info!("  Revision: {}", desc.revision_counter);
            info!("  Encrypted body: {} bytes", desc.encrypted_body.len());
            info!("  Introduction points: {}", desc.introduction_points.len());

            if desc.introduction_points.is_empty() {
                info!("\n⚠ No introduction points found.");
                info!("  This could mean:");
                info!("  - Descriptor decryption failed");
                info!("  - The service has no active intro points");
                info!("  - Key derivation is incorrect");
            } else {
                info!("\n=== Introduction Points ===");
                for (i, ip) in desc.introduction_points.iter().enumerate() {
                    info!("  [{}] Onion key: {:?}...", i + 1, &ip.onion_key[..8]);
                    if let Some(id) = ip.relay_identity() {
                        info!("      Relay ID: {:?}...", &id[..8]);
                    }
                }
            }

            info!("\n=== Success ===");
        },
        Err(e) => {
            error!("  ✗ Failed to fetch descriptor: {}", e);
            return Err(e);
        },
    }

    Ok(())
}

/// Test Tor control port connection
async fn run_tor_test() -> Result<()> {
    info!("=== RustBalance Tor Connection Test ===");

    // Try common ports
    for port in [9051, 9151] {
        info!("\n[Testing port {}]", port);
        let tor_config = TorConfig {
            control_host: "127.0.0.1".to_string(),
            control_port: port,
            control_password: None,
            socks_port: 9050,
        };

        match TorController::connect(&tor_config).await {
            Ok(mut tor) => {
                info!("  ✓ Connected to port {}", port);

                // Try to get version
                match tor.get_info("version").await {
                    Ok(version) => info!("  ✓ Tor version: {}", version.trim()),
                    Err(e) => info!("  ? Could not get version: {}", e),
                }

                // Check if we're bootstrapped
                match tor.get_info("status/bootstrap-phase").await {
                    Ok(status) => info!("  ✓ Bootstrap status: {}", status.trim()),
                    Err(e) => info!("  ? Could not get bootstrap status: {}", e),
                }
            },
            Err(e) => {
                info!("  ✗ Could not connect: {}", e);
            },
        }
    }

    Ok(())
}

/// Test SOCKS5 connectivity to an onion address
async fn run_connect(args: &DebugConnectArgs) -> Result<()> {
    info!("=== RustBalance SOCKS5 Connect Test ===");
    info!("Target: {}:{}", args.address, args.port);
    info!("SOCKS5 proxy: 127.0.0.1:{}", args.socks_port);

    // Normalize the address
    let address = args
        .address
        .trim()
        .to_lowercase()
        .trim_end_matches(".onion")
        .to_string()
        + ".onion";

    // Connect to SOCKS5 proxy
    info!("\n[Step 1] Connecting to Tor SOCKS5 proxy...");
    let socks_addr = format!("127.0.0.1:{}", args.socks_port);

    let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&socks_addr)).await {
        Ok(Ok(s)) => {
            info!("  ✓ Connected to SOCKS5 proxy");
            s
        },
        Ok(Err(e)) => {
            error!("  ✗ Failed to connect to SOCKS5 proxy: {}", e);
            return Err(e.into());
        },
        Err(_) => {
            error!("  ✗ Timeout connecting to SOCKS5 proxy");
            anyhow::bail!("Timeout connecting to SOCKS5 proxy");
        },
    };

    // SOCKS5 handshake
    info!("\n[Step 2] SOCKS5 handshake...");
    let mut stream = stream;

    // Send greeting: version 5, 1 method (no auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    // Read response
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    if response[0] != 0x05 || response[1] != 0x00 {
        error!("  ✗ SOCKS5 handshake failed: {:?}", response);
        anyhow::bail!("SOCKS5 handshake failed");
    }
    info!("  ✓ SOCKS5 handshake successful");

    // Send connect request for onion address
    info!("\n[Step 3] Connecting to {}:{}...", address, args.port);
    info!("  (This may take 30-60 seconds for onion services)");

    // SOCKS5 connect request:
    // Version (1) | Command (1) | Reserved (1) | Address type (1) | Address | Port (2)
    // For domain names: type=0x03, followed by length byte, then hostname
    #[allow(clippy::cast_possible_truncation)] // Address length always < 256
    let addr_len = address.len() as u8;
    let mut request = vec![0x05, 0x01, 0x00, 0x03, addr_len];
    request.extend_from_slice(address.as_bytes());
    #[allow(clippy::cast_possible_truncation)] // Port fits in u8
    {
        request.push((args.port >> 8) as u8);
        request.push((args.port & 0xff) as u8);
    }

    stream.write_all(&request).await?;

    // Wait for response (with timeout for onion services)
    let mut reply = [0u8; 10];
    match timeout(Duration::from_secs(120), stream.read_exact(&mut reply)).await {
        Ok(Ok(_)) => {
            if reply[0] != 0x05 {
                error!("  ✗ Invalid SOCKS5 response");
                anyhow::bail!("Invalid SOCKS5 response");
            }

            match reply[1] {
                0x00 => {
                    info!("  ✓ Successfully connected to {}:{}", address, args.port);
                    info!("\n=== Onion Service is REACHABLE ===");
                },
                0x01 => {
                    error!("  ✗ General SOCKS server failure");
                    anyhow::bail!("SOCKS server failure");
                },
                0x02 => {
                    error!("  ✗ Connection not allowed by ruleset");
                    anyhow::bail!("Connection not allowed");
                },
                0x03 => {
                    error!("  ✗ Network unreachable");
                    anyhow::bail!("Network unreachable");
                },
                0x04 => {
                    error!("  ✗ Host unreachable (onion service may be offline)");
                    anyhow::bail!("Host unreachable");
                },
                0x05 => {
                    error!("  ✗ Connection refused");
                    anyhow::bail!("Connection refused");
                },
                0x06 => {
                    error!("  ✗ TTL expired");
                    anyhow::bail!("TTL expired");
                },
                code => {
                    error!("  ✗ SOCKS error code: {}", code);
                    anyhow::bail!("SOCKS error: {}", code);
                },
            }
        },
        Ok(Err(e)) => {
            error!("  ✗ Connection failed: {}", e);
            return Err(e.into());
        },
        Err(_) => {
            error!("  ✗ Timeout waiting for onion service (120s)");
            anyhow::bail!("Timeout waiting for onion service");
        },
    }

    Ok(())
}

/// Show onion address derived from master key
async fn run_show_onion(config_dir: &Path, args: &DebugShowOnionArgs) -> Result<()> {
    // Determine key path
    let key_path = if let Some(p) = &args.key {
        p.clone()
    } else {
        config_dir.join("master.key")
    };

    if !key_path.exists() {
        anyhow::bail!(
            "Master key not found at {:?}. Use --key to specify path.",
            key_path
        );
    }

    // Read key file
    let key_bytes = std::fs::read(&key_path)?;

    // Extract 32-byte seed
    let seed: [u8; 32] = if key_bytes.len() == 32 {
        // Raw 32-byte seed
        key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?
    } else if key_bytes.len() == 96 && key_bytes.starts_with(b"== ed25519v1-secret") {
        // Tor format - need to derive seed (we can't reverse the expansion, so this is tricky)
        // For Tor format, read the public key file instead
        let pub_path = key_path.with_file_name("hs_ed25519_public_key");
        if pub_path.exists() {
            let pub_bytes = std::fs::read(&pub_path)?;
            if pub_bytes.len() == 64 && pub_bytes.starts_with(b"== ed25519v1-public") {
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&pub_bytes[32..64]);
                // Compute onion from public key directly
                let onion = onion_address_from_pubkey(&pubkey);
                println!("{}", onion);
                return Ok(());
            }
        }
        anyhow::bail!("Cannot derive onion from Tor format key without public key file");
    } else {
        anyhow::bail!("Unsupported key format: {} bytes", key_bytes.len());
    };

    // Derive onion address
    let identity = MasterIdentity::from_seed(&seed);
    let onion = identity.onion_address();

    // Just print the onion address (for script consumption)
    println!("{}", onion);

    Ok(())
}

/// Compute onion address from raw public key bytes
fn onion_address_from_pubkey(pubkey: &[u8; 32]) -> String {
    use sha3::{Digest, Sha3_256};

    // Compute checksum: SHA3-256(".onion checksum" || pubkey || version)
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]); // version 3
    let checksum = hasher.finalize();

    // Build address: pubkey || checksum[0..2] || version
    let mut addr_bytes = [0u8; 35];
    addr_bytes[..32].copy_from_slice(pubkey);
    addr_bytes[32..34].copy_from_slice(&checksum[..2]);
    addr_bytes[34] = 0x03;

    // Base32 encode
    let encoded = data_encoding::BASE32_NOPAD
        .encode(&addr_bytes)
        .to_lowercase();
    format!("{}.onion", encoded)
}
