//! Join command - join an existing cluster
//!
//! Joins a RustBalance cluster using a join token:
//! 1. Decode and decrypt the join token
//! 2. Extract master identity key
//! 3. Generate WireGuard keypair
//! 4. Configure peer connection to initiator
//! 5. Create local configuration
//! 6. Generate new join token for additional nodes

use super::init::WgKeypair;
use super::token::{cluster_id_from_pubkey, JoinToken, JoinTokenPayload};
use super::JoinArgs;
use crate::crypto::keys::MasterIdentity;
use crate::util::rand::random_bytes;
use anyhow::{Context, Result};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tracing::info;

/// Run the join command
pub async fn run_join(config_dir: &Path, args: &JoinArgs) -> Result<()> {
    println!("🔗 Joining RustBalance cluster...\n");

    // Step 1: Decode the join token
    println!("🎫 Decoding join token...");
    let token = JoinToken::decode(&args.token).context("Invalid join token format")?;

    // Step 2: Get password and decrypt
    let password = if let Some(pw) = &args.token_password {
        pw.clone()
    } else {
        print!("   Enter token password: ");
        io::stdout().flush()?;
        read_password()?
    };

    let payload = token
        .decrypt(&password)
        .context("Failed to decrypt token")?;
    println!("   ✓ Token decrypted successfully");

    // Step 3: Reconstruct master identity
    let identity = MasterIdentity::from_seed(&payload.master_key_seed);
    let onion_address = identity.onion_address();

    if onion_address != payload.master_onion {
        anyhow::bail!("Master key mismatch - token may be corrupted");
    }
    println!("   Master onion: {}", onion_address);

    // Step 4: Create config directory
    fs::create_dir_all(config_dir).context("Failed to create config directory")?;

    // Step 5: Generate our WireGuard keypair
    println!("\n🔐 Generating WireGuard keypair...");
    let wg_keypair = WgKeypair::generate();
    println!("   Public key: {}", wg_keypair.public_key_base64());

    // Step 6: Save master identity key
    let key_path = config_dir.join("master.key");
    fs::write(&key_path, &payload.master_key_seed).context("Failed to write master key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    }
    println!("\n💾 Saved master key to {:?}", key_path);

    // Step 7: Save WireGuard private key
    let wg_key_path = config_dir.join("wireguard.key");
    fs::write(&wg_key_path, wg_keypair.private_key_base64())
        .context("Failed to write WireGuard key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&wg_key_path, fs::Permissions::from_mode(0o600))?;
    }
    println!("💾 Saved WireGuard private key to {:?}", wg_key_path);

    // Step 8: Generate node ID
    let node_id = generate_node_id();

    // Step 9: Create configuration file with initiator as peer
    let config_path = config_dir.join("config.toml");
    let config_content = generate_config(
        &node_id,
        &onion_address,
        &key_path,
        args.priority,
        args.tor_port,
        args.tor_password.as_deref(),
        args.wg_port,
        &wg_keypair,
        &payload,
    );
    fs::write(&config_path, &config_content).context("Failed to write config file")?;
    println!("💾 Saved configuration to {:?}", config_path);

    // Step 10: Generate new join token (so this node can invite others)
    println!("\n🎫 Generating new join token for additional nodes...");
    let cluster_id = cluster_id_from_pubkey(&identity.public_key_bytes());
    let new_payload = JoinTokenPayload {
        version: 1,
        master_key_seed: payload.master_key_seed,
        master_onion: onion_address.clone(),
        initiator_wg_pubkey: wg_keypair.public_key,
        initiator_endpoint: args.endpoint.clone(),
        cluster_id,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Use same password for convenience
    let new_token = JoinToken::create(&new_payload, &password)?;
    let new_token_str = new_token.encode();

    let token_path = config_dir.join("join-token.txt");
    fs::write(&token_path, &new_token_str).context("Failed to write join token")?;
    println!("💾 Saved new join token to {:?}", token_path);

    // Step 11: Display summary
    println!("\n{}", "=".repeat(60));
    println!("✅ Successfully joined RustBalance cluster!\n");
    println!("📍 Master Onion Address:");
    println!("   {}\n", onion_address);
    println!("🔗 Peer Connection:");
    println!("   Initiator endpoint: {}", payload.initiator_endpoint);
    println!(
        "   Initiator WG pubkey: {}",
        base64_encode(&payload.initiator_wg_pubkey)
    );
    println!("\n📋 Next Steps:");
    println!("   1. Configure your Tor daemon");
    println!("   2. Set up WireGuard interface (see below)");
    println!("   3. Start RustBalance: rustbalance run");
    println!("   4. Notify the initiator node of your WireGuard public key\n");

    // WireGuard setup instructions
    println!("🔧 WireGuard Setup:");
    println!("   # Create WireGuard interface");
    println!("   sudo ip link add wg-rustbalance type wireguard");
    println!(
        "   sudo wg set wg-rustbalance listen-port {} private-key {:?}",
        args.wg_port, wg_key_path
    );
    println!("   sudo ip addr add 10.200.200.X/24 dev wg-rustbalance  # Use unique IP");
    println!("   sudo ip link set wg-rustbalance up\n");
    println!("   # Add peer (initiator node)");
    println!(
        "   sudo wg set wg-rustbalance peer {} endpoint {} allowed-ips 10.200.200.1/32",
        base64_encode(&payload.initiator_wg_pubkey),
        payload.initiator_endpoint
    );

    println!("\n🔄 On the initiator node, run:");
    println!(
        "   sudo wg set wg-rustbalance peer {} endpoint {} allowed-ips 10.200.200.X/32\n",
        wg_keypair.public_key_base64(),
        args.endpoint
    );

    info!("Joined cluster: {}", onion_address);

    Ok(())
}

/// Generate a random node ID
fn generate_node_id() -> String {
    let bytes = random_bytes::<4>();
    format!(
        "node-{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

/// Read password from stdin
fn read_password() -> Result<String> {
    #[cfg(unix)]
    {
        rpassword::read_password().context("Failed to read password")
    }
    #[cfg(not(unix))]
    {
        let mut password = String::new();
        io::stdin()
            .read_line(&mut password)
            .context("Failed to read password")?;
        Ok(password.trim().to_string())
    }
}

/// Base64 encode helper
fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

/// Generate configuration file content with peer
fn generate_config(
    node_id: &str,
    onion_address: &str,
    key_path: &Path,
    priority: u32,
    tor_port: u16,
    tor_password: Option<&str>,
    wg_port: u16,
    wg_keypair: &WgKeypair,
    initiator: &JoinTokenPayload,
) -> String {
    let tor_password_line = tor_password
        .map(|p| format!("control_password = \"{}\"", p))
        .unwrap_or_else(|| "# control_password = \"your-password\"".to_string());

    let initiator_pubkey = base64_encode(&initiator.initiator_wg_pubkey);

    format!(
        r#"# RustBalance Configuration
# Generated by rustbalance join

[node]
id = "{node_id}"
priority = {priority}
clock_skew_tolerance_secs = 5

[master]
onion_address = "{onion_address}"
identity_key_path = "{key_path}"

[tor]
control_host = "127.0.0.1"
control_port = {tor_port}
{tor_password_line}
socks_port = 9050

[publish]
refresh_interval_secs = 600
takeover_grace_secs = 90
max_intro_points = 20

[health]
check_interval_secs = 30
timeout_secs = 10
unhealthy_threshold = 3
healthy_threshold = 2

[coordination]
mode = "wireguard"
heartbeat_interval_secs = 5
lease_duration_secs = 60
election_timeout_secs = 15

[wireguard]
listen_port = {wg_port}
private_key = "{wg_private}"
public_key = "{wg_public}"

[[wireguard.peers]]
id = "initiator"
public_key = "{initiator_pubkey}"
endpoint = "{initiator_endpoint}"
allowed_ips = "10.200.200.1/32"

# Backend onion services to load balance
# [[backends]]
# address = "backend1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion"
# weight = 100
"#,
        node_id = node_id,
        priority = priority,
        onion_address = onion_address,
        key_path = key_path.display(),
        tor_port = tor_port,
        tor_password_line = tor_password_line,
        wg_port = wg_port,
        wg_private = wg_keypair.private_key_base64(),
        wg_public = wg_keypair.public_key_base64(),
        initiator_pubkey = initiator_pubkey,
        initiator_endpoint = initiator.initiator_endpoint,
    )
}
