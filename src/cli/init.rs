//! Init command - initialize a new cluster
//!
//! Creates the first node of a RustBalance cluster:
//! 1. Generate or load master identity key
//! 2. Generate WireGuard keypair
//! 3. Create configuration file
//! 4. Generate join token for other nodes
//! 5. Display setup information

use super::token::{cluster_id_from_pubkey, JoinToken, JoinTokenPayload};
use super::InitArgs;
use crate::crypto::keys::MasterIdentity;
use crate::util::rand::random_bytes;
use anyhow::{Context, Result};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tracing::info;

/// WireGuard keypair
pub struct WgKeypair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl WgKeypair {
    /// Generate a new X25519 keypair for WireGuard
    pub fn generate() -> Self {
        use x25519_dalek::{PublicKey, StaticSecret};

        let private_bytes = random_bytes::<32>();
        let secret = StaticSecret::from(private_bytes);
        let public = PublicKey::from(&secret);

        Self {
            private_key: private_bytes,
            public_key: public.to_bytes(),
        }
    }

    /// Encode private key as base64 (WireGuard format)
    pub fn private_key_base64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(self.private_key)
    }

    /// Encode public key as base64 (WireGuard format)
    pub fn public_key_base64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(self.public_key)
    }
}

/// Run the init command
pub async fn run_init(config_dir: &Path, args: &InitArgs) -> Result<()> {
    println!("🔧 Initializing RustBalance cluster...\n");

    // Ensure config directory exists
    fs::create_dir_all(config_dir).context("Failed to create config directory")?;

    // Step 1: Generate or load master identity key
    let (master_seed, identity) = if let Some(key_path) = &args.identity_key {
        println!(
            "📂 Loading existing master identity key from {:?}",
            key_path
        );
        let bytes = fs::read(key_path).context("Failed to read identity key file")?;
        let seed: [u8; 32] = if bytes.len() >= 32 {
            let mut s = [0u8; 32];
            s.copy_from_slice(&bytes[..32]);
            s
        } else {
            anyhow::bail!("Invalid key file - must be at least 32 bytes");
        };
        (seed, MasterIdentity::from_seed(&seed))
    } else {
        println!("🔑 Generating new master identity key...");
        let seed = random_bytes::<32>();
        (seed, MasterIdentity::from_seed(&seed))
    };

    let onion_address = identity.onion_address();
    println!("   Master onion: {}", onion_address);

    // Step 2: Generate WireGuard keypair
    println!("\n🔐 Generating WireGuard keypair...");
    let wg_keypair = WgKeypair::generate();
    println!("   Public key: {}", wg_keypair.public_key_base64());

    // Step 3: Save master identity key
    let key_path = config_dir.join("master.key");
    fs::write(&key_path, &master_seed).context("Failed to write master key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    }
    println!("\n💾 Saved master key to {:?}", key_path);

    // Step 4: Save WireGuard private key
    let wg_key_path = config_dir.join("wireguard.key");
    fs::write(&wg_key_path, wg_keypair.private_key_base64())
        .context("Failed to write WireGuard key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&wg_key_path, fs::Permissions::from_mode(0o600))?;
    }
    println!("💾 Saved WireGuard private key to {:?}", wg_key_path);

    // Step 5: Generate node ID
    let node_id = generate_node_id();

    // Step 6: Create configuration file
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
    );
    fs::write(&config_path, &config_content).context("Failed to write config file")?;
    println!("💾 Saved configuration to {:?}", config_path);

    // Step 7: Generate join token
    println!("\n🎫 Generating join token...");
    let password = if let Some(pw) = &args.token_password {
        pw.clone()
    } else {
        print!("   Enter token password (for encrypting the join token): ");
        io::stdout().flush()?;
        read_password()?
    };

    if password.len() < 8 {
        anyhow::bail!("Password must be at least 8 characters");
    }

    let cluster_id = cluster_id_from_pubkey(&identity.public_key_bytes());
    let payload = JoinTokenPayload {
        version: 1,
        master_key_seed: master_seed,
        master_onion: onion_address.clone(),
        initiator_wg_pubkey: wg_keypair.public_key,
        initiator_endpoint: args.endpoint.clone(),
        cluster_id,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let token = JoinToken::create(&payload, &password)?;
    let token_str = token.encode();

    // Save token to file
    let token_path = config_dir.join("join-token.txt");
    fs::write(&token_path, &token_str).context("Failed to write join token")?;
    println!("💾 Saved join token to {:?}", token_path);

    // Step 8: Display summary
    println!("\n{}", "=".repeat(60));
    println!("✅ RustBalance cluster initialized successfully!\n");
    println!("📍 Master Onion Address:");
    println!("   {}\n", onion_address);
    println!("🔗 Join Token (give this to other nodes):");
    println!("   {}\n", token_str);
    println!("📋 Next Steps:");
    println!("   1. Edit config to set your target service:");
    println!("      sudo nano {:?}", config_path);
    println!("      Change: onion_address = \"YOUR_TARGET_SERVICE.onion\"");
    println!("   2. Create hidden service directory:");
    println!("      sudo mkdir -p /var/lib/tor/rustbalance_hs");
    println!("      sudo chown debian-tor:debian-tor /var/lib/tor/rustbalance_hs");
    println!("      sudo chmod 700 /var/lib/tor/rustbalance_hs");
    println!("   3. Start RustBalance: sudo rustbalance run");
    println!("   4. On other nodes: rustbalance join --token <TOKEN> --endpoint <IP:PORT>\n");

    // WireGuard setup instructions (for multi-node)
    println!("🔧 WireGuard Setup (for multi-node only):");
    println!("   Change [coordination] mode = \"wireguard\" in config, then:");
    println!("   sudo ip link add wg-rb type wireguard");
    println!(
        "   sudo wg set wg-rb listen-port {} private-key {:?}",
        args.wg_port, wg_key_path
    );
    println!("   sudo ip addr add 10.200.200.1/24 dev wg-rb");
    println!("   sudo ip link set wg-rb up\n");

    info!("Cluster initialized: {}", onion_address);

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

/// Read password from stdin (with echo disabled on Unix)
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

/// Generate configuration file content
fn generate_config(
    node_id: &str,
    onion_address: &str,
    key_path: &Path,
    priority: u32,
    tor_port: u16,
    tor_password: Option<&str>,
    wg_port: u16,
    wg_keypair: &WgKeypair,
) -> String {
    let tor_password_line = tor_password
        .map(|p| format!("control_password = \"{}\"", p))
        .unwrap_or_else(|| "# control_password = \"your-password\"".to_string());

    format!(
        r#"# RustBalance Configuration
# Generated by rustbalance init

# Root-level settings
local_port = 8080
# DEPRECATED: Legacy field, kept for backward compatibility
hidden_service_dir = "/var/lib/tor/rustbalance_hs"

[node]
id = "{node_id}"
priority = {priority}
clock_skew_tolerance_secs = 5
# Node-specific hidden service directory
# Each node gets its own unique .onion address here
hidden_service_dir = "/var/lib/tor/rustbalance_node_hs"

[master]
onion_address = "{onion_address}"
identity_key_path = "{key_path}"

# Target service to reverse proxy to
# REQUIRED: Set this to your actual target hidden service
[target]
onion_address = "YOUR_TARGET_SERVICE.onion"
port = 80

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
descriptor_max_age_secs = 900
http_probe_enabled = false
http_probe_path = "/health"
http_probe_timeout_secs = 5

[coordination]
# Use "tor" for single-node, "wireguard" for multi-node
mode = "tor"
heartbeat_interval_secs = 10
heartbeat_timeout_secs = 30
lease_duration_secs = 60
backoff_jitter_secs = 15

[wireguard]
interface = "wg-rb"
listen_port = {wg_port}
tunnel_ip = "10.200.200.1"
private_key = "{wg_private}"
public_key = "{wg_public}"
peers = []
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
    )
}
