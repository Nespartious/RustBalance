//! Onion Service management
//!
//! Creates and manages a file-based hidden service for PoW support.
//! Handles reverse proxying connections to the target service.
//! Includes join endpoint handler for Tor Bootstrap Channel.

use crate::balance::join_handler::JoinHandler;
use crate::config::{Config, TorConfig};
use crate::coord::{Coordinator, PeerTracker};
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Manages the hidden service lifecycle
pub struct OnionService {
    /// Local port we listen on for HS connections
    local_port: u16,
    /// Target onion address to proxy to
    target_address: String,
    /// Target port
    target_port: u16,
    /// Tor SOCKS port for outbound connections
    socks_port: u16,
    /// Join secret for the Tor Bootstrap Channel (if enabled)
    join_secret: Option<String>,
    /// Cluster token for validating join requests
    cluster_token: Option<String>,
    /// Shared peer tracker for join handling
    peers: Option<Arc<RwLock<PeerTracker>>>,
    /// This node's info for join responses
    node_info: Option<NodeInfo>,
    /// Coordinator for adding peers (needed by join handler)
    coordinator: Option<Arc<RwLock<Coordinator>>>,
}

/// This node's info for join responses
#[derive(Clone)]
pub struct NodeInfo {
    pub node_id: String,
    pub wg_pubkey: String,
    pub wg_endpoint: String,
    pub tunnel_ip: String,
}

impl OnionService {
    /// Create a new onion service manager
    pub fn new(config: &Config) -> Self {
        Self {
            local_port: config.local_port,
            target_address: config.target.onion_address.clone(),
            target_port: config.target.port,
            socks_port: config.tor.socks_port,
            join_secret: config.coordination.join_secret.clone(),
            cluster_token: config.coordination.cluster_token.clone(),
            peers: None,
            node_info: None,
            coordinator: None,
        }
    }

    /// Enable join endpoint handling
    pub fn enable_join_handler(
        &mut self,
        peers: Arc<RwLock<PeerTracker>>,
        node_info: NodeInfo,
        coordinator: Arc<RwLock<Coordinator>>,
    ) {
        self.peers = Some(peers);
        self.node_info = Some(node_info);
        self.coordinator = Some(coordinator);
    }

    /// Configure Tor to create hidden service pointing to our local port
    ///
    /// This uses SETCONF to add HiddenServiceDir and HiddenServicePort
    pub async fn configure_tor_hs(&self, hs_dir: &str, virtual_port: u16) -> Result<()> {
        // Connect to control port
        let mut stream = TcpStream::connect("127.0.0.1:9051")
            .await
            .context("Failed to connect to Tor control port")?;

        // Authenticate
        let cookie = self.read_cookie().await?;
        let auth_cmd = format!("AUTHENTICATE {}\r\n", cookie);
        stream.write_all(auth_cmd.as_bytes()).await?;

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);
        if !response.starts_with("250") {
            bail!("Auth failed: {}", response.trim());
        }

        // Configure hidden service via SETCONF
        // This tells Tor to create a hidden service from the directory
        let setconf_cmd = format!(
            "SETCONF HiddenServiceDir=\"{}\" HiddenServicePort=\"{} 127.0.0.1:{}\"\r\n",
            hs_dir, virtual_port, self.local_port
        );
        info!(
            "Configuring Tor hidden service: {} -> 127.0.0.1:{}",
            virtual_port, self.local_port
        );

        stream.write_all(setconf_cmd.as_bytes()).await?;

        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);
        if !response.starts_with("250") {
            bail!("SETCONF failed: {}", response.trim());
        }

        info!("Tor hidden service configured successfully");
        Ok(())
    }

    /// Read the Tor control cookie
    async fn read_cookie(&self) -> Result<String> {
        let cookie_paths = [
            "/run/tor/control.authcookie",
            "/var/run/tor/control.authcookie",
            "/var/lib/tor/control_auth_cookie",
        ];

        for path in cookie_paths {
            if let Ok(bytes) = tokio::fs::read(path).await {
                return Ok(data_encoding::HEXLOWER.encode(&bytes));
            }
        }

        bail!("Could not find Tor control cookie");
    }

    /// Start listening for connections and proxy them to target
    pub async fn run_proxy(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.local_port))
            .await
            .with_context(|| format!("Failed to bind to port {}", self.local_port))?;

        info!("Reverse proxy listening on 127.0.0.1:{}", self.local_port);
        info!(
            "Proxying to {}:{} via SOCKS",
            self.target_address, self.target_port
        );

        // Build JoinHandler if configured
        let join_handler = self.build_join_handler();
        if join_handler.is_some() {
            info!("Join endpoint enabled at /.rb/<secret>");
        }
        let join_handler = Arc::new(join_handler);

        loop {
            match listener.accept().await {
                Ok((client, addr)) => {
                    debug!("Accepted connection from {}", addr);

                    let target = self.target_address.clone();
                    let target_port = self.target_port;
                    let socks_port = self.socks_port;
                    let handler = Arc::clone(&join_handler);

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection_with_join(
                            client,
                            &target,
                            target_port,
                            socks_port,
                            handler,
                        )
                        .await
                        {
                            warn!("Connection handling error: {}", e);
                        }
                    });
                },
                Err(e) => {
                    error!("Accept error: {}", e);
                },
            }
        }
    }

    /// Build join handler if configured
    fn build_join_handler(&self) -> Option<JoinHandler> {
        let join_secret = self.join_secret.as_ref()?;
        let cluster_token = self.cluster_token.as_ref()?;
        let node_info = self.node_info.as_ref()?;
        let peers = self.peers.as_ref()?;
        let coordinator = self.coordinator.as_ref()?;

        Some(JoinHandler::new(
            join_secret.clone(),
            cluster_token.clone(),
            node_info.node_id.clone(),
            node_info.wg_pubkey.clone(),
            node_info.wg_endpoint.clone(),
            node_info.tunnel_ip.clone(),
            Arc::clone(peers),
            Arc::clone(coordinator),
        ))
    }

    /// Handle a connection, checking for join requests first
    async fn handle_connection_with_join(
        mut client: TcpStream,
        target: &str,
        target_port: u16,
        socks_port: u16,
        join_handler: Arc<Option<JoinHandler>>,
    ) -> Result<()> {
        // Peek at the first line to check if this is a join request
        let mut peek_buf = [0u8; 512];
        let peek_len = client.peek(&mut peek_buf).await.unwrap_or(0);

        if peek_len > 0 {
            let peek_str = String::from_utf8_lossy(&peek_buf[..peek_len]);
            if let Some(first_line) = peek_str.lines().next() {
                // Check if this looks like a join request
                if let Some(path) = JoinHandler::extract_join_path(first_line) {
                    if let Some(ref handler) = *join_handler {
                        if handler.is_valid_join_path(&path) {
                            // This is a valid join request - handle it
                            debug!("Detected join request, handling directly");
                            return handler.handle_join_request(client).await;
                        }
                        // Wrong path - send 404
                        debug!("Invalid join path, sending 404");
                        let response = "HTTP/1.1 404 Not Found\r\n\
                            Content-Type: text/plain\r\n\
                            Content-Length: 9\r\n\
                            Connection: close\r\n\
                            \r\n\
                            Not Found";
                        client.write_all(response.as_bytes()).await?;
                        return Ok(());
                    }
                }
            }
        }

        // Not a join request - proxy normally
        Self::handle_connection(client, target, target_port, socks_port).await
    }

    /// Handle a single proxied connection
    async fn handle_connection(
        client: TcpStream,
        target: &str,
        target_port: u16,
        socks_port: u16,
    ) -> Result<()> {
        // Connect to target via Tor SOCKS5
        let mut socks = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
            .await
            .context("Failed to connect to SOCKS proxy")?;

        // SOCKS5 handshake
        // Send greeting: version 5, 1 auth method (no auth)
        socks.write_all(&[0x05, 0x01, 0x00]).await?;

        let mut response = [0u8; 2];
        socks.read_exact(&mut response).await?;
        if response[0] != 0x05 || response[1] != 0x00 {
            bail!("SOCKS5 auth negotiation failed");
        }

        // Send connect request
        // Version, connect cmd, reserved, address type (domain name)
        let target_trimmed = target.trim_end_matches(".onion");
        let domain = format!("{}.onion", target_trimmed);
        let domain_bytes = domain.as_bytes();

        #[allow(clippy::cast_possible_truncation)] // Domain length always < 256
        let domain_len = domain_bytes.len() as u8;
        let mut request = vec![
            0x05, // version
            0x01, // connect
            0x00, // reserved
            0x03, // domain name
            domain_len,
        ];
        request.extend_from_slice(domain_bytes);
        #[allow(clippy::cast_possible_truncation)] // Port fits in u8
        {
            request.push((target_port >> 8) as u8);
            request.push((target_port & 0xff) as u8);
        }

        socks.write_all(&request).await?;

        // Read response (minimum 10 bytes for IPv4 response)
        let mut resp_buf = [0u8; 10];
        socks.read_exact(&mut resp_buf).await?;

        if resp_buf[0] != 0x05 {
            bail!("Invalid SOCKS5 response version");
        }
        if resp_buf[1] != 0x00 {
            bail!("SOCKS5 connect failed with code: {}", resp_buf[1]);
        }

        debug!("SOCKS5 connection established to {}", domain);

        // Now proxy with Host header rewriting
        Self::proxy_with_host_rewrite(client, socks, &domain, target_port).await
    }

    /// Proxy connection with HTTP Host header rewriting
    ///
    /// Many sites (like Dread) require the correct Host header.
    /// We rewrite it from the master onion to the target onion.
    async fn proxy_with_host_rewrite(
        mut client: TcpStream,
        mut socks: TcpStream,
        target_host: &str,
        target_port: u16,
    ) -> Result<()> {
        // Read the initial request to check if it's HTTP and needs Host rewriting
        let mut buf = vec![0u8; 8192];
        let n = client.read(&mut buf).await?;
        if n == 0 {
            return Ok(()); // Client disconnected
        }

        let request_data = &buf[..n];

        // Check if this looks like an HTTP request
        let is_http = request_data.starts_with(b"GET ")
            || request_data.starts_with(b"POST ")
            || request_data.starts_with(b"HEAD ")
            || request_data.starts_with(b"PUT ")
            || request_data.starts_with(b"DELETE ")
            || request_data.starts_with(b"PATCH ")
            || request_data.starts_with(b"OPTIONS ")
            || request_data.starts_with(b"CONNECT ");

        if is_http {
            // Rewrite Host header to target
            let request_str = String::from_utf8_lossy(request_data);
            let target_with_port = if target_port == 80 {
                target_host.to_string()
            } else {
                format!("{}:{}", target_host, target_port)
            };

            // Replace Host header (case-insensitive)
            let modified = Self::rewrite_host_header(&request_str, &target_with_port);
            debug!("Rewriting Host header to {}", target_with_port);

            // Send modified request to target
            socks.write_all(modified.as_bytes()).await?;
        } else {
            // Not HTTP, just forward raw
            socks.write_all(request_data).await?;
        }

        // Now bidirectionally proxy the rest
        let (mut client_read, mut client_write) = client.split();
        let (mut socks_read, mut socks_write) = socks.split();

        let client_to_socks = tokio::io::copy(&mut client_read, &mut socks_write);
        let socks_to_client = tokio::io::copy(&mut socks_read, &mut client_write);

        tokio::select! {
            result = client_to_socks => {
                if let Err(e) = result {
                    debug!("Client to SOCKS copy error: {}", e);
                }
            }
            result = socks_to_client => {
                if let Err(e) = result {
                    debug!("SOCKS to client copy error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Rewrite the Host header in an HTTP request
    fn rewrite_host_header(request: &str, new_host: &str) -> String {
        let mut result = String::with_capacity(request.len() + new_host.len());
        let mut host_replaced = false;

        for line in request.split("\r\n") {
            if !result.is_empty() {
                result.push_str("\r\n");
            }

            // Check for Host header (case-insensitive)
            if !host_replaced && line.len() > 5 {
                let lower = line.to_lowercase();
                if lower.starts_with("host:") {
                    result.push_str(&format!("Host: {}", new_host));
                    host_replaced = true;
                    continue;
                }
            }

            result.push_str(line);
        }

        result
    }
}

/// Setup the hidden service directory with master key
///
/// Converts the master identity key to Tor's hs_ed25519_secret_key format and sets up the directory.
/// This is needed for file-based HiddenServiceDir with PoW support.
///
/// Tor's format for hs_ed25519_secret_key:
/// - 32-byte header: "== ed25519v1-secret: type0 =="
/// - 64-byte expanded key: clamped_scalar(32) + PRF_secret(32)
///
/// Tor's format for hs_ed25519_public_key:
/// - 32-byte header: "== ed25519v1-public: type0 =="  
/// - 32-byte public key
pub async fn setup_hs_directory(hs_dir: &str, master_key_path: &Path) -> Result<()> {
    use sha2::{Digest, Sha512};

    // Create the directory if it doesn't exist
    tokio::fs::create_dir_all(hs_dir)
        .await
        .with_context(|| format!("Failed to create HS directory: {}", hs_dir))?;

    // Set proper permissions (700) - Unix only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(hs_dir, perms)
            .with_context(|| format!("Failed to set permissions on {}", hs_dir))?;
    }

    let secret_key_path = format!("{}/hs_ed25519_secret_key", hs_dir);
    let pub_key_path = format!("{}/hs_ed25519_public_key", hs_dir);

    // Read the master key
    let key_bytes = tokio::fs::read(master_key_path)
        .await
        .with_context(|| format!("Failed to read master key from {:?}", master_key_path))?;

    // Check if already in Tor format (96 bytes with header)
    if key_bytes.len() == 96 && key_bytes.starts_with(b"== ed25519v1-secret") {
        info!("Master key already in Tor format, copying directly");
        tokio::fs::write(&secret_key_path, &key_bytes).await?;

        // Try to copy public key if it exists
        let master_pub_path = master_key_path.with_file_name("hs_ed25519_public_key");
        if master_pub_path.exists() {
            tokio::fs::copy(&master_pub_path, &pub_key_path).await?;
        }
    } else if key_bytes.len() == 32 {
        // It's a 32-byte seed - need to expand it to Tor's format
        info!("Converting 32-byte seed to Tor format");

        // Expand seed to get private scalar and PRF secret
        let mut hasher = Sha512::new();
        hasher.update(&key_bytes);
        let expanded = hasher.finalize();

        // Apply Ed25519 clamping to first 32 bytes (private scalar)
        let mut clamped_scalar = [0u8; 32];
        clamped_scalar.copy_from_slice(&expanded[..32]);
        clamped_scalar[0] &= 248;
        clamped_scalar[31] &= 63;
        clamped_scalar[31] |= 64;

        // PRF secret is bytes 32-64
        let mut prf_secret = [0u8; 32];
        prf_secret.copy_from_slice(&expanded[32..64]);

        // Derive public key from private scalar using curve25519
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&key_bytes.try_into().unwrap());
        let public_key = signing_key.verifying_key().to_bytes();

        // Build Tor secret key format
        let mut tor_secret = Vec::with_capacity(96);
        tor_secret.extend_from_slice(b"== ed25519v1-secret: type0 ==\x00\x00\x00");
        tor_secret.extend_from_slice(&clamped_scalar);
        tor_secret.extend_from_slice(&prf_secret);

        // Build Tor public key format
        let mut tor_public = Vec::with_capacity(64);
        tor_public.extend_from_slice(b"== ed25519v1-public: type0 ==\x00\x00\x00");
        tor_public.extend_from_slice(&public_key);

        // Write the keys
        tokio::fs::write(&secret_key_path, &tor_secret)
            .await
            .with_context(|| format!("Failed to write secret key to {}", secret_key_path))?;
        tokio::fs::write(&pub_key_path, &tor_public)
            .await
            .with_context(|| format!("Failed to write public key to {}", pub_key_path))?;

        info!("Generated Tor format keys from seed");
    } else {
        bail!(
            "Unsupported key format: {} bytes. Expected 32 (seed) or 96 (Tor format)",
            key_bytes.len()
        );
    }

    // Set key file permissions (600) - Unix only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key_perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&secret_key_path, key_perms.clone())?;
        if Path::new(&pub_key_path).exists() {
            std::fs::set_permissions(&pub_key_path, key_perms)?;
        }
    }

    // Fix ownership so Tor (debian-tor) can access
    #[cfg(unix)]
    {
        fix_hs_directory_ownership(hs_dir).await?;
    }

    info!("Hidden service directory setup complete at {}", hs_dir);
    Ok(())
}

/// Fix ownership of HS directory to debian-tor user
/// Required because Tor runs as debian-tor but we create files as root
#[cfg(unix)]
async fn fix_hs_directory_ownership(hs_dir: &str) -> Result<()> {
    use std::process::Command;

    // Get debian-tor user/group - try common service users
    let users_to_try = ["debian-tor", "tor", "_tor"];

    for user in users_to_try {
        // Check if user exists
        let check = Command::new("id").arg("-u").arg(user).output();

        if let Ok(output) = check {
            if output.status.success() {
                // User exists, chown the directory
                info!("Setting ownership of {} to {}", hs_dir, user);
                let chown = Command::new("chown")
                    .args(["-R", &format!("{}:{}", user, user), hs_dir])
                    .output()
                    .context("Failed to run chown")?;

                if !chown.status.success() {
                    warn!("chown failed: {}", String::from_utf8_lossy(&chown.stderr));
                    // Continue anyway - might work if we're running as the correct user
                } else {
                    info!("Fixed ownership to {}", user);
                }
                return Ok(());
            }
        }
    }

    warn!("Could not find Tor user (debian-tor/tor/_tor) - ownership not changed");
    warn!(
        "If Tor fails to start, manually run: sudo chown -R debian-tor:debian-tor {}",
        hs_dir
    );
    Ok(())
}

/// Read the hostname file from HS directory
pub async fn read_hs_hostname(hs_dir: &str) -> Result<String> {
    let hostname_path = format!("{}/hostname", hs_dir);
    let hostname = tokio::fs::read_to_string(&hostname_path)
        .await
        .with_context(|| format!("Failed to read hostname from {}", hostname_path))?;
    Ok(hostname.trim().to_string())
}
