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
    /// Master onion address (for response header rewriting)
    master_address: String,
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
            master_address: config.master.onion_address.clone(),
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

        // Connection counter for logging
        let connection_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

        loop {
            match listener.accept().await {
                Ok((client, addr)) => {
                    let count = connection_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    info!("Session #{}: New connection from {} -> proxying to {}", count, addr, self.target_address);

                    let target = self.target_address.clone();
                    let target_port = self.target_port;
                    let socks_port = self.socks_port;
                    let master = self.master_address.clone();
                    let handler = Arc::clone(&join_handler);

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection_with_join(
                            client,
                            &target,
                            target_port,
                            socks_port,
                            &master,
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
        master_address: &str,
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
        Self::handle_connection(client, target, target_port, socks_port, master_address).await
    }

    /// Handle a single proxied connection
    async fn handle_connection(
        client: TcpStream,
        target: &str,
        target_port: u16,
        socks_port: u16,
        master_address: &str,
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
        Self::proxy_with_host_rewrite(client, socks, &domain, target_port, master_address).await
    }

    /// Proxy connection with HTTP Host header rewriting
    ///
    /// Many sites (like Dread) require the correct Host header.
    /// We rewrite it from the master onion to the target onion.
    /// Also rewrites Location and Set-Cookie headers in responses.
    async fn proxy_with_host_rewrite(
        mut client: TcpStream,
        mut socks: TcpStream,
        target_host: &str,
        target_port: u16,
        master_address: &str,
    ) -> Result<()> {
        let target_with_port = if target_port == 80 {
            target_host.to_string()
        } else {
            format!("{}:{}", target_host, target_port)
        };

        let (client_read, mut client_write) = client.split();
        let (socks_read, mut socks_write) = socks.split();

        // Wrap in BufReader for line-based reading
        let mut client_reader = tokio::io::BufReader::new(client_read);
        let mut socks_reader = tokio::io::BufReader::new(socks_read);

        // Spawn task to forward requests client -> server with Host rewriting
        let target_for_task = target_with_port.clone();
        let request_forwarder = async move {
            Self::forward_requests_with_rewrite(&mut client_reader, &mut socks_write, &target_for_task).await
        };

        // Spawn task to forward responses server -> client WITH header rewriting
        let master_for_task = master_address.to_string();
        let target_for_response = target_host.to_string();
        let response_forwarder = async move {
            Self::forward_responses_with_rewrite(&mut socks_reader, &mut client_write, &target_for_response, &master_for_task).await
        };

        tokio::select! {
            result = request_forwarder => {
                if let Err(e) = result {
                    debug!("Request forwarder error: {}", e);
                }
            }
            result = response_forwarder => {
                if let Err(e) = result {
                    debug!("Response forwarder error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Forward HTTP requests from client to server, rewriting Host header for each request
    async fn forward_requests_with_rewrite<R, W>(
        reader: &mut tokio::io::BufReader<R>,
        writer: &mut W,
        target_host: &str,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        loop {
            // Read the request line
            let mut request_line = String::new();
            let n = reader.read_line(&mut request_line).await?;
            if n == 0 {
                return Ok(()); // Connection closed
            }

            // Check if this is an HTTP request
            let is_http = request_line.starts_with("GET ")
                || request_line.starts_with("POST ")
                || request_line.starts_with("HEAD ")
                || request_line.starts_with("PUT ")
                || request_line.starts_with("DELETE ")
                || request_line.starts_with("PATCH ")
                || request_line.starts_with("OPTIONS ")
                || request_line.starts_with("CONNECT ");

            if !is_http {
                // Not HTTP, just forward and continue
                writer.write_all(request_line.as_bytes()).await?;
                // Copy rest of data raw
                tokio::io::copy(reader, writer).await?;
                return Ok(());
            }

            // Write request line
            writer.write_all(request_line.as_bytes()).await?;

            // Read and process headers
            let mut content_length: usize = 0;
            loop {
                let mut header_line = String::new();
                let n = reader.read_line(&mut header_line).await?;
                if n == 0 {
                    return Ok(()); // Connection closed
                }

                // Check for end of headers
                if header_line == "\r\n" || header_line == "\n" {
                    writer.write_all(header_line.as_bytes()).await?;
                    break;
                }

                // Check for Host header and rewrite it
                let lower = header_line.to_lowercase();
                if lower.starts_with("host:") {
                    let new_header = format!("Host: {}\r\n", target_host);
                    debug!("Rewrote Host header to: {}", target_host);
                    writer.write_all(new_header.as_bytes()).await?;
                } else {
                    // Check for Content-Length
                    if lower.starts_with("content-length:") {
                        if let Some(len_str) = header_line.split(':').nth(1) {
                            content_length = len_str.trim().parse().unwrap_or(0);
                        }
                    }
                    writer.write_all(header_line.as_bytes()).await?;
                }
            }

            writer.flush().await?;

            // Forward request body if present
            if content_length > 0 {
                let mut body_buf = vec![0u8; content_length];
                use tokio::io::AsyncReadExt;
                reader.read_exact(&mut body_buf).await?;
                writer.write_all(&body_buf).await?;
                writer.flush().await?;
            }

            // Continue to next request on this connection (HTTP/1.1 keep-alive)
        }
    }

    /// Forward HTTP responses from server to client, rewriting Location and Set-Cookie headers
    ///
    /// This is critical for proper reverse proxy behavior:
    /// - Location headers must be rewritten so redirects stay on master address
    /// - Set-Cookie Domain= attributes must be stripped so cookies work
    async fn forward_responses_with_rewrite<R, W>(
        reader: &mut tokio::io::BufReader<R>,
        writer: &mut W,
        target_host: &str,
        master_address: &str,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        loop {
            // Read the status line
            let mut status_line = String::new();
            let n = reader.read_line(&mut status_line).await?;
            if n == 0 {
                return Ok(()); // Connection closed
            }

            // Check if this looks like an HTTP response
            let is_http_response = status_line.starts_with("HTTP/");

            if !is_http_response {
                // Not HTTP, just forward and continue with raw copy
                writer.write_all(status_line.as_bytes()).await?;
                tokio::io::copy(reader, writer).await?;
                return Ok(());
            }

            // Write status line unchanged
            writer.write_all(status_line.as_bytes()).await?;

            // Read and process headers
            let mut content_length: Option<usize> = None;
            let mut is_chunked = false;

            loop {
                let mut header_line = String::new();
                let n = reader.read_line(&mut header_line).await?;
                if n == 0 {
                    return Ok(()); // Connection closed
                }

                // Check for end of headers
                if header_line == "\r\n" || header_line == "\n" {
                    writer.write_all(header_line.as_bytes()).await?;
                    break;
                }

                let lower = header_line.to_lowercase();

                // Rewrite Location header
                if lower.starts_with("location:") {
                    let new_header = Self::rewrite_location(&header_line, target_host, master_address);
                    debug!("Rewrote Location header: {} -> {}", header_line.trim(), new_header.trim());
                    writer.write_all(new_header.as_bytes()).await?;
                }
                // Rewrite Set-Cookie header
                else if lower.starts_with("set-cookie:") {
                    let new_header = Self::rewrite_cookie(&header_line);
                    if new_header != header_line {
                        debug!("Rewrote Set-Cookie header");
                    }
                    writer.write_all(new_header.as_bytes()).await?;
                }
                // Track Content-Length
                else if lower.starts_with("content-length:") {
                    if let Some(len_str) = header_line.split(':').nth(1) {
                        content_length = Some(len_str.trim().parse().unwrap_or(0));
                    }
                    writer.write_all(header_line.as_bytes()).await?;
                }
                // Track Transfer-Encoding: chunked
                else if lower.starts_with("transfer-encoding:") {
                    if lower.contains("chunked") {
                        is_chunked = true;
                    }
                    writer.write_all(header_line.as_bytes()).await?;
                }
                else {
                    writer.write_all(header_line.as_bytes()).await?;
                }
            }

            writer.flush().await?;

            // Forward response body
            if is_chunked {
                // Handle chunked transfer encoding
                Self::forward_chunked_body(reader, writer).await?;
            } else if let Some(len) = content_length {
                if len > 0 {
                    // Fixed-length body
                    let mut remaining = len;
                    let mut buf = vec![0u8; 8192.min(remaining)];
                    while remaining > 0 {
                        let to_read = buf.len().min(remaining);
                        use tokio::io::AsyncReadExt;
                        let n = reader.read(&mut buf[..to_read]).await?;
                        if n == 0 {
                            break; // EOF
                        }
                        writer.write_all(&buf[..n]).await?;
                        remaining -= n;
                    }
                }
            }
            // If neither chunked nor content-length, continue to next response
            // (HTTP/1.1 keep-alive or empty body)

            writer.flush().await?;
        }
    }

    /// Forward a chunked transfer-encoded body
    async fn forward_chunked_body<R, W>(
        reader: &mut tokio::io::BufReader<R>,
        writer: &mut W,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        loop {
            // Read chunk size line
            let mut size_line = String::new();
            let n = reader.read_line(&mut size_line).await?;
            if n == 0 {
                return Ok(());
            }
            
            // Parse chunk size (hex)
            let size_str = size_line.trim().split(';').next().unwrap_or("0");
            let chunk_size = usize::from_str_radix(size_str, 16).unwrap_or(0);
            
            // Write chunk size line
            writer.write_all(size_line.as_bytes()).await?;
            
            if chunk_size == 0 {
                // Last chunk - read and forward trailing CRLF
                let mut trailer = String::new();
                reader.read_line(&mut trailer).await?;
                writer.write_all(trailer.as_bytes()).await?;
                break;
            }
            
            // Read and forward chunk data
            let mut remaining = chunk_size;
            let mut buf = vec![0u8; 8192.min(remaining)];
            while remaining > 0 {
                let to_read = buf.len().min(remaining);
                use tokio::io::AsyncReadExt;
                let n = reader.read(&mut buf[..to_read]).await?;
                if n == 0 {
                    break;
                }
                writer.write_all(&buf[..n]).await?;
                remaining -= n;
            }
            
            // Read and forward trailing CRLF
            let mut crlf = String::new();
            reader.read_line(&mut crlf).await?;
            writer.write_all(crlf.as_bytes()).await?;
        }
        
        Ok(())
    }

    /// Rewrite Location header to use master address instead of target
    ///
    /// Converts URLs like:
    /// - http://target.onion/path -> /path (relative)
    /// - https://target.onion/path -> /path (relative)
    /// - http://target.onion:8080/path -> /path (relative)
    fn rewrite_location(header: &str, target_host: &str, _master_address: &str) -> String {
        // Extract the URL from "Location: URL"
        let parts: Vec<&str> = header.splitn(2, ':').collect();
        if parts.len() != 2 {
            return header.to_string();
        }
        
        let url = parts[1].trim();
        
        // Target without .onion suffix for matching
        let target_base = target_host.trim_end_matches(".onion");
        
        // Check if URL points to the target
        // Handle http://target.onion, https://target.onion, target.onion
        for prefix in &[
            format!("http://{}.onion", target_base),
            format!("https://{}.onion", target_base),
            format!("http://{}:80", target_host),
            format!("https://{}:443", target_host),
            target_host.to_string(),
        ] {
            if url.starts_with(prefix) {
                // Extract path after the host
                let remainder = &url[prefix.len()..];
                let path = if remainder.is_empty() || remainder == "/" {
                    "/".to_string()
                } else if remainder.starts_with('/') {
                    remainder.to_string()
                } else if remainder.starts_with(':') {
                    // Port number - find the path after
                    if let Some(slash_pos) = remainder.find('/') {
                        remainder[slash_pos..].to_string()
                    } else {
                        "/".to_string()
                    }
                } else {
                    format!("/{}", remainder)
                };
                
                // Return relative path (browser will resolve against current origin)
                return format!("Location: {}\r\n", path);
            }
        }
        
        // Not a target URL, pass through unchanged
        header.to_string()
    }

    /// Rewrite Set-Cookie header to remove Domain= attribute
    ///
    /// Removes Domain= so cookies are scoped to the master address
    fn rewrite_cookie(header: &str) -> String {
        // Split into parts by ;
        let parts: Vec<&str> = header.splitn(2, ':').collect();
        if parts.len() != 2 {
            return header.to_string();
        }
        
        let cookie_parts: Vec<&str> = parts[1].split(';').collect();
        let mut new_parts: Vec<&str> = Vec::new();
        
        for part in cookie_parts {
            let trimmed = part.trim().to_lowercase();
            // Skip Domain= attribute
            if !trimmed.starts_with("domain=") {
                new_parts.push(part);
            }
        }
        
        format!("Set-Cookie:{}\r\n", new_parts.join(";").trim_end())
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
