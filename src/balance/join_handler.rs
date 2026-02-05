//! Join request handler for Tor Bootstrap Channel
//!
//! Handles join requests from new nodes connecting via the master .onion address.
//! Validates cluster_token and join_secret, then adds the new peer to WireGuard.

use crate::coord::messages::{JoinRequestPayload, JoinResponsePayload, KnownPeerInfo};
use crate::coord::{Coordinator, PeerTracker};
use anyhow::{bail, Context, Result};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Maximum age of a join request (5 minutes)
const MAX_REQUEST_AGE: Duration = Duration::from_secs(300);

/// WireGuard interface name
const WG_INTERFACE: &str = "wg-rb";

/// Handles join requests from new nodes
pub struct JoinHandler {
    /// Expected join secret (the path portion)
    join_secret: String,
    /// Expected cluster token for validation
    cluster_token: String,
    /// This node's info for the response
    node_id: String,
    wg_pubkey: String,
    wg_endpoint: String,
    tunnel_ip: String,
    /// Shared peer tracker (for reading known peers)
    peers: Arc<RwLock<PeerTracker>>,
    /// Coordinator for adding peers to WgTransport
    coordinator: Arc<RwLock<Coordinator>>,
}

impl JoinHandler {
    pub fn new(
        join_secret: String,
        cluster_token: String,
        node_id: String,
        wg_pubkey: String,
        wg_endpoint: String,
        tunnel_ip: String,
        peers: Arc<RwLock<PeerTracker>>,
        coordinator: Arc<RwLock<Coordinator>>,
    ) -> Self {
        Self {
            join_secret,
            cluster_token,
            node_id,
            wg_pubkey,
            wg_endpoint,
            tunnel_ip,
            peers,
            coordinator,
        }
    }

    /// Add a WireGuard peer using the wg command
    fn add_wg_peer(pubkey: &str, endpoint: &str, tunnel_ip: &str) -> Result<()> {
        // Add peer with allowed IPs based on tunnel IP
        let allowed_ips = format!("{}/32", tunnel_ip);

        let status = Command::new("wg")
            .args([
                "set",
                WG_INTERFACE,
                "peer",
                pubkey,
                "endpoint",
                endpoint,
                "allowed-ips",
                &allowed_ips,
                "persistent-keepalive",
                "25",
            ])
            .status()
            .context("Failed to run 'wg set peer'")?;

        if !status.success() {
            bail!("wg set peer command failed with status: {}", status);
        }

        info!(
            "Added WireGuard peer: {} at {} (tunnel: {})",
            pubkey, endpoint, tunnel_ip
        );
        Ok(())
    }

    /// Check if an HTTP request is a join request
    ///
    /// Returns the path if it looks like a potential join request
    pub fn extract_join_path(request_line: &str) -> Option<String> {
        // Parse: "POST /.rb/... HTTP/1.1"
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "POST" && parts[1].starts_with("/.rb/") {
            Some(parts[1].to_string())
        } else {
            None
        }
    }

    /// Check if the path matches our join secret (constant-time comparison)
    pub fn is_valid_join_path(&self, path: &str) -> bool {
        let expected = format!("/.rb/{}", self.join_secret);
        // Use constant-time comparison to prevent timing oracle
        bool::from(path.as_bytes().ct_eq(expected.as_bytes()))
    }

    /// Handle a join request
    ///
    /// This is called after we've verified the path matches
    pub async fn handle_join_request(&self, mut stream: TcpStream) -> Result<()> {
        // Read the HTTP request
        let mut reader = BufReader::new(&mut stream);
        let mut headers = String::new();
        let mut content_length = 0usize;

        // Read headers
        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                bail!("Connection closed while reading headers");
            }

            if line == "\r\n" || line == "\n" {
                break;
            }

            if line.to_lowercase().starts_with("content-length:") {
                if let Some(len) = line.split(':').nth(1) {
                    content_length = len.trim().parse().unwrap_or(0);
                }
            }
            headers.push_str(&line);
        }

        // Read body
        if content_length == 0 || content_length > 8192 {
            self.send_error_response(&mut stream, 400, "Invalid content length")
                .await?;
            return Ok(());
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).await?;

        // Parse the join request
        let join_request: JoinRequestPayload = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(e) => {
                debug!("Failed to parse join request: {}", e);
                self.send_error_response(&mut stream, 400, "Invalid request")
                    .await?;
                return Ok(());
            },
        };

        // Validate cluster token (constant-time)
        if !bool::from(
            join_request
                .cluster_token
                .as_bytes()
                .ct_eq(self.cluster_token.as_bytes()),
        ) {
            warn!("Join request with invalid cluster token");
            // Send generic 404 to not reveal validity
            self.send_not_found(&mut stream).await?;
            return Ok(());
        }

        // Validate request timestamp
        let request_time = SystemTime::UNIX_EPOCH + Duration::from_secs(join_request.request_time);
        let now = SystemTime::now();

        if let Ok(age) = now.duration_since(request_time) {
            if age > MAX_REQUEST_AGE {
                warn!("Join request too old: {:?}", age);
                self.send_not_found(&mut stream).await?;
                return Ok(());
            }
        } else if let Ok(future_by) = request_time.duration_since(now) {
            if future_by > Duration::from_secs(60) {
                warn!("Join request from future: {:?}", future_by);
                self.send_not_found(&mut stream).await?;
                return Ok(());
            }
        }

        // Generate a node ID from the WG pubkey (first 8 chars)
        let new_node_id = format!(
            "node-{}",
            &join_request.wg_pubkey[..8.min(join_request.wg_pubkey.len())]
        );

        info!(
            "Valid join request from {} with WG pubkey: {}",
            new_node_id, join_request.wg_pubkey
        );

        // Add peer to WireGuard AND internal peer list via Coordinator
        // This ensures heartbeats can be sent to the new peer
        {
            let mut coord = self.coordinator.write().await;
            if let Err(e) = coord.add_runtime_peer(
                &new_node_id,
                &join_request.wg_pubkey,
                &join_request.wg_endpoint,
                &join_request.tunnel_ip,
            ) {
                warn!("Failed to add peer via coordinator: {}", e);
                self.send_error_response(&mut stream, 500, "Internal error")
                    .await?;
                return Ok(());
            }
            info!(
                "Added peer {} to WireGuard transport and peer tracker",
                new_node_id
            );
        }

        // Build response with our info and known peers
        let known_peers = {
            let peers = self.peers.read().await;
            peers
                .alive_peers()
                .iter()
                .map(|p| KnownPeerInfo {
                    node_id: p.node_id.clone(),
                    wg_pubkey: p.wg_pubkey.clone().unwrap_or_default(),
                    wg_endpoint: p.endpoint.clone().unwrap_or_default(),
                    tunnel_ip: p.tunnel_ip.clone().unwrap_or_default(),
                })
                .collect()
        };

        let response = JoinResponsePayload {
            success: true,
            error: None,
            responder_node_id: self.node_id.clone(),
            responder_wg_pubkey: self.wg_pubkey.clone(),
            responder_wg_endpoint: self.wg_endpoint.clone(),
            responder_tunnel_ip: self.tunnel_ip.clone(),
            known_peers,
        };

        self.send_success_response(&mut stream, &response).await?;

        info!("Successfully processed join request");
        Ok(())
    }

    /// Send a generic 404 response (used for all auth failures to prevent oracle)
    async fn send_not_found(&self, stream: &mut TcpStream) -> Result<()> {
        let response = "HTTP/1.1 404 Not Found\r\n\
            Content-Type: text/plain\r\n\
            Content-Length: 9\r\n\
            Connection: close\r\n\
            \r\n\
            Not Found";
        stream.write_all(response.as_bytes()).await?;
        Ok(())
    }

    /// Send an error response
    async fn send_error_response(
        &self,
        stream: &mut TcpStream,
        status: u16,
        message: &str,
    ) -> Result<()> {
        let body = format!("{{\"error\":\"{}\"}}", message);
        let response = format!(
            "HTTP/1.1 {} {}\r\n\
            Content-Type: application/json\r\n\
            Content-Length: {}\r\n\
            Connection: close\r\n\
            \r\n\
            {}",
            status,
            if status == 400 {
                "Bad Request"
            } else {
                "Internal Server Error"
            },
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await?;
        Ok(())
    }

    /// Send a success response with the join response payload
    async fn send_success_response(
        &self,
        stream: &mut TcpStream,
        payload: &JoinResponsePayload,
    ) -> Result<()> {
        let body = serde_json::to_string(payload)?;
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
            Content-Type: application/json\r\n\
            Content-Length: {}\r\n\
            Connection: close\r\n\
            \r\n\
            {}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await?;
        Ok(())
    }
}
