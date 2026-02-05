//! Bootstrap client for Tor-based peer discovery
//!
//! When a node starts and has no active peers, it uses this client to connect
//! to the master.onion address via Tor SOCKS and send a JoinRequest.
//! The existing nodes receive this request and add the new node to WireGuard.

use crate::coord::messages::{JoinRequestPayload, JoinResponsePayload, KnownPeerInfo};
use anyhow::{bail, Context, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

/// Bootstrap client for joining the cluster via Tor
pub struct BootstrapClient {
    /// Master .onion address to connect to
    master_onion: String,
    /// Port on the master address
    master_port: u16,
    /// Join secret (the path portion)
    join_secret: String,
    /// Cluster token for authentication
    cluster_token: String,
    /// Tor SOCKS port
    socks_port: u16,
    /// This node's WireGuard info
    wg_pubkey: String,
    wg_endpoint: String,
    tunnel_ip: String,
}

impl BootstrapClient {
    pub fn new(
        master_onion: String,
        master_port: u16,
        join_secret: String,
        cluster_token: String,
        socks_port: u16,
        wg_pubkey: String,
        wg_endpoint: String,
        tunnel_ip: String,
    ) -> Self {
        Self {
            master_onion,
            master_port,
            join_secret,
            cluster_token,
            socks_port,
            wg_pubkey,
            wg_endpoint,
            tunnel_ip,
        }
    }

    /// Attempt to join the cluster via the master .onion address
    ///
    /// Returns the join response containing the responder's info and known peers
    pub async fn join(&self) -> Result<JoinResponsePayload> {
        info!("Attempting to join cluster via {}", self.master_onion);

        // Connect to SOCKS proxy
        let mut socks = TcpStream::connect(format!("127.0.0.1:{}", self.socks_port))
            .await
            .context("Failed to connect to Tor SOCKS proxy")?;

        // SOCKS5 handshake
        socks.write_all(&[0x05, 0x01, 0x00]).await?;

        let mut response = [0u8; 2];
        socks.read_exact(&mut response).await?;
        if response[0] != 0x05 || response[1] != 0x00 {
            bail!("SOCKS5 auth negotiation failed");
        }

        // Connect to master.onion
        let domain = self.master_onion.trim_end_matches(".onion");
        let domain = format!("{}.onion", domain);
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
            request.push((self.master_port >> 8) as u8);
            request.push((self.master_port & 0xff) as u8);
        }

        socks.write_all(&request).await?;

        // Read response
        let mut resp_buf = [0u8; 10];
        socks.read_exact(&mut resp_buf).await?;

        if resp_buf[0] != 0x05 {
            bail!("Invalid SOCKS5 response version");
        }
        if resp_buf[1] != 0x00 {
            bail!("SOCKS5 connect failed with code: {}", resp_buf[1]);
        }

        debug!("SOCKS5 connection established to {}", domain);

        // Build the JoinRequest
        let request_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let join_request = JoinRequestPayload {
            cluster_token: self.cluster_token.clone(),
            wg_pubkey: self.wg_pubkey.clone(),
            wg_endpoint: self.wg_endpoint.clone(),
            tunnel_ip: self.tunnel_ip.clone(),
            request_time,
        };

        let body = serde_json::to_string(&join_request)?;

        // Send HTTP POST request
        let http_request = format!(
            "POST /.rb/{} HTTP/1.1\r\n\
            Host: {}\r\n\
            Content-Type: application/json\r\n\
            Content-Length: {}\r\n\
            Connection: close\r\n\
            \r\n\
            {}",
            self.join_secret,
            domain,
            body.len(),
            body
        );

        socks.write_all(http_request.as_bytes()).await?;

        // Read response
        let mut response_buf = Vec::new();
        socks.read_to_end(&mut response_buf).await?;

        let response_str = String::from_utf8_lossy(&response_buf);
        debug!("Join response: {}", response_str);

        // Parse HTTP response
        let parts: Vec<&str> = response_str.splitn(2, "\r\n\r\n").collect();
        if parts.len() < 2 {
            bail!("Invalid HTTP response - no body");
        }

        let headers = parts[0];
        let body = parts[1];

        // Check status code
        let first_line = headers.lines().next().unwrap_or("");
        if !first_line.contains("200") {
            if first_line.contains("404") {
                bail!("Join endpoint not found - invalid join_secret or endpoint disabled");
            }
            bail!("Join request failed: {}", first_line);
        }

        // Parse JSON response
        let join_response: JoinResponsePayload =
            serde_json::from_str(body).context("Failed to parse join response")?;

        if !join_response.success {
            bail!("Join request rejected: {:?}", join_response.error);
        }

        info!(
            "Successfully joined cluster via node {}",
            join_response.responder_node_id
        );

        Ok(join_response)
    }

    /// Attempt to join with retries
    pub async fn join_with_retry(
        &self,
        max_attempts: u32,
        delay: Duration,
    ) -> Result<JoinResponsePayload> {
        let mut last_error = None;

        for attempt in 1..=max_attempts {
            info!("Join attempt {}/{}", attempt, max_attempts);

            match self.join().await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!("Join attempt {} failed: {}", attempt, e);
                    last_error = Some(e);
                    if attempt < max_attempts {
                        tokio::time::sleep(delay).await;
                    }
                },
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Join failed with no error")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_join_request_serialization() {
        let request = JoinRequestPayload {
            cluster_token: "test-token".to_string(),
            wg_pubkey: "pubkey123".to_string(),
            wg_endpoint: "192.168.1.1:51820".to_string(),
            tunnel_ip: "10.0.0.1".to_string(),
            request_time: 1_234_567_890,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-token"));
        assert!(json.contains("pubkey123"));
    }
}
