//! Tor Control Port client
//!
//! Communicates with the local Tor daemon via the control protocol.

use crate::config::TorConfig;
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// Response from ADD_ONION command
#[derive(Debug, Clone)]
pub struct AddOnionResponse {
    /// The service ID (without .onion suffix)
    pub service_id: String,
    /// The full onion address
    pub onion_address: String,
}

/// Response from GETINFO onions/current or hs/* commands
#[derive(Debug, Clone)]
pub struct HsServiceInfo {
    /// Introduction points for this service  
    pub intro_points: Vec<IntroPointInfo>,
}

/// Information about an introduction point from Tor
#[derive(Debug, Clone)]
pub struct IntroPointInfo {
    /// The relay fingerprint (base64 or hex)
    pub relay_id: String,
    /// Raw link specifiers if available
    pub link_specifiers: Vec<u8>,
}

/// Common cookie file locations
const COOKIE_PATHS: &[&str] = &[
    "/run/tor/control.authcookie",
    "/var/run/tor/control.authcookie",
    "/var/lib/tor/control_auth_cookie",
];

/// Connection to Tor control port
pub struct TorController {
    stream: TcpStream,
    authenticated: bool,
}

impl TorController {
    /// Connect to Tor control port
    pub async fn connect(config: &TorConfig) -> Result<Self> {
        let addr = format!("{}:{}", config.control_host, config.control_port);
        debug!("Connecting to Tor control port: {}", addr);

        let stream = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("Failed to connect to Tor at {}", addr))?;

        let mut controller = Self {
            stream,
            authenticated: false,
        };

        // Authenticate
        if let Some(password) = &config.control_password {
            controller.authenticate_password(password).await?;
        } else {
            controller.authenticate_cookie().await?;
        }

        Ok(controller)
    }

    /// Authenticate with password (hex-encoded for HashedControlPassword)
    async fn authenticate_password(&mut self, password: &str) -> Result<()> {
        // Tor expects hex-encoded password when using HashedControlPassword
        let password_hex = data_encoding::HEXLOWER.encode(password.as_bytes());
        let cmd = format!("AUTHENTICATE {}\r\n", password_hex);
        self.send_command(&cmd).await?;
        self.authenticated = true;
        Ok(())
    }

    /// Authenticate with cookie file
    async fn authenticate_cookie(&mut self) -> Result<()> {
        // Try to find and read the cookie file
        for path in COOKIE_PATHS {
            if let Ok(cookie) = std::fs::read(path) {
                let cookie_hex = data_encoding::HEXLOWER.encode(&cookie);
                let cmd = format!("AUTHENTICATE {}\r\n", cookie_hex);
                match self.send_command(&cmd).await {
                    Ok(_) => {
                        self.authenticated = true;
                        debug!("Authenticated with cookie from {}", path);
                        return Ok(());
                    },
                    Err(e) => {
                        debug!("Cookie auth failed with {}: {}", path, e);
                        continue;
                    },
                }
            }
        }

        // Fallback: try null authentication (works if no auth configured)
        debug!("Trying null authentication");
        self.send_command("AUTHENTICATE\r\n").await?;
        self.authenticated = true;
        Ok(())
    }

    /// Send a command and read response
    async fn send_command(&mut self, cmd: &str) -> Result<String> {
        // Log the command being sent (truncate if long)
        let cmd_preview = if cmd.len() > 100 { &cmd[..100] } else { cmd };
        tracing::info!("Sending Tor command: {}...", cmd_preview.trim());

        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.flush().await?;
        tracing::info!("Command sent and flushed, waiting for response...");

        let mut reader = BufReader::new(&mut self.stream);
        let mut response = String::new();
        let mut in_data_block = false;
        let mut total_lines_read = 0;

        loop {
            let mut line = String::new();
            tracing::debug!("Waiting to read line {}...", total_lines_read + 1);

            // Add a timeout to prevent hanging forever
            // Use 30 seconds to accommodate large responses (e.g. consensus ~5MB)
            let read_future = reader.read_line(&mut line);
            let bytes_read =
                match tokio::time::timeout(std::time::Duration::from_secs(30), read_future).await {
                    Ok(result) => result?,
                    Err(_) => {
                        tracing::warn!(
                            "Timeout waiting for Tor response after {} lines",
                            total_lines_read
                        );
                        anyhow::bail!("Timeout waiting for Tor response");
                    },
                };

            total_lines_read += 1;
            tracing::debug!(
                "Read line {}: {} bytes: {:?}",
                total_lines_read,
                bytes_read,
                line.trim()
            );

            if bytes_read == 0 {
                tracing::info!(
                    "EOF reached after {} lines, breaking loop",
                    total_lines_read
                );
                break;
            }

            // Check if this is the start of a data block (multi-line response)
            // Format: 250+keyword=\r\n (data lines) .\r\n 250 OK\r\n
            if line.starts_with("250+") {
                in_data_block = true;
                response.push_str(&line);
                continue;
            }

            // Check for end of data block
            if in_data_block && line.trim() == "." {
                in_data_block = false;
                // Don't add the dot line to response
                continue;
            }

            // Check for final response (250 OK or error)
            // Error codes are 5XX where XX are digits
            if !in_data_block
                && (line.starts_with("250 ")
                    || (line.starts_with("5")
                        && line.len() >= 3
                        && line.chars().skip(1).take(2).all(|c| c.is_ascii_digit())))
            {
                tracing::info!("Got final response line: {:?}", line.trim());
                // Don't include "250 OK" in the response data
                if line.starts_with("5") {
                    response.push_str(&line);
                }
                break;
            }

            response.push_str(&line);
        }

        // Check for error response - must be error code format (5XX)
        let is_error = response.lines().any(|line| {
            line.starts_with("5")
                && line.len() >= 3
                && line.chars().skip(1).take(2).all(|c| c.is_ascii_digit())
        });

        if is_error {
            tracing::error!("Tor control error: {}", response.trim());
            bail!("Tor control error: {}", response.trim());
        }

        tracing::info!(
            "Command completed successfully, response len: {}",
            response.len()
        );
        Ok(response)
    }

    /// Get a hidden service descriptor by onion address
    pub async fn get_hs_descriptor(&mut self, onion_addr: &str) -> Result<String> {
        // Strip .onion suffix if present
        let addr = onion_addr.trim_end_matches(".onion");

        let cmd = format!("HSFETCH {}\r\n", addr);
        let response = self.send_command(&cmd).await?;

        debug!("HSFETCH response: {}", response);

        // The actual descriptor comes via async HS_DESC event
        // For now, we trigger the fetch - descriptor parsing happens elsewhere
        Ok(response)
    }

    /// Upload a hidden service descriptor
    pub async fn upload_hs_descriptor(
        &mut self,
        descriptor: &str,
        hs_address: &str,
        servers: &[String],
    ) -> Result<()> {
        // Build SERVER= arguments: one SERVER= per HSDir fingerprint
        let server_args = if servers.is_empty() {
            String::new()
        } else {
            use std::fmt::Write;
            servers.iter().fold(String::new(), |mut acc, s| {
                let _ = write!(acc, " SERVER={}", s);
                acc
            })
        };

        // Strip .onion suffix if present for HSADDRESS
        let addr = hs_address.trim_end_matches(".onion");

        // Convert LF to CRLF for the descriptor, and ensure proper termination
        // Tor control protocol expects CRLF line endings
        let descriptor_crlf = descriptor.replace("\n", "\r\n");
        // Remove trailing CRLF if present, as we'll add the proper termination
        let descriptor_trimmed = descriptor_crlf.trim_end_matches("\r\n");

        let cmd = format!(
            "+HSPOST{} HSADDRESS={}\r\n{}\r\n.\r\n",
            server_args, addr, descriptor_trimmed
        );

        tracing::info!(
            "HSPOST command length: {} bytes, address: {}",
            cmd.len(),
            addr
        );
        self.send_command(&cmd).await?;
        Ok(())
    }

    /// Get information about the Tor daemon
    pub async fn get_info(&mut self, keyword: &str) -> Result<String> {
        let cmd = format!("GETINFO {}\r\n", keyword);
        self.send_command(&cmd).await
    }

    /// Check if Tor is fully bootstrapped
    pub async fn is_bootstrapped(&mut self) -> Result<bool> {
        let response = self.get_info("status/bootstrap-phase").await?;
        Ok(response.contains("PROGRESS=100"))
    }

    /// Get circuit status
    pub async fn get_circuit_status(&mut self) -> Result<String> {
        self.get_info("circuit-status").await
    }

    /// Create a hidden service using ADD_ONION with the provided Ed25519 private key
    ///
    /// The key should be the expanded 64-byte Ed25519 secret key (as from hs_ed25519_secret_key file)
    /// Virtual port is the port clients connect to, target is where connections are sent locally.
    ///
    /// Flags:
    /// - DiscardPK: Don't return the private key in response
    /// - Detach: Keep the service running even if control connection closes
    /// - NonAnonymous: Use single-hop circuits (faster, but less anonymous - requires specific Tor config)
    pub async fn add_onion(
        &mut self,
        private_key: &[u8; 64],
        virtual_port: u16,
        target_port: u16,
        flags: &[&str],
    ) -> Result<AddOnionResponse> {
        // Tor expects ED25519-V3 keys in base64 format
        // The key should be 64 bytes: 32-byte seed + 32-byte public key (expanded form)
        let key_b64 = data_encoding::BASE64.encode(private_key);

        let flags_str = if flags.is_empty() {
            String::new()
        } else {
            format!(" Flags={}", flags.join(","))
        };

        let cmd = format!(
            "ADD_ONION ED25519-V3:{}{} Port={},{}\r\n",
            key_b64, flags_str, virtual_port, target_port
        );

        info!(
            "Sending ADD_ONION command for port {} -> {}",
            virtual_port, target_port
        );
        let response = self.send_command(&cmd).await?;

        // Parse response to extract ServiceID
        // Response format: "250-ServiceID=<address>\n250 OK"
        let service_id = response
            .lines()
            .find_map(|line| {
                let line = line.trim();
                if line.starts_with("250-ServiceID=") || line.starts_with("ServiceID=") {
                    Some(line.split('=').nth(1)?.to_string())
                } else {
                    None
                }
            })
            .context("ADD_ONION response missing ServiceID")?;

        let onion_address = format!("{}.onion", service_id);

        info!("Created hidden service: {}", onion_address);

        Ok(AddOnionResponse {
            service_id,
            onion_address,
        })
    }

    /// Remove a previously created onion service
    pub async fn del_onion(&mut self, service_id: &str) -> Result<()> {
        let cmd = format!("DEL_ONION {}\r\n", service_id);
        self.send_command(&cmd).await?;
        info!("Removed hidden service: {}", service_id);
        Ok(())
    }

    /// Get list of currently active hidden services created via ADD_ONION
    pub async fn get_onion_services(&mut self) -> Result<Vec<String>> {
        let response = self.get_info("onions/current").await?;

        // Parse response - format varies, may be empty or list service IDs
        let services: Vec<String> = response
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with("250-onions/current=") || line.starts_with("onions/current=") {
                    let ids = line.split('=').nth(1)?;
                    Some(ids.split(',').map(|s| s.to_string()).collect::<Vec<_>>())
                } else if line.len() == 56 && !line.contains(' ') {
                    // Direct service ID on its own line
                    Some(vec![line.to_string()])
                } else {
                    None
                }
            })
            .flatten()
            .collect();

        Ok(services)
    }

    /// Get our own service's descriptor (for file-based HS)
    /// Returns the raw descriptor text if available
    pub async fn get_own_hs_descriptor(&mut self, onion_addr: &str) -> Result<Option<String>> {
        let addr = onion_addr.trim_end_matches(".onion");

        // Try to get the descriptor Tor has cached for our service
        let response = self.get_info(&format!("hs/service/desc/id/{}", addr)).await;

        match response {
            Ok(resp) => {
                // V3 descriptors start with "hs-descriptor 3"
                // The response format is: 250+hs/service/desc/id/<addr>=<descriptor>
                // Check for substantial response (descriptor is typically 10KB+)
                if resp.len() > 1000 {
                    debug!("Got descriptor for our service: {} bytes", resp.len());
                    Ok(Some(resp))
                } else if resp.contains("hs-descriptor") {
                    Ok(Some(resp))
                } else {
                    debug!(
                        "No descriptor cached for our service yet (resp len: {})",
                        resp.len()
                    );
                    Ok(None)
                }
            },
            Err(e) => {
                // 552 means "unrecognized" which happens if HS isn't publishing yet
                if e.to_string().contains("552") {
                    debug!("Service descriptor not available yet: {}", e);
                    Ok(None)
                } else {
                    Err(e)
                }
            },
        }
    }

    /// Enable or disable Tor's automatic hidden service descriptor publishing
    ///
    /// When disabled (enabled=false), Tor will still create and manage intro points,
    /// but will NOT publish descriptors to HSDirs. This allows RustBalance to publish
    /// merged descriptors via HSPOST without Tor overwriting them.
    ///
    /// Use this in multi-node mode where we handle descriptor publishing ourselves.
    pub async fn set_publish_descriptors(&mut self, enabled: bool) -> Result<()> {
        let value = if enabled { "1" } else { "0" };
        let cmd = format!("SETCONF PublishHidServDescriptors={}\r\n", value);
        info!(
            "Setting PublishHidServDescriptors={} (Tor auto-publish {})",
            value,
            if enabled { "enabled" } else { "disabled" }
        );
        self.send_command(&cmd).await?;
        info!("PublishHidServDescriptors set to {}", value);
        Ok(())
    }

    /// Get the number of established introduction points for our service
    ///
    /// Note: V3 descriptors have encrypted intro points, so we can't directly count them.
    /// Instead, we check if Tor has a valid descriptor published, which indicates
    /// intro points are established. Tor typically creates 3 intro points by default.
    pub async fn get_hs_intro_point_count(&mut self, onion_addr: &str) -> Result<usize> {
        match self.get_own_hs_descriptor(onion_addr).await? {
            Some(desc) => {
                // V3 descriptors encrypt intro points, so we can't directly count them.
                // However, if we have a descriptor > 5KB, Tor has successfully established
                // intro points and published. Default is 3 intro points.
                if desc.len() > 5000 {
                    // Substantial descriptor = intro points established
                    // Return 3 as Tor's default intro point count
                    Ok(3)
                } else {
                    // Small descriptor might be incomplete
                    debug!(
                        "Descriptor too small ({} bytes), assuming no intro points",
                        desc.len()
                    );
                    Ok(0)
                }
            },
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    // Integration tests require a running Tor daemon
}
