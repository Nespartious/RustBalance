//! HTTP-aware reverse proxy
//!
//! Proper reverse proxy that rewrites Location and Set-Cookie headers
//! so the client's URL bar stays on the master .onion address.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use reqwest::redirect::Policy;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

/// Configuration for the HTTP reverse proxy
#[derive(Clone)]
pub struct HttpProxyConfig {
    /// Local address to listen on (e.g., "127.0.0.1:8080")
    pub listen_addr: SocketAddr,
    /// Backend .onion address to proxy to (e.g., "http://target.onion")
    pub backend_address: String,
    /// Backend port
    pub backend_port: u16,
    /// SOCKS proxy address for .onion resolution (e.g., "127.0.0.1:9050")
    pub socks_proxy: String,
    /// Master .onion address (for rewriting Location headers back to this)
    pub master_address: String,
}

/// HTTP reverse proxy that maintains URL bar transparency
pub struct HttpProxy {
    config: Arc<HttpProxyConfig>,
    client: reqwest::Client,
}

impl HttpProxy {
    /// Create a new HTTP reverse proxy
    pub fn new(config: HttpProxyConfig) -> Result<Self> {
        // Build reqwest client with SOCKS5h proxy for .onion resolution
        let socks_url = format!("socks5h://{}", config.socks_proxy);

        let client = reqwest::Client::builder()
            .redirect(Policy::none()) // Don't follow redirects - we need to rewrite them!
            .proxy(reqwest::Proxy::all(&socks_url)
                .context("Failed to configure SOCKS proxy")?)
            .timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(60))
            .build()
            .context("Failed to build HTTP client")?;

        info!(
            "HTTP proxy configured: {} -> {} via {}",
            config.master_address, config.backend_address, socks_url
        );

        Ok(Self {
            config: Arc::new(config),
            client,
        })
    }

    /// Run the HTTP reverse proxy server
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", self.config.listen_addr))?;

        info!(
            "HTTP reverse proxy listening on {}",
            self.config.listen_addr
        );
        info!(
            "Proxying {} -> {}",
            self.config.master_address, self.config.backend_address
        );

        loop {
            let (stream, addr) = listener.accept().await?;
            let io = TokioIo::new(stream);

            let config = Arc::clone(&self.config);
            let client = self.client.clone();

            tokio::spawn(async move {
                let service = service_fn(|req| {
                    let config = Arc::clone(&config);
                    let client = client.clone();
                    async move { handle_request(req, config, client, addr).await }
                });

                if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                    debug!("Connection error from {}: {}", addr, e);
                }
            });
        }
    }
}

/// Handle a single HTTP request
async fn handle_request(
    req: Request<Incoming>,
    config: Arc<HttpProxyConfig>,
    client: reqwest::Client,
    client_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    debug!("Session from {}: {} {}", client_addr, method, uri);

    match forward_to_backend(req, &config, &client).await {
        Ok(response) => {
            debug!("Response for {} {}: {}", method, uri, response.status());
            Ok(response)
        },
        Err(e) => {
            error!("Proxy error for {} {}: {}", method, uri, e);
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Proxy error: {}", e),
            ))
        },
    }
}

/// Forward request to backend and return response with rewritten headers
async fn forward_to_backend(
    req: Request<Incoming>,
    config: &HttpProxyConfig,
    client: &reqwest::Client,
) -> Result<Response<Full<Bytes>>> {
    // ========================================
    // 1. EXTRACT PATH AND BUILD BACKEND URL
    // ========================================
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");

    // Construct full backend URL
    let backend_url = format!(
        "http://{}:{}{}",
        config.backend_address.trim_end_matches('/'),
        config.backend_port,
        path
    );

    debug!("Forwarding to backend: {}", backend_url);

    // ========================================
    // 2. COPY REQUEST METHOD AND HEADERS
    // ========================================
    let method = convert_method(req.method())?;
    let headers = req.headers().clone();

    // Read request body
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .context("Failed to read request body")?
        .to_bytes();

    let mut req_builder = client.request(method, &backend_url);

    // Forward headers, but rewrite Host to backend
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if name_lower == "host" {
            // Rewrite Host header to backend
            req_builder = req_builder.header(
                name,
                format!("{}:{}", config.backend_address, config.backend_port),
            );
        } else {
            req_builder = req_builder.header(name, value);
        }
    }

    // Attach body if present
    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes.to_vec());
    }

    // ========================================
    // 3. SEND REQUEST TO BACKEND
    // ========================================
    let backend_response = req_builder
        .send()
        .await
        .context("Failed to connect to backend")?;

    // ========================================
    // 4. PROCESS RESPONSE AND REWRITE HEADERS
    // ========================================
    let status = StatusCode::from_u16(backend_response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response = Response::builder().status(status);

    // Iterate through all backend response headers and rewrite as needed
    for (name, value) in backend_response.headers().iter() {
        let name_str = name.as_str();
        let name_lower = name_str.to_lowercase();

        if name_lower == "location" {
            // REWRITE LOCATION HEADERS (for redirects)
            if let Ok(location) = value.to_str() {
                let rewritten = rewrite_location(location, config);
                debug!("Rewrote Location: {} -> {}", location, rewritten);
                response = response.header(name_str, rewritten);
            }
        } else if name_lower == "set-cookie" {
            // REWRITE COOKIES (remove domain restrictions)
            if let Ok(cookie) = value.to_str() {
                let rewritten = rewrite_cookie(cookie);
                response = response.header(name_str, rewritten);
            }
        } else {
            // Pass through all other headers unchanged
            response = response.header(name_str, value);
        }
    }

    // ========================================
    // 5. READ RESPONSE BODY AND RETURN
    // ========================================
    let body_bytes = backend_response
        .bytes()
        .await
        .context("Failed to read backend response body")?;

    response
        .body(Full::new(body_bytes))
        .context("Failed to build response")
}

/// Rewrite Location header to keep user on master address
fn rewrite_location(location: &str, config: &HttpProxyConfig) -> String {
    // Check if Location points to our backend address
    let backend_patterns = [
        format!("http://{}:{}", config.backend_address, config.backend_port),
        format!("https://{}:{}", config.backend_address, config.backend_port),
        format!("http://{}", config.backend_address),
        format!("https://{}", config.backend_address),
    ];

    for pattern in &backend_patterns {
        if location.starts_with(pattern) {
            // Extract the path after the backend address and make it relative
            let path = &location[pattern.len()..];
            if path.is_empty() {
                return "/".to_string();
            }
            return path.to_string();
        }
    }

    // Keep everything else as-is:
    // - External redirects to other .onion addresses
    // - Already relative paths (e.g., "/login")
    // - Any other URLs
    location.to_string()
}

/// Rewrite Set-Cookie header to remove Domain= restrictions
fn rewrite_cookie(cookie: &str) -> String {
    // Remove Domain= attributes so cookies work with any domain (proxy or direct)
    // Trim each part to avoid double-spacing when rejoining
    let filtered: Vec<String> = cookie
        .split(';')
        .map(|p| p.trim())
        .filter(|part| {
            let lower = part.to_lowercase();
            !lower.starts_with("domain=")
        })
        .map(|s| s.to_string())
        .collect();
    filtered.join("; ")
}

/// Convert hyper Method to reqwest Method
fn convert_method(method: &Method) -> Result<reqwest::Method> {
    match *method {
        Method::GET => Ok(reqwest::Method::GET),
        Method::POST => Ok(reqwest::Method::POST),
        Method::PUT => Ok(reqwest::Method::PUT),
        Method::DELETE => Ok(reqwest::Method::DELETE),
        Method::HEAD => Ok(reqwest::Method::HEAD),
        Method::OPTIONS => Ok(reqwest::Method::OPTIONS),
        Method::PATCH => Ok(reqwest::Method::PATCH),
        Method::TRACE => Ok(reqwest::Method::TRACE),
        Method::CONNECT => Ok(reqwest::Method::CONNECT),
        _ => bail!("Unsupported HTTP method: {}", method),
    }
}

/// Create an error response
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Internal Server Error"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_location_absolute_to_relative() {
        let config = HttpProxyConfig {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            backend_address: "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
                .to_string(),
            backend_port: 80,
            socks_proxy: "127.0.0.1:9050".to_string(),
            master_address: "master.onion".to_string(),
        };

        // Backend URL should become relative
        let result = rewrite_location(
            "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/search?q=test",
            &config,
        );
        assert_eq!(result, "/search?q=test");

        // With port
        let result = rewrite_location(
            "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80/",
            &config,
        );
        assert_eq!(result, "/");

        // External should pass through
        let result = rewrite_location("https://example.com/page", &config);
        assert_eq!(result, "https://example.com/page");

        // Relative should pass through
        let result = rewrite_location("/login", &config);
        assert_eq!(result, "/login");
    }

    #[test]
    fn test_rewrite_cookie() {
        // Remove Domain= attribute
        let result = rewrite_cookie("session=abc123; Domain=.example.com; Path=/; HttpOnly");
        assert_eq!(result, "session=abc123; Path=/; HttpOnly");

        // Keep cookies without Domain
        let result = rewrite_cookie("token=xyz; Path=/; Secure");
        assert_eq!(result, "token=xyz; Path=/; Secure");
    }
}
