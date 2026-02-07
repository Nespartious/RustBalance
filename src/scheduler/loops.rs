//! Main scheduler loops

use crate::balance::onion_service::NodeInfo;
use crate::balance::{BootstrapClient, OnionService, Publisher};
use crate::config::Config;
use crate::coord::{CoordMessage, Coordinator, KnownPeerInfo, MessageType, PeerTracker};
use crate::state::RuntimeState;
use crate::tor::TorController;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, trace, warn};

/// Run the main scheduler
pub async fn run(
    config: Config,
    state: RuntimeState,
    _tor: TorController,
    coordinator: Coordinator,
) -> Result<()> {
    let state = Arc::new(RwLock::new(state));
    let coordinator = Arc::new(RwLock::new(coordinator));

    // Initialize election with our config
    {
        let mut coord = coordinator.write().await;
        coord.election_mut().init(
            config.node.id.clone(),
            config.node.priority,
            config.coordination.heartbeat_timeout_secs,
            config.publish.takeover_grace_secs,
        );
    }

    // Determine if this is a joining node (has pre-configured peers)
    let has_configured_peers = config
        .wireguard
        .as_ref()
        .map(|wg| !wg.peers.is_empty())
        .unwrap_or(false);

    // CRITICAL: Write the master key to the HiddenServiceDir BEFORE configuring Tor.
    // This ensures Tor uses the master's identity, not a randomly generated one.
    // When clients connect to the master address, Tor needs the master's keys to
    // decrypt INTRODUCE2 cells. Without this, connections will fail.
    info!(
        "Node hidden service directory: {}",
        config.node.hidden_service_dir
    );
    
    // Load master identity and write its keys to the HS directory
    let master_identity = crate::crypto::load_identity_key(
        std::path::Path::new(&config.master.identity_key_path)
    )?;
    
    info!(
        "Writing master key to HS directory: {}",
        config.node.hidden_service_dir
    );
    crate::crypto::write_tor_key_files(
        &master_identity,
        std::path::Path::new(&config.node.hidden_service_dir),
    )?;

    // Create onion service manager
    let mut onion_service = OnionService::new(&config);

    // For INIT nodes: Configure Tor HS immediately
    // For JOINING nodes: Delay HS config until after bootstrap (to avoid self-connection)
    if has_configured_peers {
        info!("Joining node: Delaying HS config until after bootstrap");
    } else {
        info!("Init node: Configuring Tor hidden service...");
        // Tor will use the master keys we just wrote to the directory
        onion_service
            .configure_tor_hs(&config.node.hidden_service_dir, 80)
            .await?;

        // Wait for Tor to create intro points
        info!("Waiting for Tor to initialize hidden service...");
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Verify hostname matches master address
        match crate::balance::onion_service::read_hs_hostname(&config.node.hidden_service_dir)
            .await
        {
            Ok(hostname) => {
                info!("Tor HS address: {}", hostname);
                info!("Master address: {}", config.master.onion_address);
                // Verify they match (the node should be running AS the master address)
                if !hostname.starts_with(&config.master.onion_address.replace(".onion", "")) {
                    warn!(
                        "HS address mismatch! Expected {}, got {}. Key write may have failed.",
                        config.master.onion_address, hostname
                    );
                }
                // Store in state for intro point sharing
                let mut state = state.write().await;
                state.node_onion_address = Some(hostname);
            },
            Err(e) => {
                error!("Failed to read hostname: {}", e);
            },
        }

        // Mark HS as running
        {
            let mut state = state.write().await;
            state.hs_running = true;
        }
    }

    // Auto-detect mode: WireGuard always runs, mode determined by peer presence
    // This allows seamless transition from single-node to multi-node
    let has_wg_config = config.wireguard.is_some();

    // Create shared peer tracker for join handling
    let peer_tracker = Arc::new(RwLock::new(PeerTracker::new(
        config.coordination.heartbeat_interval_secs,
        3, // dead_threshold: mark peer dead after 3 missed heartbeats
    )));

    // Enable join handler if we have join_secret configured (Node 1 accepts join requests)
    if let (Some(ref _join_secret), Some(ref wg_config)) =
        (&config.coordination.join_secret, &config.wireguard)
    {
        if let (Some(ref pubkey), Some(ref endpoint), Some(ref tunnel_ip)) = (
            &wg_config.public_key,
            &wg_config.external_endpoint,
            &wg_config.tunnel_ip,
        ) {
            info!("Enabling Tor Bootstrap Channel join handler");
            let node_info = NodeInfo {
                node_id: config.node.id.clone(),
                wg_pubkey: pubkey.clone(),
                wg_endpoint: endpoint.clone(),
                tunnel_ip: tunnel_ip.clone(),
            };
            onion_service.enable_join_handler(
                Arc::clone(&peer_tracker),
                node_info,
                Arc::clone(&coordinator),
            );
        }
    }

    if has_wg_config {
        info!("WireGuard configured - coordination layer active, auto-detect mode enabled");
        // In auto-detect mode, we start as standby and check for peers dynamically
        // If no peers are active, we auto-become publisher
    } else {
        info!("No WireGuard config - pure single-node mode, auto-becoming publisher");
        // No coordination possible, become publisher immediately
        {
            let mut coord = coordinator.write().await;
            coord.election_mut().become_publisher();
        }
    }

    // For JOINING nodes: Bootstrap via Tor BEFORE configuring HS
    // This prevents the node from connecting to itself (since HS isn't published yet)
    if has_configured_peers {
        info!("Joining node: Attempting bootstrap via Tor (before HS config)...");

        // Wait a bit for Tor to establish circuits
        info!("Waiting 30 seconds for Tor circuits to establish...");
        tokio::time::sleep(Duration::from_secs(30)).await;

        // Try bootstrap synchronously (max 5 attempts)
        let bootstrap_result = initial_bootstrap(&coordinator, &config).await;

        match bootstrap_result {
            Ok(true) => {
                info!("Bootstrap successful! WireGuard mesh established.");
            },
            Ok(false) => {
                warn!("Bootstrap completed but no peers added. Proceeding anyway.");
            },
            Err(e) => {
                warn!("Bootstrap failed: {}. Proceeding to single-node mode.", e);
            },
        }

        // NOW configure the hidden service (after bootstrap attempt)
        info!("Joining node: NOW configuring Tor hidden service...");
        // Tor will use the master keys we wrote earlier
        onion_service
            .configure_tor_hs(&config.node.hidden_service_dir, 80)
            .await?;

        // Wait for Tor to create intro points
        info!("Waiting for Tor to initialize hidden service...");
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Verify hostname matches master address
        match crate::balance::onion_service::read_hs_hostname(&config.node.hidden_service_dir)
            .await
        {
            Ok(hostname) => {
                info!("Tor HS address: {}", hostname);
                info!("Master address: {}", config.master.onion_address);
                // Verify they match (the node should be running AS the master address)
                if !hostname.starts_with(&config.master.onion_address.replace(".onion", "")) {
                    warn!(
                        "HS address mismatch! Expected {}, got {}. Key write may have failed.",
                        config.master.onion_address, hostname
                    );
                }
                // Store in state for intro point sharing
                let mut state = state.write().await;
                state.node_onion_address = Some(hostname);
            },
            Err(e) => {
                error!("Failed to read hostname: {}", e);
            },
        }

        // Mark HS as running
        {
            let mut state = state.write().await;
            state.hs_running = true;
        }
    }

    // Spawn tasks
    let coord_clone = Arc::clone(&coordinator);
    let state_clone = Arc::clone(&state);
    let config_clone = config.clone();
    let heartbeat_handle = if has_wg_config {
        Some(tokio::spawn(async move {
            heartbeat_loop(coord_clone, state_clone, config_clone).await
        }))
    } else {
        None
    };

    let coord_clone = Arc::clone(&coordinator);
    let config_clone = config.clone();
    let receive_handle = if has_wg_config {
        Some(tokio::spawn(async move {
            receive_loop(coord_clone, config_clone).await
        }))
    } else {
        None
    };

    let state_clone = Arc::clone(&state);
    let coord_clone = Arc::clone(&coordinator);
    let config_clone = config.clone();
    let publish_handle =
        tokio::spawn(async move { publish_loop(state_clone, coord_clone, config_clone).await });

    // Intro point refresh loop - periodically fetches and parses our own descriptor
    let state_clone = Arc::clone(&state);
    let coord_clone = Arc::clone(&coordinator);
    let config_clone = config.clone();
    let intro_point_handle = tokio::spawn(async move {
        intro_point_refresh_loop(state_clone, coord_clone, config_clone).await
    });

    // Run the reverse proxy (blocking)
    let proxy_handle = tokio::spawn(async move { onion_service.run_proxy().await });

    // Background bootstrap loop only for joining nodes (in case initial bootstrap failed)
    // This continues checking for peers even after initial attempt
    let coord_clone = Arc::clone(&coordinator);
    let config_clone = config.clone();
    let bootstrap_handle =
        if has_wg_config && config.coordination.join_secret.is_some() && has_configured_peers {
            // Note: Initial bootstrap already happened above, this is for ongoing checks
            Some(tokio::spawn(async move {
                background_bootstrap_loop(coord_clone, config_clone).await
            }))
        } else if has_wg_config && !has_configured_peers {
            info!("Bootstrap loop disabled - this is the init node (no pre-configured peers)");
            None
        } else {
            None
        };

    // Wait for any task to fail
    tokio::select! {
        r = publish_handle => {
            error!("Publish loop exited: {:?}", r);
        }
        r = proxy_handle => {
            error!("Proxy loop exited: {:?}", r);
        }
        r = intro_point_handle => {
            error!("Intro point refresh loop exited: {:?}", r);
        }
        r = async {
            if let Some(h) = heartbeat_handle { h.await } else { std::future::pending().await }
        } => {
            error!("Heartbeat loop exited: {:?}", r);
        }
        r = async {
            if let Some(h) = bootstrap_handle { h.await } else { std::future::pending().await }
        } => {
            error!("Bootstrap loop exited: {:?}", r);
        }
        r = async {
            if let Some(h) = receive_handle { h.await } else { std::future::pending().await }
        } => {
            error!("Receive loop exited: {:?}", r);
        }
    }

    Ok(())
}

/// Heartbeat loop - sends periodic heartbeats with peer gossip
async fn heartbeat_loop(
    coordinator: Arc<RwLock<Coordinator>>,
    state: Arc<RwLock<RuntimeState>>,
    config: Config,
) -> Result<()> {
    let mut ticker = interval(Duration::from_secs(
        config.coordination.heartbeat_interval_secs,
    ));

    // Build our own peer info for gossip (so others can discover us)
    let our_info = config.wireguard.as_ref().and_then(|wg| {
        match (&wg.public_key, &wg.external_endpoint, &wg.tunnel_ip) {
            (Some(pubkey), Some(endpoint), Some(tunnel_ip)) => Some(KnownPeerInfo {
                node_id: config.node.id.clone(),
                wg_pubkey: pubkey.clone(),
                wg_endpoint: endpoint.clone(),
                tunnel_ip: tunnel_ip.clone(),
            }),
            _ => None,
        }
    });

    loop {
        ticker.tick().await;

        let (role, mut known_peers, intro_point_count) = {
            let coord = coordinator.read().await;
            let role = coord.election().role();
            // Gather known peers for gossip
            let known_peers = coord.peers().get_known_peer_infos();

            // Get our intro point count
            let state = state.read().await;
            let intro_count = state.own_intro_points.len();

            (role, known_peers, intro_count)
        };

        // Include ourselves in the gossip so peers can discover our info
        if let Some(ref our) = our_info {
            if !known_peers.iter().any(|p| p.node_id == our.node_id) {
                known_peers.push(our.clone());
            }
        }

        let msg = CoordMessage::heartbeat(
            config.node.id.clone(),
            role,
            None, // TODO: track last publish time
            known_peers,
            intro_point_count,
        );

        let coord = coordinator.read().await;
        if let Err(e) = coord.broadcast(&msg).await {
            warn!("Failed to send heartbeat: {}", e);
        } else {
            debug!("Successfully sent heartbeat to peers");
        }

        // Also broadcast our intro points with every heartbeat
        // This ensures peers receive them even if initial messages were rejected
        if intro_point_count > 0 {
            let intro_points = {
                let state = state.read().await;
                state.own_intro_points.clone()
            };

            if !intro_points.is_empty() {
                let intro_data: Vec<crate::coord::IntroPointData> = intro_points
                    .iter()
                    .map(|ip| crate::coord::IntroPointData {
                        data: base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            ip.to_bytes(),
                        ),
                    })
                    .collect();

                let intro_msg = CoordMessage::intro_points(config.node.id.clone(), intro_data);
                if let Err(e) = coord.broadcast(&intro_msg).await {
                    debug!("Failed to broadcast intro points with heartbeat: {}", e);
                }
            }
        }
    }
}

/// Receive loop - processes incoming coordination messages
async fn receive_loop(coordinator: Arc<RwLock<Coordinator>>, config: Config) -> Result<()> {
    loop {
        // Get the receive future with a timeout so we don't block forever
        // This allows other tasks to acquire locks
        let recv_result = {
            let coord = coordinator.read().await;
            tokio::time::timeout(Duration::from_millis(100), coord.receive()).await
        };

        match recv_result {
            Ok(Ok(msg)) => {
                if !msg.is_valid_time(config.node.clock_skew_tolerance_secs) {
                    warn!(
                        "Rejecting message with invalid timestamp from {}",
                        msg.node_id
                    );
                    continue;
                }

                // Skip our own messages (shouldn't happen but prevents self-as-peer bug)
                if msg.node_id == config.node.id {
                    trace!("Ignoring our own message");
                    continue;
                }

                // Handle different message types
                match &msg.message {
                    MessageType::Heartbeat(payload) => {
                        // Process heartbeat (updates election and peer state)
                        let mut coord = coordinator.write().await;
                        coord.process_message(&msg);

                        // Ensure the sender is in our WgTransport peer list for broadcasting
                        // The sender includes their own info in known_peers
                        for peer_info in &payload.known_peers {
                            // Skip ourselves
                            if peer_info.node_id == config.node.id {
                                continue;
                            }

                            // Check if this peer is in WgTransport (for broadcast routing)
                            if !coord.has_wg_peer(&peer_info.node_id) {
                                info!(
                                    "Adding peer to WgTransport for broadcasts: {} at {}",
                                    peer_info.node_id, peer_info.wg_endpoint
                                );
                                if let Err(e) = coord.add_runtime_peer(
                                    &peer_info.node_id,
                                    &peer_info.wg_pubkey,
                                    &peer_info.wg_endpoint,
                                    &peer_info.tunnel_ip,
                                ) {
                                    warn!("Failed to add peer {}: {}", peer_info.node_id, e);
                                }
                            }
                        }

                        // Process gossip - discover new peers (for mesh self-healing)
                        let unknown_peers = coord.peers().find_unknown_peers(&payload.known_peers);
                        for peer_info in unknown_peers {
                            // Skip ourselves (we might be in someone else's known_peers)
                            if peer_info.node_id == config.node.id {
                                continue;
                            }

                            // Skip if we already have this peer in WireGuard
                            if coord.has_wg_peer(&peer_info.node_id) {
                                continue;
                            }

                            info!(
                                "Discovered new peer via gossip: {} at {}",
                                peer_info.node_id, peer_info.wg_endpoint
                            );

                            // Add to WireGuard
                            match coord.add_runtime_peer(
                                &peer_info.node_id,
                                &peer_info.wg_pubkey,
                                &peer_info.wg_endpoint,
                                &peer_info.tunnel_ip,
                            ) {
                                Ok(true) => {
                                    info!("Added WireGuard peer: {}", peer_info.node_id);
                                    // Add to peer tracker
                                    coord.peers_mut().process_gossip(&peer_info);

                                    // Send PeerAnnounce to the new peer so they know about us
                                    if let Some(wg_config) = &config.wireguard {
                                        let our_tunnel_ip = wg_config
                                            .tunnel_ip
                                            .clone()
                                            .unwrap_or_else(|| "10.200.200.1".to_string());
                                        let our_endpoint = format!(
                                            "{}:{}",
                                            config.node.id, // This should be our public IP
                                            wg_config.listen_port
                                        );
                                        // Note: We'd need our public key here - for now log the intent
                                        info!(
                                            "Would send PeerAnnounce to {} (need our pubkey)",
                                            peer_info.node_id
                                        );
                                        // TODO: Store our WG pubkey in config and send PeerAnnounce
                                        let _ = our_tunnel_ip;
                                        let _ = our_endpoint;
                                    }
                                },
                                Ok(false) => {
                                    debug!("Peer {} already known", peer_info.node_id);
                                },
                                Err(e) => {
                                    warn!(
                                        "Failed to add WireGuard peer {}: {}",
                                        peer_info.node_id, e
                                    );
                                },
                            }
                        }
                    },
                    MessageType::PeerAnnounce(payload) => {
                        info!(
                            "Received peer announcement from {} (endpoint: {})",
                            msg.node_id, payload.wg_endpoint
                        );

                        // Validate cluster token
                        let token_valid = config
                            .coordination
                            .cluster_token
                            .as_ref()
                            .map(|t| t == &payload.cluster_token)
                            .unwrap_or(true); // If no token configured, accept all

                        if !token_valid {
                            warn!("Rejected peer {} - invalid cluster token", msg.node_id);
                            continue;
                        }

                        let mut coord = coordinator.write().await;

                        // Add to WireGuard if not already known
                        if !coord.has_wg_peer(&msg.node_id) {
                            match coord.add_runtime_peer(
                                &msg.node_id,
                                &payload.wg_pubkey,
                                &payload.wg_endpoint,
                                &payload.tunnel_ip,
                            ) {
                                Ok(true) => {
                                    info!(
                                        "Added WireGuard peer from announcement: {}",
                                        msg.node_id
                                    );
                                },
                                Ok(false) => {},
                                Err(e) => {
                                    warn!("Failed to add peer {}: {}", msg.node_id, e);
                                },
                            }
                        }

                        // Update peer tracker
                        if coord.peers_mut().process_peer_announce(&msg) {
                            info!("Added new peer to tracker: {}", msg.node_id);
                        }
                    },
                    MessageType::IntroPoints(payload) => {
                        debug!(
                            "Received {} intro points from {}",
                            payload.intro_points.len(),
                            msg.node_id
                        );
                        let mut coord = coordinator.write().await;
                        coord
                            .peers_mut()
                            .update_intro_points(&msg.node_id, payload.intro_points.clone());
                    },
                    _ => {
                        // Other message types (LeaseClaim, LeaseRelease, etc.)
                        let mut coord = coordinator.write().await;
                        coord.process_message(&msg);
                    },
                }
            },
            Ok(Err(e)) => {
                warn!("Error receiving message: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            },
            Err(_) => {
                // Timeout - no message received, just loop to try again
                // This releases the lock periodically
            },
        }
    }
}

/// Publish loop - manages descriptor publishing with auto-detect mode
async fn publish_loop(
    state: Arc<RwLock<RuntimeState>>,
    coordinator: Arc<RwLock<Coordinator>>,
    config: Config,
) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    // Load master key
    let identity = crate::crypto::load_identity_key(&config.master.identity_key_path)?;
    let mut publisher = Publisher::new(identity);

    // Wait for hidden service to be established AND intro points to be collected
    // The intro_check loop waits 60 seconds then checks every 30 seconds,
    // so we wait 90 seconds to ensure at least one intro point check has completed.
    info!("Publish loop waiting 90 seconds for hidden service and intro points...");
    tokio::time::sleep(Duration::from_secs(90)).await;

    let mut ticker = interval(Duration::from_secs(config.publish.refresh_interval_secs));
    // Tick immediately on first iteration (don't wait for full interval)
    ticker.tick().await;
    
    info!(
        "Publish loop starting, interval: {} secs",
        config.publish.refresh_interval_secs
    );

    // Max intro points per descriptor (Tor spec limit)
    let max_intro_points = 20;

    // Track whether Tor's auto-publish is disabled (for multi-node mode)
    let mut auto_publish_disabled = false;

    loop {

        // Auto-detect mode: check if we have active peers
        let (has_active_peers, alive_count) = {
            let coord = coordinator.read().await;
            let alive = coord.peers().alive_count();
            (alive > 0, alive)
        };

        if has_active_peers {
            info!("Multi-node mode detected: {} active peer(s)", alive_count);
        } else {
            debug!("Single-node mode: no active peers");
        }

        // Check if we should take over publisher role
        {
            let mut coord = coordinator.write().await;

            if has_active_peers {
                // Multi-node mode - use election logic
                let should_take = coord.election_mut().should_take_over();
                if should_take {
                    coord.election_mut().become_publisher();
                    info!("Became publisher via election");

                    // Announce lease claim
                    let msg =
                        CoordMessage::lease_claim(config.node.id.clone(), config.node.priority);
                    let _ = coord.broadcast(&msg).await;
                }
            } else {
                // In single-node mode (no peers), always be publisher
                if !coord.election().is_publisher() {
                    info!("No active peers - auto-becoming publisher");
                    coord.election_mut().become_publisher();
                }
            }
        }

        // Check if we're publisher
        let is_publisher = {
            let coord = coordinator.read().await;
            coord.election().is_publisher()
        };

        if !is_publisher {
            debug!("Not publisher, skipping publish");
            ticker.tick().await;
            continue;
        }

        // Get intro point counts
        let (own_intro_count, peer_intro_count) = {
            let state = state.read().await;
            let coord = coordinator.read().await;
            (
                state.own_intro_points.len(),
                coord.peers().total_peer_intro_points(),
            )
        };

        let total_intro_count = own_intro_count + peer_intro_count;

        if !has_active_peers {
            // Single-node mode: Tor auto-publishes for master address since we
            // injected the master key into HiddenServiceDir. However, we still
            // HSPOST to ensure descriptor freshness and to allow seamless
            // transition when peers join. Using higher revision counter ensures
            // our descriptor takes precedence.
            info!("Single-node mode: publishing descriptor for master address via HSPOST");

            // Re-enable Tor auto-publish if it was previously disabled (transition from multi → single)
            if auto_publish_disabled {
                info!("Single-node mode: re-enabling Tor auto-publish");
                match crate::tor::control::TorController::connect(&config.tor).await {
                    Ok(mut tor) => {
                        if let Err(e) = tor.set_publish_descriptors(true).await {
                            warn!("Failed to re-enable Tor auto-publish: {}", e);
                        } else {
                            auto_publish_disabled = false;
                            info!("Tor auto-publish re-enabled for single-node mode");
                        }
                    },
                    Err(e) => {
                        warn!("Failed to connect to Tor to re-enable auto-publish: {}", e);
                    },
                }
            }

            // Get our own intro points
            let own_intro_points: Vec<crate::tor::IntroductionPoint> = {
                let state = state.read().await;
                state.own_intro_points.clone()
            };

            if own_intro_points.is_empty() {
                debug!("No intro points yet, waiting...");
                ticker.tick().await;
                continue;
            }

            info!(
                "Publishing descriptor with {} intro points for master address",
                own_intro_points.len()
            );

            // Connect to Tor and publish via HSPOST
            match crate::tor::control::TorController::connect(&config.tor).await {
                Ok(mut tor) => {
                    if let Err(e) = publisher.publish(&mut tor, own_intro_points).await {
                        warn!("Failed to publish descriptor: {}", e);
                    } else {
                        info!("Successfully published descriptor for master address via HSPOST");
                    }
                },
                Err(e) => {
                    warn!(
                        "Failed to connect to Tor control port for publishing: {}",
                        e
                    );
                },
            }
        } else if total_intro_count == 0 {
            // Multi-node but no intro points collected yet
            warn!(
                "Multi-node mode but no intro points collected yet - waiting for intro point data"
            );
        } else {
            // Multi-node mode with intro points: merge and publish

            // CRITICAL: Disable Tor's auto-publishing in multi-node mode.
            // Tor's service subsystem runs upload_descriptor_to_hsdir() every second,
            // which uses OPE-encrypted revision counters that monotonically increase.
            // This constantly overwrites our HSPOST descriptor on HSDirs.
            // PublishHidServDescriptors=0 only stops descriptor UPLOADS to HSDirs;
            // intro point circuits continue to be maintained normally.
            if !auto_publish_disabled {
                info!("Multi-node mode: disabling Tor auto-publish to prevent HSPOST race");
                match crate::tor::control::TorController::connect(&config.tor).await {
                    Ok(mut tor) => {
                        if let Err(e) = tor.set_publish_descriptors(false).await {
                            warn!("Failed to disable Tor auto-publish: {}", e);
                        } else {
                            auto_publish_disabled = true;
                            info!("Tor auto-publish disabled successfully");
                        }
                    },
                    Err(e) => {
                        warn!("Failed to connect to Tor to disable auto-publish: {}", e);
                    },
                }
            }

            // 1. Collect own intro points
            let own_intro_points: Vec<crate::tor::IntroductionPoint> = {
                let state = state.read().await;
                state.own_intro_points.clone()
            };

            // 2. Collect and deserialize peer intro points
            let peer_intro_data = {
                let coord = coordinator.read().await;
                coord
                    .peers()
                    .collect_peer_intro_points()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>()
            };

            let mut peer_intro_points: Vec<crate::tor::IntroductionPoint> = Vec::new();
            for data in &peer_intro_data {
                match STANDARD.decode(&data.data) {
                    Ok(bytes) => {
                        if let Some(ip) = crate::tor::IntroductionPoint::from_bytes(&bytes) {
                            peer_intro_points.push(ip);
                        } else {
                            warn!("Failed to deserialize intro point from peer data");
                        }
                    },
                    Err(e) => {
                        warn!("Failed to decode base64 intro point data: {}", e);
                    },
                }
            }

            // Log actual counts AFTER collecting/deserializing
            // Note: peer_intro_count from heartbeats may differ from actual data received
            let actual_peer_count = peer_intro_points.len();
            if actual_peer_count != peer_intro_count {
                warn!(
                    "Peer intro point mismatch: heartbeat reports {} but we have {} actual data entries",
                    peer_intro_count, actual_peer_count
                );
            }
            info!(
                "Multi-node mode: merging {} own + {} peer intro points (heartbeat reported {})",
                own_intro_points.len(), actual_peer_count, peer_intro_count
            );

            // 3. Merge intro points, capping at max
            let mut merged: Vec<crate::tor::IntroductionPoint> = own_intro_points;
            merged.extend(peer_intro_points);

            if merged.len() > max_intro_points {
                info!(
                    "Capping {} intro points to max {}",
                    merged.len(),
                    max_intro_points
                );
                merged.truncate(max_intro_points);
            }

            info!(
                "Publishing merged descriptor with {} intro points",
                merged.len()
            );

            // 4. Connect to Tor and publish via HSPOST
            match crate::tor::control::TorController::connect(&config.tor).await {
                Ok(mut tor) => {
                    if let Err(e) = publisher.publish(&mut tor, merged).await {
                        warn!("Failed to publish merged descriptor: {}", e);
                    } else {
                        info!("Successfully published merged descriptor via HSPOST");
                    }
                },
                Err(e) => {
                    warn!(
                        "Failed to connect to Tor control port for publishing: {}",
                        e
                    );
                },
            }
        }
        
        // Wait for next publish interval
        ticker.tick().await;
    }
}

/// Initial bootstrap - runs BEFORE hidden service is configured on joining nodes
///
/// This is a synchronous bootstrap attempt that happens during startup.
/// By running before HS config, the node won't route .onion requests to itself.
/// Returns Ok(true) if bootstrap succeeded and peer was added.
async fn initial_bootstrap(
    coordinator: &Arc<RwLock<Coordinator>>,
    config: &Config,
) -> Result<bool> {
    let max_attempts = 5;
    let delay_between_attempts = Duration::from_secs(15);

    // Extract config values
    let wg_config = config
        .wireguard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No WireGuard config"))?;

    let (wg_pubkey, wg_endpoint, tunnel_ip) = match (
        &wg_config.public_key,
        &wg_config.external_endpoint,
        &wg_config.tunnel_ip,
    ) {
        (Some(p), Some(e), Some(t)) => (p.clone(), e.clone(), t.clone()),
        _ => return Err(anyhow::anyhow!("Incomplete WireGuard config")),
    };

    let join_secret = config
        .coordination
        .join_secret
        .clone()
        .ok_or_else(|| anyhow::anyhow!("No join_secret configured"))?;

    let cluster_token = config
        .coordination
        .cluster_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("No cluster_token configured"))?;

    for attempt in 1..=max_attempts {
        info!(
            "Initial bootstrap attempt {}/{} via Tor to {}",
            attempt, max_attempts, config.master.onion_address
        );

        let client = BootstrapClient::new(
            config.master.onion_address.clone(),
            80,
            join_secret.clone(),
            cluster_token.clone(),
            config.tor.socks_port,
            wg_pubkey.clone(),
            wg_endpoint.clone(),
            tunnel_ip.clone(),
        );

        match client.join().await {
            Ok(response) => {
                info!(
                    "Initial bootstrap successful! Node {} responded",
                    response.responder_node_id
                );

                // Add the responder as a WireGuard peer
                let mut coord = coordinator.write().await;

                match coord.add_runtime_peer(
                    &response.responder_node_id,
                    &response.responder_wg_pubkey,
                    &response.responder_wg_endpoint,
                    &response.responder_tunnel_ip,
                ) {
                    Ok(true) => {
                        info!(
                            "Added bootstrap peer to WireGuard: {} at {}",
                            response.responder_node_id, response.responder_wg_endpoint
                        );
                    },
                    Ok(false) => {
                        debug!("Bootstrap peer already known");
                    },
                    Err(e) => {
                        warn!("Failed to add bootstrap peer to WireGuard: {}", e);
                    },
                }

                // Also add any known peers from the response
                for peer in &response.known_peers {
                    if peer.node_id == config.node.id {
                        continue;
                    }
                    let _ = coord.add_runtime_peer(
                        &peer.node_id,
                        &peer.wg_pubkey,
                        &peer.wg_endpoint,
                        &peer.tunnel_ip,
                    );
                }

                return Ok(true);
            },
            Err(e) => {
                warn!("Bootstrap attempt {} failed: {}", attempt, e);
                if attempt < max_attempts {
                    info!(
                        "Waiting {} seconds before retry...",
                        delay_between_attempts.as_secs()
                    );
                    tokio::time::sleep(delay_between_attempts).await;
                }
            },
        }
    }

    Ok(false) // All attempts failed
}

/// Background bootstrap loop - runs AFTER hidden service is configured
///
/// This continues checking for peers in case:
/// 1. Initial bootstrap failed but WireGuard heartbeats work later
/// 2. Network conditions change
///
/// Since HS is already configured, it won't attempt Tor bootstrap to avoid
/// self-connection. It just monitors for peer liveness.
async fn background_bootstrap_loop(
    coordinator: Arc<RwLock<Coordinator>>,
    _config: Config,
) -> Result<()> {
    let mut ticker = interval(Duration::from_secs(30));

    loop {
        ticker.tick().await;

        let alive_count = {
            let coord = coordinator.read().await;
            coord.peers().alive_count()
        };

        if alive_count > 0 {
            debug!("Background check: {} active peer(s)", alive_count);
        } else {
            // No active peers, but we can't bootstrap via Tor anymore
            // (HS is configured, would connect to self)
            // Just wait for WireGuard heartbeats to potentially work
            debug!("Background check: No active peers, waiting for WireGuard heartbeats");
        }
    }
}

/// Intro point refresh loop - periodically fetches and parses our own descriptor
///
/// This runs on all nodes and updates state.own_intro_points which:
/// 1. Is reported in heartbeats (intro_point_count)
/// 2. Is broadcast to peers via IntroPoints messages
/// 3. Is used by publisher to merge into the final descriptor
///
/// IMPORTANT: In the unified-master-key architecture, each node runs as the master
/// address. The master key is written to node.hidden_service_dir before Tor starts,
/// so Tor creates intro points for the master address. We fetch the descriptor
/// for the master address to get the intro points Tor created.
async fn intro_point_refresh_loop(
    state: Arc<RwLock<RuntimeState>>,
    coordinator: Arc<RwLock<Coordinator>>,
    config: Config,
) -> Result<()> {
    // Wait for hidden service to establish first
    info!("Intro point refresh loop waiting 60 seconds for HS to establish...");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // Load master identity key for descriptor decryption
    // This is the same key that Tor is using (we wrote it to HS dir at startup)
    let node_key_path = std::path::Path::new(&config.node.hidden_service_dir)
        .join("hs_ed25519_secret_key");
    
    let master_identity = match crate::crypto::load_identity_key(&node_key_path) {
        Ok(id) => id,
        Err(e) => {
            error!(
                "Failed to load master identity key from {:?} for intro point parsing: {}",
                node_key_path, e
            );
            return Err(e);
        },
    };

    info!("Loaded master identity key for intro point parsing");

    let mut ticker = interval(Duration::from_secs(30)); // Check every 30 seconds

    info!("Intro point refresh loop starting");

    loop {
        ticker.tick().await;

        // Get the onion address from state (should be master address after HS init)
        let node_onion_address = {
            let state = state.read().await;
            state.node_onion_address.clone()
        };

        let addr = match node_onion_address {
            Some(addr) => addr,
            None => {
                debug!("Onion address not yet available, waiting...");
                continue;
            },
        };

        // Connect to Tor control port
        let mut tor = match crate::tor::control::TorController::connect(&config.tor).await {
            Ok(t) => t,
            Err(e) => {
                warn!("Failed to connect to Tor control port: {}", e);
                continue;
            },
        };

        // Fetch the descriptor from Tor (this is the master address descriptor)
        // Tor auto-publishes this since it has the master key in HiddenServiceDir
        let descriptor_raw = match tor.get_own_hs_descriptor(&addr).await {
            Ok(Some(desc)) => desc,
            Ok(None) => {
                info!("No descriptor available yet for {} - waiting for Tor to publish.", addr);
                continue;
            },
            Err(e) => {
                debug!("Failed to get descriptor: {}", e);
                continue;
            },
        };

        // Parse and decrypt the descriptor using master key
        let intro_points = match crate::tor::HsDescriptor::parse_and_decrypt_with_pubkey(
            &descriptor_raw,
            master_identity.public_key(),
        ) {
            Ok(desc) => desc.introduction_points,
            Err(e) => {
                warn!("Failed to parse/decrypt our descriptor: {}", e);
                if descriptor_raw.len() > 5000 {
                    debug!("Descriptor exists but decryption failed");
                }
                continue;
            },
        };

        let new_count = intro_points.len();

        debug!("Intro point refresh loop: new_count = {}", new_count);

        // Check if intro points changed
        let (current_count, changed) = {
            let state = state.read().await;
            let current = state.own_intro_points.len();
            // Simple change detection: count changed
            (current, current != new_count)
        };

        if new_count > 0 {
            if changed {
                info!(
                    "Intro points updated: {} -> {} (parsed from descriptor)",
                    current_count, new_count
                );
            }

            // Serialize intro points for broadcast
            // NOTE: We broadcast on EVERY tick (not just on change) because:
            // 1. A peer that restarts needs to receive our intro points
            // 2. IntroPoints messages may be lost if peer tracker doesn't have us yet
            // 3. Periodic broadcast ensures eventual consistency
            let intro_data: Vec<crate::coord::IntroPointData> = intro_points
                .iter()
                .map(|ip| crate::coord::IntroPointData {
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        ip.to_bytes(),
                    ),
                })
                .collect();

            // Broadcast to peers
            let msg = CoordMessage::intro_points(config.node.id.clone(), intro_data);
            {
                let coord = coordinator.write().await;
                if let Err(e) = coord.broadcast(&msg).await {
                    warn!("Failed to broadcast intro points: {}", e);
                } else {
                    debug!("Broadcast {} intro points to peers", new_count);
                }
            }

            // Update local state if changed
            if changed {
                let mut state = state.write().await;
                state.own_intro_points = intro_points;
            }
        } else if current_count > 0 && new_count == 0 {
            warn!("Intro points dropped to 0 (was {})", current_count);
            let mut state = state.write().await;
            state.own_intro_points.clear();
        }
    }
}
