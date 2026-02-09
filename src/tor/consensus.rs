//! Tor consensus parsing and HSDir hash ring computation
//!
//! Parses the Tor network consensus to extract HSDir relay information
//! and shared random values (SRVs). Computes the HSDir hash ring to
//! determine which relays are responsible for storing our descriptors.
//!
//! This is required because Tor's HSPOST command only uploads to HSDirs
//! computed with `use_second_hsdir_index=0` (current SRV). During
//! 12:00-00:00 UTC, clients fetch using `use_second_hsdir_index=1`
//! (previous SRV) — completely different HSDirs. Without targeted
//! uploading, our merged descriptor is invisible to half the clients.
//!
//! Reference: rend-spec-v3 section 2.2.6 [HASHRING]

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha3::{Digest, Sha3_256};
use tracing::{debug, info};

/// Number of replicas per descriptor (from Tor spec)
const HSDIR_N_REPLICAS: u64 = 2;

/// How many HSDirs to store per replica (from Tor consensus param, default 4)
const HSDIR_SPREAD_STORE: usize = 4;

/// Time period length in minutes (matching Tor's default)
const TIME_PERIOD_LENGTH_MINUTES: u64 = 1440;

/// An HSDir relay from the consensus
#[derive(Debug, Clone)]
pub struct HsDirNode {
    /// RSA fingerprint in uppercase hex (40 chars), for HSPOST SERVER=
    pub rsa_fingerprint: String,
    /// Ed25519 identity key (32 bytes), for hash ring computation
    pub ed25519_identity: [u8; 32],
}

/// Parsed consensus data for HSDir computation
#[derive(Debug)]
pub struct ConsensusData {
    /// Current SRV (shared-rand-current-value), 32 bytes
    pub current_srv: [u8; 32],
    /// Previous SRV (shared-rand-previous-value), 32 bytes
    pub previous_srv: [u8; 32],
    /// All HSDir-flagged relays with ed25519 keys
    pub hsdir_nodes: Vec<HsDirNode>,
}

/// Compute the HSDir hash ring index for a relay
///
/// `hsdir_index(node) = SHA3-256("node-idx" | ed25519_identity | srv
///                                | INT_8(period_num) | INT_8(period_length))`
fn compute_hsdir_index(
    ed25519_identity: &[u8; 32],
    srv: &[u8; 32],
    period_num: u64,
    period_length: u64,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"node-idx");
    hasher.update(ed25519_identity);
    hasher.update(srv);
    hasher.update(period_num.to_be_bytes());
    hasher.update(period_length.to_be_bytes());
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute the HS store-at index for our service
///
/// `hs_index(replica) = SHA3-256("store-at-idx" | blinded_pk | INT_8(replica)
///                                | INT_8(period_length) | INT_8(period_num))`
fn compute_hs_index(
    blinded_pubkey: &[u8; 32],
    replica_num: u64,
    period_num: u64,
    period_length: u64,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"store-at-idx");
    hasher.update(blinded_pubkey);
    hasher.update(replica_num.to_be_bytes());
    hasher.update(period_length.to_be_bytes());
    hasher.update(period_num.to_be_bytes());
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Get the SRV and time period number for a descriptor.
///
/// Mirrors Onionbalance's `get_srv_and_time_period()` and matches how
/// Tor's `hs_get_responsible_hsdirs()` works with `use_second_hsdir_index`.
///
/// - First descriptor: uses **previous** SRV (`shared-rand-previous-value`)
/// - Second descriptor: uses **current** SRV (`shared-rand-current-value`)
///
/// The time period depends on the TP/SRV phase:
///
/// | Phase              | First desc (prev SRV) | Second desc (curr SRV) |
/// |--------------------|-----------------------|------------------------|
/// | 12:00-00:00 (TP→SRV) | tp = current - 1   | tp = current           |
/// | 00:00-12:00 (SRV→TP) | tp = current        | tp = current + 1       |
pub fn get_srv_and_time_period(
    consensus: &ConsensusData,
    is_first_descriptor: bool,
    current_tp: u64,
) -> ([u8; 32], u64) {
    let between_tp_and_srv = crate::crypto::blinding::in_period_between_tp_and_srv();

    if is_first_descriptor {
        if between_tp_and_srv {
            // 12:00-00:00 UTC: previous SRV, previous TP
            (consensus.previous_srv, current_tp.saturating_sub(1))
        } else {
            // 00:00-12:00 UTC: previous SRV, current TP
            (consensus.previous_srv, current_tp)
        }
    } else if between_tp_and_srv {
        // 12:00-00:00 UTC: current SRV, current TP
        (consensus.current_srv, current_tp)
    } else {
        // 00:00-12:00 UTC: current SRV, next TP
        (consensus.current_srv, current_tp + 1)
    }
}

/// Compute the responsible HSDirs for a blinded public key.
///
/// For each replica (1..=`HSDIR_N_REPLICAS`), computes the HS index on the
/// hash ring and finds the `HSDIR_SPREAD_STORE` closest relays.
///
/// Returns a list of RSA fingerprints (uppercase hex, 40 chars each).
pub fn compute_responsible_hsdirs(
    consensus: &ConsensusData,
    blinded_pubkey: &[u8; 32],
    is_first_descriptor: bool,
    current_tp: u64,
) -> Vec<String> {
    let (srv, tp) = get_srv_and_time_period(consensus, is_first_descriptor, current_tp);
    let period_length = TIME_PERIOD_LENGTH_MINUTES;

    info!(
        "Computing responsible HSDirs: {} descriptor, srv={}, tp={}, period_len={}",
        if is_first_descriptor {
            "first"
        } else {
            "second"
        },
        hex::encode(&srv[..8]),
        tp,
        period_length,
    );

    // Build hash ring: compute hsdir_index for each node
    let mut ring: Vec<([u8; 32], usize)> = consensus
        .hsdir_nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| {
            let hsdir_idx = compute_hsdir_index(&node.ed25519_identity, &srv, tp, period_length);
            (hsdir_idx, idx)
        })
        .collect();

    // Sort by hsdir_index
    ring.sort_by(|a, b| a.0.cmp(&b.0));

    info!("Hash ring size: {} nodes", ring.len());

    if ring.is_empty() {
        info!("Hash ring is empty — no HSDir nodes found in consensus");
        return Vec::new();
    }

    let mut responsible: Vec<String> = Vec::new();

    for replica in 1..=HSDIR_N_REPLICAS {
        let hs_index = compute_hs_index(blinded_pubkey, replica, tp, period_length);
        let mut replica_hsdirs: Vec<String> = Vec::new();

        // Find position in ring using binary search
        let pos = ring.partition_point(|(ref idx, _)| *idx < hs_index);

        debug!(
            "Replica {}: hs_index={}, ring position={}",
            replica,
            hex::encode(&hs_index[..8]),
            pos,
        );

        // Collect HSDIR_SPREAD_STORE closest nodes, wrapping around the ring
        let mut i = pos;
        while replica_hsdirs.len() < HSDIR_SPREAD_STORE {
            if i >= ring.len() {
                i = 0; // Wrap around
            }

            let node_idx = ring[i].1;
            let fingerprint = &consensus.hsdir_nodes[node_idx].rsa_fingerprint;

            // Skip if already in this replica's list
            if replica_hsdirs.contains(fingerprint) {
                debug!("Skipping duplicate in replica: {}", fingerprint);
                i += 1;
                continue;
            }

            // Skip if already in overall responsible list (from previous replica)
            if responsible.contains(fingerprint) {
                debug!("Skipping duplicate across replicas: {}", fingerprint);
                i += 1;
                continue;
            }

            replica_hsdirs.push(fingerprint.clone());
            i += 1;
        }

        responsible.extend(replica_hsdirs);
    }

    info!(
        "Found {} responsible HSDirs for {} descriptor",
        responsible.len(),
        if is_first_descriptor {
            "first"
        } else {
            "second"
        },
    );

    responsible
}

/// Parse a Tor consensus document to extract HSDir nodes and SRV values.
///
/// Expects the raw text from `GETINFO dir/status-vote/current/consensus`.
/// Extracts:
/// - `shared-rand-current-value` and `shared-rand-previous-value`
/// - All relays with the HSDir flag and an ed25519 identity key
pub fn parse_consensus(consensus_text: &str) -> Result<ConsensusData> {
    let mut current_srv = [0u8; 32];
    let mut previous_srv = [0u8; 32];
    let mut has_current_srv = false;
    let mut has_previous_srv = false;
    let mut hsdir_nodes: Vec<HsDirNode> = Vec::new();

    // Parser state for router entries
    let mut current_rsa_fp: Option<String> = None;
    let mut current_ed25519: Option<[u8; 32]> = None;
    let mut is_hsdir = false;

    for line in consensus_text.lines() {
        let line = line.trim();

        // Parse SRV lines from consensus header
        if line.starts_with("shared-rand-current-value ") {
            // Format: shared-rand-current-value <num-reveals> <base64-value>
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(bytes) = STANDARD.decode(parts[2]) {
                    if bytes.len() == 32 {
                        current_srv.copy_from_slice(&bytes);
                        has_current_srv = true;
                    }
                }
            }
        } else if line.starts_with("shared-rand-previous-value ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(bytes) = STANDARD.decode(parts[2]) {
                    if bytes.len() == 32 {
                        previous_srv.copy_from_slice(&bytes);
                        has_previous_srv = true;
                    }
                }
            }
        }
        // Router entry starts with "r "
        else if line.starts_with("r ") {
            // Save previous entry if it was a valid HSDir
            if let (Some(ref fp), Some(ref ed25519)) = (&current_rsa_fp, &current_ed25519) {
                if is_hsdir {
                    hsdir_nodes.push(HsDirNode {
                        rsa_fingerprint: fp.clone(),
                        ed25519_identity: *ed25519,
                    });
                }
            }

            // Reset for new entry
            current_rsa_fp = None;
            current_ed25519 = None;
            is_hsdir = false;

            // Parse RSA fingerprint from r line
            // Format: r <name> <identity-b64> <digest-b64> <published> <ip> <ORport> <DirPort>
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                // identity is base64-encoded 20-byte SHA-1 of RSA key
                let mut id_b64 = parts[2].to_string();
                // Add missing padding
                while id_b64.len() % 4 != 0 {
                    id_b64.push('=');
                }
                if let Ok(id_bytes) = STANDARD.decode(&id_b64) {
                    current_rsa_fp = Some(hex::encode_upper(&id_bytes));
                }
            }
        }
        // Ed25519 identity key line
        else if line.starts_with("id ed25519 ") {
            let key_b64 = line.trim_start_matches("id ed25519 ").trim();
            let mut padded = key_b64.to_string();
            while padded.len() % 4 != 0 {
                padded.push('=');
            }
            if let Ok(key_bytes) = STANDARD.decode(&padded) {
                if key_bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&key_bytes);
                    current_ed25519 = Some(key);
                }
            }
        }
        // Flags line
        else if line.starts_with("s ") {
            is_hsdir = line.split_whitespace().any(|f| f == "HSDir");
        }
    }

    // Don't forget the last entry
    if let (Some(ref fp), Some(ref ed25519)) = (&current_rsa_fp, &current_ed25519) {
        if is_hsdir {
            hsdir_nodes.push(HsDirNode {
                rsa_fingerprint: fp.clone(),
                ed25519_identity: *ed25519,
            });
        }
    }

    if !has_current_srv || !has_previous_srv {
        bail!(
            "Consensus missing SRV values (current: {}, previous: {})",
            has_current_srv,
            has_previous_srv
        );
    }

    info!(
        "Parsed consensus: {} HSDir nodes, current_srv={}..., previous_srv={}...",
        hsdir_nodes.len(),
        hex::encode(&current_srv[..8]),
        hex::encode(&previous_srv[..8]),
    );

    Ok(ConsensusData {
        current_srv,
        previous_srv,
        hsdir_nodes,
    })
}

/// Fetch and parse the consensus from Tor's control port.
///
/// Returns the parsed consensus data with HSDir nodes and SRV values.
pub async fn fetch_consensus(
    tor: &mut crate::tor::control::TorController,
) -> Result<ConsensusData> {
    info!("Fetching consensus from Tor control port...");
    let raw = tor.get_info("dir/status-vote/current/consensus").await?;

    if raw.len() < 1000 {
        bail!(
            "Consensus response too small ({} bytes), Tor may not have a consensus yet",
            raw.len()
        );
    }

    // Strip control protocol prefix: "250+dir/status-vote/current/consensus=\r\n"
    // The GETINFO response includes this as the first line
    let consensus_text = if let Some(pos) = raw.find("network-status-version") {
        &raw[pos..]
    } else {
        info!(
            "Consensus response first 200 chars: {:?}",
            &raw[..std::cmp::min(200, raw.len())]
        );
        &raw
    };

    info!(
        "Got consensus: {} bytes raw, {} bytes after prefix strip, parsing...",
        raw.len(),
        consensus_text.len()
    );
    parse_consensus(consensus_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hsdir_index_deterministic() {
        let identity = [42u8; 32];
        let srv = [1u8; 32];
        let idx1 = compute_hsdir_index(&identity, &srv, 20492, 1440);
        let idx2 = compute_hsdir_index(&identity, &srv, 20492, 1440);
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn test_compute_hsdir_index_varies_by_srv() {
        let identity = [42u8; 32];
        let srv1 = [1u8; 32];
        let srv2 = [2u8; 32];
        let idx1 = compute_hsdir_index(&identity, &srv1, 20492, 1440);
        let idx2 = compute_hsdir_index(&identity, &srv2, 20492, 1440);
        assert_ne!(idx1, idx2, "Different SRVs must produce different indices");
    }

    #[test]
    fn test_compute_hs_index_deterministic() {
        let blinded = [99u8; 32];
        let idx1 = compute_hs_index(&blinded, 1, 20492, 1440);
        let idx2 = compute_hs_index(&blinded, 1, 20492, 1440);
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn test_compute_hs_index_varies_by_replica() {
        let blinded = [99u8; 32];
        let idx1 = compute_hs_index(&blinded, 1, 20492, 1440);
        let idx2 = compute_hs_index(&blinded, 2, 20492, 1440);
        assert_ne!(
            idx1, idx2,
            "Different replicas must produce different indices"
        );
    }

    #[test]
    fn test_parse_consensus_minimal() {
        // Minimal consensus with 2 HSDir nodes
        // Note: Base64 values must be canonical (zero trailing bits, correct length)
        // 32 bytes = 43 base64 chars + "=" padding (44 total)
        // 20 bytes (RSA identity) = 27 base64 chars (Tor omits "=" padding)
        let consensus = "\
network-status-version 3
vote-status consensus
shared-rand-previous-value 9 AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
shared-rand-current-value 9 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
r relay1 AAAAAAAAAAAAAAAAAAAAAAAAAAA 2024-01-01 00:00:00 1.2.3.4 9001 0
id ed25519 AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
s Fast Guard HSDir Running Stable V2Dir Valid
r relay2 BAQEBAQEBAQEBAQEBAQEBAQEBAQ 2024-01-01 00:00:00 5.6.7.8 9001 0
id ed25519 AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
s Fast HSDir Running Stable V2Dir Valid
r relay3 BAQEBAQEBAQEBAQEBAQEBAQEBAQ 2024-01-01 00:00:00 9.10.11.12 9001 0
s Fast Running Stable
";

        let result = parse_consensus(consensus).unwrap();
        // Two relays have HSDir flag
        assert_eq!(result.hsdir_nodes.len(), 2);
        // Third relay doesn't have HSDir flag, should not be included
        assert!(result.current_srv != [0u8; 32]);
        assert!(result.previous_srv != [0u8; 32]);
    }

    #[test]
    fn test_responsible_hsdirs_count() {
        // Create a synthetic consensus with enough nodes
        let mut hsdir_nodes = Vec::new();
        for i in 0u8..20 {
            let mut identity = [0u8; 32];
            identity[0] = i;
            hsdir_nodes.push(HsDirNode {
                rsa_fingerprint: format!("{:02X}{}", i, "0".repeat(38)),
                ed25519_identity: identity,
            });
        }

        let consensus = ConsensusData {
            current_srv: [1u8; 32],
            previous_srv: [2u8; 32],
            hsdir_nodes,
        };

        let blinded = [99u8; 32];
        let hsdirs = compute_responsible_hsdirs(&consensus, &blinded, true, 20492);

        // Should have HSDIR_N_REPLICAS * HSDIR_SPREAD_STORE = 2 * 4 = 8 unique HSDirs
        // (could be less if some nodes overlap between replicas)
        assert!(
            hsdirs.len() <= (HSDIR_N_REPLICAS as usize * HSDIR_SPREAD_STORE),
            "Too many HSDirs: {}",
            hsdirs.len()
        );
        assert!(
            hsdirs.len() >= HSDIR_SPREAD_STORE,
            "Too few HSDirs: {}",
            hsdirs.len()
        );

        // All fingerprints should be unique
        let unique: std::collections::HashSet<_> = hsdirs.iter().collect();
        assert_eq!(unique.len(), hsdirs.len(), "HSDirs should be unique");
    }
}
