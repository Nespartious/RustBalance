#!/bin/bash
#==============================================================================
# RustBalance VM Deployment Script
#==============================================================================
#
# Automates complete RustBalance deployment on fresh Ubuntu VMs.
#
# QUICK START:
# -------------
#   First node:   curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | sudo bash -s -- --init --target TARGET.onion --endpoint YOUR_IP:51820
#   Join node:    curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | sudo bash -s -- --join --target TARGET.onion --master-onion MASTER.onion --master-key "KEY" --peer-endpoint IP:PORT --peer-pubkey "PUBKEY" --cluster-token "TOKEN" --join-secret "SECRET"
#
# WHAT IT DOES:
# -------------
#   1. Installs dependencies (Tor, WireGuard, Rust toolchain)
#   2. Clones and builds RustBalance from GitHub
#   3. Generates cryptographic keys (master key, WireGuard keys)
#   4. Configures Tor hidden service with master key
#   5. Sets up WireGuard mesh interface
#   6. Creates systemd service for auto-start
#   7. Outputs join command for additional nodes
#
# CLUSTER TOKEN:
# --------------
#   Generated automatically on --init, required for --join.
#   Authenticates nodes joining the mesh.
#
# MESH SELF-HEALING:
# ------------------
#   Nodes discover each other via gossip protocol.
#   No manual peer management needed after initial setup.
#
#==============================================================================

set -e

REPO_URL="https://github.com/Nespartious/RustBalance.git"
REPO_BRANCH="feature/separate-node-addresses"  # Branch to clone (testing feature branch)
INSTALL_DIR="$HOME/rustbalance"
CONFIG_DIR="/etc/rustbalance"
# DEPRECATED: Legacy HS dir for master key (no longer used in multi-node mode)
HS_DIR="/var/lib/tor/rustbalance_hs"
# Node-specific HS dir - Tor creates a UNIQUE address here for each node
NODE_HS_DIR="/var/lib/tor/rustbalance_node_hs"
LOG_FILE="$HOME/rustbalance_deploy.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

# Parse arguments
CLEAN=false
INIT=false
JOIN=false
TARGET_ONION=""
ENDPOINT=""
MASTER_ONION=""
MASTER_KEY=""
PEER_ENDPOINT=""
PEER_PUBKEY=""
NODE_PRIORITY=10
CLUSTER_TOKEN=""
JOIN_SECRET=""

print_usage() {
    echo "Usage:"
    echo "  First node:  $0 --init --target TARGET.onion --endpoint YOUR_IP:51820"
    echo "  Join node:   $0 --join --target TARGET.onion --master-onion MASTER.onion \\"
    echo "                  --master-key BASE64_KEY --peer-endpoint IP:PORT --peer-pubkey PUBKEY \\"
    echo "                  --cluster-token TOKEN --join-secret SECRET"
    echo ""
    echo "Options:"
    echo "  --clean           Clean previous deployment"
    echo "  --init            Initialize first node (generates master key)"
    echo "  --join            Join existing cluster"
    echo "  --target          Target onion address to reverse proxy to"
    echo "  --endpoint        This node's WireGuard endpoint (IP:PORT)"
    echo "  --master-onion    Master onion address (for --join)"
    echo "  --master-key      Base64 encoded master key (for --join)"
    echo "  --peer-endpoint   First node's WireGuard endpoint (for --join)"
    echo "  --peer-pubkey     First node's WireGuard public key (for --join)"
    echo "  --cluster-token   Cluster authentication token (for --join)"
    echo "  --join-secret     Join secret for Tor Bootstrap Channel (for --join)"
    echo "  --priority        Node priority, lower = higher priority (default: 10)"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=true
            shift
            ;;
        --init)
            INIT=true
            shift
            ;;
        --join)
            JOIN=true
            shift
            ;;
        --target)
            TARGET_ONION="$2"
            shift 2
            ;;
        --endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        --master-onion)
            MASTER_ONION="$2"
            shift 2
            ;;
        --master-key)
            MASTER_KEY="$2"
            shift 2
            ;;
        --peer-endpoint)
            PEER_ENDPOINT="$2"
            shift 2
            ;;
        --peer-pubkey)
            PEER_PUBKEY="$2"
            shift 2
            ;;
        --priority)
            NODE_PRIORITY="$2"
            shift 2
            ;;
        --cluster-token)
            CLUSTER_TOKEN="$2"
            shift 2
            ;;
        --join-secret)
            JOIN_SECRET="$2"
            shift 2
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Validate arguments
validate_args() {
    if [ "$INIT" = true ] && [ "$JOIN" = true ]; then
        error "Cannot use both --init and --join"
    fi
    
    if [ "$INIT" = true ]; then
        if [ -z "$TARGET_ONION" ]; then
            error "--target is required for --init"
        fi
        if [ -z "$ENDPOINT" ]; then
            warn "--endpoint not provided. WireGuard will be configured but peer connections require endpoint."
            ENDPOINT="YOUR_IP:51820"
        fi
    fi
    
    if [ "$JOIN" = true ]; then
        if [ -z "$TARGET_ONION" ]; then
            error "--target is required for --join"
        fi
        if [ -z "$MASTER_ONION" ]; then
            error "--master-onion is required for --join"
        fi
        if [ -z "$MASTER_KEY" ]; then
            error "--master-key is required for --join"
        fi
        if [ -z "$PEER_ENDPOINT" ]; then
            error "--peer-endpoint is required for --join"
        fi
        if [ -z "$PEER_PUBKEY" ]; then
            error "--peer-pubkey is required for --join"
        fi
    fi
}

# Clean function - removes all RustBalance artifacts
clean() {
    log "Cleaning previous deployment..."
    
    # Stop RustBalance if running
    sudo systemctl stop rustbalance 2>/dev/null || true
    sudo systemctl disable rustbalance 2>/dev/null || true
    pkill -f rustbalance 2>/dev/null || true
    
    # Remove systemd service
    sudo rm -f /etc/systemd/system/rustbalance.service
    sudo systemctl daemon-reload 2>/dev/null || true
    
    # Remove WireGuard interface
    if ip link show wg-rb &>/dev/null; then
        log "Removing WireGuard interface wg-rb..."
        sudo ip link delete wg-rb 2>/dev/null || true
    fi
    
    # Remove hidden service directories
    if [ -d "$HS_DIR" ]; then
        log "Removing legacy hidden service directory..."
        sudo rm -rf "$HS_DIR"
    fi
    
    if [ -d "$NODE_HS_DIR" ]; then
        log "Removing node hidden service directory..."
        sudo rm -rf "$NODE_HS_DIR"
    fi
    
    # Remove config directory
    if [ -d "$CONFIG_DIR" ]; then
        log "Removing config directory..."
        sudo rm -rf "$CONFIG_DIR"
    fi
    
    # Remove RustBalance directory
    if [ -d "$INSTALL_DIR" ]; then
        log "Removing $INSTALL_DIR..."
        rm -rf "$INSTALL_DIR"
    fi
    
    log "Cleanup complete!"
}

# Install system dependencies
install_deps() {
    log "Installing system dependencies..."
    
    # Force IPv4 for apt to avoid IPv6 connectivity issues
    log "Configuring apt to use IPv4 only..."
    echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null
    
    log "Updating package lists..."
    sudo apt-get update || {
        warn "apt-get update had some failures, retrying..."
        sleep 5
        sudo apt-get update
    }
    
    log "Installing packages (this may take a few minutes)..."
    sudo apt-get install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        tor \
        wireguard-tools \
        curl \
        git
    
    log "System dependencies installed"
}

# Install Rust if not present
install_rust() {
    if command -v rustc &>/dev/null; then
        log "Rust already installed: $(rustc --version)"
        return
    fi
    
    log "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    log "Rust installed: $(rustc --version)"
}

# Configure Tor for RustBalance
configure_tor() {
    log "Configuring Tor..."
    
    # Backup original torrc
    sudo cp /etc/tor/torrc /etc/tor/torrc.backup 2>/dev/null || true
    
    # Ensure SocksPort is enabled
    if ! grep -q "^SocksPort 9050" /etc/tor/torrc; then
        log "Adding SocksPort..."
        echo "SocksPort 9050" | sudo tee -a /etc/tor/torrc
    fi
    
    # Uncomment or add ControlPort
    sudo sed -i 's/^#ControlPort 9051/ControlPort 9051/' /etc/tor/torrc
    if ! grep -q "^ControlPort 9051" /etc/tor/torrc; then
        log "Adding Tor ControlPort..."
        echo "ControlPort 9051" | sudo tee -a /etc/tor/torrc
    fi
    
    # Uncomment or add CookieAuthentication
    sudo sed -i 's/^#CookieAuthentication 1/CookieAuthentication 1/' /etc/tor/torrc
    if ! grep -q "^CookieAuthentication 1" /etc/tor/torrc; then
        log "Adding CookieAuthentication..."
        echo "CookieAuthentication 1" | sudo tee -a /etc/tor/torrc
    fi
    
    # Restart Tor (handles both tor and tor@default service styles)
    sudo systemctl restart tor@default 2>/dev/null || sudo systemctl restart tor
    sleep 3
    
    # Verify Tor control port is listening
    if ss -tlnp | grep -q ":9051"; then
        log "Tor control port 9051 is listening"
    else
        warn "Tor control port may not be listening"
        sudo systemctl status tor@default 2>/dev/null || sudo systemctl status tor
    fi
    
    # Make sure cookie is readable by root
    if [ -f /run/tor/control.authcookie ]; then
        sudo chmod 640 /run/tor/control.authcookie
        log "Tor cookie file configured"
    fi
    
    log "Tor configured"
}

# Setup hidden service directories with correct ownership
setup_hs_directory() {
    log "Setting up hidden service directories..."
    
    # Create legacy directory (for backward compatibility, unused in multi-node)
    sudo mkdir -p "$HS_DIR"
    sudo chown -R debian-tor:debian-tor "$HS_DIR"
    sudo chmod 700 "$HS_DIR"
    
    # Create node-specific HS directory - Tor will generate a UNIQUE keypair here
    # This gives each node its own .onion address, separate from the master
    sudo mkdir -p "$NODE_HS_DIR"
    sudo chown -R debian-tor:debian-tor "$NODE_HS_DIR"
    sudo chmod 700 "$NODE_HS_DIR"
    
    log "Hidden service directories created:"
    log "  Legacy (unused): $HS_DIR"
    log "  Node HS:         $NODE_HS_DIR"
}

# Clone and build RustBalance
build_rustbalance() {
    log "Cloning RustBalance repository (branch: $REPO_BRANCH)..."
    
    if [ -d "$INSTALL_DIR" ]; then
        cd "$INSTALL_DIR"
        git fetch origin
        git checkout "$REPO_BRANCH"
        git pull origin "$REPO_BRANCH"
    else
        git clone -b "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
    
    log "Building RustBalance (release mode)..."
    source "$HOME/.cargo/env"
    cargo build --release
    
    # Copy binary to system path
    sudo cp "$INSTALL_DIR/target/release/rustbalance" /usr/local/bin/
    sudo chmod +x /usr/local/bin/rustbalance
    
    log "Build complete: /usr/local/bin/rustbalance"
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service..."
    
    sudo tee /etc/systemd/system/rustbalance.service > /dev/null << 'EOF'
[Unit]
Description=RustBalance - Tor Hidden Service Load Balancer
After=network.target tor@default.service
Wants=tor@default.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rustbalance run
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tor/rustbalance_hs /var/lib/tor/rustbalance_node_hs /etc/rustbalance
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    log "Systemd service created"
}

# Setup WireGuard interface
setup_wireguard() {
    local INTERFACE=$1
    local LISTEN_PORT=$2
    local PRIVATE_KEY=$3
    local TUNNEL_IP=$4
    
    log "Setting up WireGuard interface $INTERFACE..."
    
    # Remove existing interface if present
    if ip link show "$INTERFACE" &>/dev/null; then
        sudo ip link delete "$INTERFACE" 2>/dev/null || true
    fi
    
    # Create interface
    sudo ip link add "$INTERFACE" type wireguard
    
    # Set private key (from config file or direct)
    if [ -f "$PRIVATE_KEY" ]; then
        sudo wg set "$INTERFACE" listen-port "$LISTEN_PORT" private-key "$PRIVATE_KEY"
    else
        echo "$PRIVATE_KEY" | sudo wg set "$INTERFACE" listen-port "$LISTEN_PORT" private-key /dev/stdin
    fi
    
    # Set IP address
    sudo ip addr add "$TUNNEL_IP/24" dev "$INTERFACE"
    
    # Bring interface up
    sudo ip link set "$INTERFACE" up
    
    log "WireGuard interface $INTERFACE configured with IP $TUNNEL_IP"
}

# Add WireGuard peer
add_wireguard_peer() {
    local INTERFACE=$1
    local PEER_PUBKEY=$2
    local PEER_ENDPOINT=$3
    local PEER_ALLOWED_IPS=$4
    
    log "Adding WireGuard peer..."
    
    if [ -n "$PEER_ENDPOINT" ]; then
        sudo wg set "$INTERFACE" peer "$PEER_PUBKEY" endpoint "$PEER_ENDPOINT" allowed-ips "$PEER_ALLOWED_IPS" persistent-keepalive 25
    else
        sudo wg set "$INTERFACE" peer "$PEER_PUBKEY" allowed-ips "$PEER_ALLOWED_IPS" persistent-keepalive 25
    fi
    
    log "Peer added: $PEER_PUBKEY"
}

# Save WireGuard config for wg-quick (persistence across reboots)
save_wireguard_config() {
    local INTERFACE=$1
    local LISTEN_PORT=$2
    local PRIVATE_KEY=$3
    local TUNNEL_IP=$4
    
    log "Saving WireGuard config for persistence..."
    
    sudo tee "/etc/wireguard/${INTERFACE}.conf" > /dev/null << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
ListenPort = $LISTEN_PORT
Address = ${TUNNEL_IP}/24
EOF
    
    sudo chmod 600 "/etc/wireguard/${INTERFACE}.conf"
    log "WireGuard config saved to /etc/wireguard/${INTERFACE}.conf"
    log "Enable on boot with: sudo systemctl enable wg-quick@${INTERFACE}"
}

# Add peer to wg-quick config file
add_peer_to_config() {
    local INTERFACE=$1
    local PEER_PUBKEY=$2
    local PEER_ENDPOINT=$3
    local PEER_ALLOWED_IPS=$4
    
    if [ -n "$PEER_ENDPOINT" ]; then
        sudo tee -a "/etc/wireguard/${INTERFACE}.conf" > /dev/null << EOF

[Peer]
PublicKey = $PEER_PUBKEY
Endpoint = $PEER_ENDPOINT
AllowedIPs = $PEER_ALLOWED_IPS
PersistentKeepalive = 25
EOF
    else
        sudo tee -a "/etc/wireguard/${INTERFACE}.conf" > /dev/null << EOF

[Peer]
PublicKey = $PEER_PUBKEY
AllowedIPs = $PEER_ALLOWED_IPS
PersistentKeepalive = 25
EOF
    fi
    
    log "Peer added to WireGuard config"
}

# Initialize RustBalance as first node (generate keys and config)
init_first_node() {
    log "Initializing RustBalance as FIRST NODE..."
    
    # Create config directory
    sudo mkdir -p "$CONFIG_DIR"
    
    # Generate master key (32-byte seed)
    log "Generating master identity key..."
    MASTER_KEY_FILE="$CONFIG_DIR/master.key"
    sudo dd if=/dev/urandom bs=32 count=1 2>/dev/null | sudo tee "$MASTER_KEY_FILE" > /dev/null
    sudo chmod 600 "$MASTER_KEY_FILE"
    
    # Generate WireGuard keypair
    log "Generating WireGuard keypair..."
    WG_PRIVATE=$(wg genkey)
    WG_PUBLIC=$(echo "$WG_PRIVATE" | wg pubkey)
    
    # Save WireGuard private key
    echo "$WG_PRIVATE" | sudo tee "$CONFIG_DIR/wireguard.key" > /dev/null
    sudo chmod 600 "$CONFIG_DIR/wireguard.key"
    
    # Generate node ID
    NODE_ID="node-$(openssl rand -hex 4)"
    
    # Get master key as base64 for join command
    MASTER_KEY_B64=$(sudo base64 -w0 "$MASTER_KEY_FILE")
    
    # Generate cluster token for peer authentication
    CLUSTER_TOKEN_GENERATED=$(openssl rand -hex 32)
    echo "$CLUSTER_TOKEN_GENERATED" | sudo tee "$CONFIG_DIR/cluster_token.txt" > /dev/null
    log "Generated cluster token for peer authentication"
    
    # Generate join_secret for Tor Bootstrap Channel (base64url, 32 bytes = 43 chars)
    JOIN_SECRET_GENERATED=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
    echo "$JOIN_SECRET_GENERATED" | sudo tee "$CONFIG_DIR/join_secret.txt" > /dev/null
    log "Generated join_secret for Tor Bootstrap Channel"
    
    # Derive master onion address (run rustbalance to compute it)
    # For now, we'll let rustbalance compute it on first run
    # We need to create a minimal config first
    
    # Create config file
    log "Creating configuration file..."
    sudo tee "$CONFIG_DIR/config.toml" > /dev/null << EOF
# RustBalance Configuration
# Generated by deploy.sh --init

# Root-level settings
local_port = 8080
# DEPRECATED: Legacy field, kept for backward compatibility
hidden_service_dir = "/var/lib/tor/rustbalance_hs"

[node]
id = "$NODE_ID"
priority = $NODE_PRIORITY
clock_skew_tolerance_secs = 5
# Node-specific HS directory - Tor generates a UNIQUE address here
# Each node has its own .onion, publisher merges intro points for master
hidden_service_dir = "/var/lib/tor/rustbalance_node_hs"

[master]
onion_address = "PENDING_FIRST_RUN"
identity_key_path = "$MASTER_KEY_FILE"

[target]
onion_address = "$TARGET_ONION"
port = 80

[tor]
control_host = "127.0.0.1"
control_port = 9051
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
mode = "wireguard"
heartbeat_interval_secs = 10
heartbeat_timeout_secs = 30
lease_duration_secs = 60
backoff_jitter_secs = 15
cluster_token = "$CLUSTER_TOKEN_GENERATED"
join_secret = "$JOIN_SECRET_GENERATED"

[wireguard]
interface = "wg-rb"
listen_port = 51820
tunnel_ip = "10.200.200.1"
private_key = "$WG_PRIVATE"
public_key = "$WG_PUBLIC"
external_endpoint = "$ENDPOINT"
peers = []
EOF

    # Compute master onion address by running rustbalance
    log "Computing master onion address..."
    MASTER_ONION=$(/usr/local/bin/rustbalance debug show-onion --key "$MASTER_KEY_FILE" 2>/dev/null || echo "")
    
    if [ -z "$MASTER_ONION" ] || [ "$MASTER_ONION" = "" ]; then
        warn "Could not compute master onion address - will be set on first run"
        MASTER_ONION="PENDING_FIRST_RUN"
    else
        log "Master onion address: $MASTER_ONION"
    fi
    
    # Update config with actual onion address
    if [ "$MASTER_ONION" != "PENDING_FIRST_RUN" ] && [ -n "$MASTER_ONION" ]; then
        sudo sed -i "s/PENDING_FIRST_RUN/$MASTER_ONION/" "$CONFIG_DIR/config.toml"
        # Save master onion for easy retrieval
        echo "$MASTER_ONION" | sudo tee "$CONFIG_DIR/master_onion.txt" > /dev/null
    fi
    
    # Setup WireGuard interface
    setup_wireguard "wg-rb" 51820 "$WG_PRIVATE" "10.200.200.1"
    
    # Save persistent wg-quick config
    save_wireguard_config "wg-rb" 51820 "$WG_PRIVATE" "10.200.200.1"
    
    # Enable WireGuard on boot
    sudo systemctl enable wg-quick@wg-rb 2>/dev/null || true
    
    log "First node initialized!"
    
    # Display join command for additional nodes
    echo ""
    echo -e "${CYAN}=========================================="
    echo "     JOIN COMMAND FOR ADDITIONAL NODES"
    echo "==========================================${NC}"
    echo ""
    echo -e "${YELLOW}⚠  IMPORTANT: Wait for Node 1's hidden service to be reachable${NC}"
    echo -e "${YELLOW}   before deploying additional nodes!${NC}"
    echo ""
    echo "Run this command on each additional node to join the cluster:"
    echo ""
    if [ "$MASTER_ONION" != "PENDING_FIRST_RUN" ]; then
        echo -e "${GREEN}curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | sudo bash -s -- \\"
        echo "  --join \\"
        echo "  --target $TARGET_ONION \\"
        echo "  --master-onion \"$MASTER_ONION\" \\"
        echo "  --master-key \"$MASTER_KEY_B64\" \\"
        echo "  --peer-endpoint \"$ENDPOINT\" \\"
        echo "  --peer-pubkey \"$WG_PUBLIC\" \\"
        echo "  --cluster-token \"$CLUSTER_TOKEN_GENERATED\" \\"
        echo "  --join-secret \"$JOIN_SECRET_GENERATED\"${NC}"
    else
        echo -e "${GREEN}curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | sudo bash -s -- \\"
        echo "  --join \\"
        echo "  --target $TARGET_ONION \\"
        echo "  --master-onion \"\$(sudo cat $CONFIG_DIR/master_onion.txt)\" \\"
        echo "  --master-key \"$MASTER_KEY_B64\" \\"
        echo "  --peer-endpoint \"$ENDPOINT\" \\"
        echo "  --peer-pubkey \"$WG_PUBLIC\" \\"
        echo "  --cluster-token \"$CLUSTER_TOKEN_GENERATED\" \\"
        echo "  --join-secret \"$JOIN_SECRET_GENERATED\"${NC}"
    fi
    echo ""
    echo "Or if you already have the binary, run:"
    echo ""
    echo -e "${GREEN}sudo ./deploy.sh --join \\"
    echo "  --target $TARGET_ONION \\"
    echo "  --master-onion \"$MASTER_ONION\" \\"
    echo "  --master-key \"$MASTER_KEY_B64\" \\"
    echo "  --peer-endpoint \"$ENDPOINT\" \\"
    echo "  --peer-pubkey \"$WG_PUBLIC\" \\"
    echo "  --cluster-token \"$CLUSTER_TOKEN_GENERATED\" \\"
    echo "  --join-secret \"$JOIN_SECRET_GENERATED\"${NC}"
    echo ""
    echo -e "${YELLOW}IMPORTANT: The service will auto-start after deployment.${NC}"
    echo "The script will wait for the hidden service to become reachable."
    echo ""
    
    # Save join info for easy retrieval
    sudo tee "$CONFIG_DIR/join_info.txt" > /dev/null << EOF
# RustBalance Join Information
# Generated: $(date)
# 
# Give this information to operators of additional nodes.
#
# ═══════════════════════════════════════════════════════════════════════════
#  ⚠  CRITICAL: WAIT FOR NODE 1 TO BE FULLY OPERATIONAL BEFORE JOINING!
# ═══════════════════════════════════════════════════════════════════════════
#
# Before running the join command on a new node:
#   1. Verify Node 1's hidden service is reachable in Tor Browser
#   2. Visit: http://$MASTER_ONION
#   3. If it loads (even with error page), you can proceed
#
# Tor hidden services typically take 2-5 minutes to become reachable after
# first starting. The Tor Bootstrap Channel requires Node 1 to be reachable
# via Tor for new nodes to automatically exchange WireGuard credentials.
#
# ═══════════════════════════════════════════════════════════════════════════
# 
# READY-TO-RUN COMMAND (copy and paste on new node):

curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | sudo bash -s -- \\
  --join \\
  --target "$TARGET_ONION" \\
  --master-onion "$MASTER_ONION" \\
  --master-key "$MASTER_KEY_B64" \\
  --peer-endpoint "$ENDPOINT" \\
  --peer-pubkey "$WG_PUBLIC" \\
  --cluster-token "$CLUSTER_TOKEN_GENERATED" \\
  --join-secret "$JOIN_SECRET_GENERATED"

# Individual values:
TARGET_ONION=$TARGET_ONION
MASTER_ONION=$MASTER_ONION
MASTER_KEY_B64=$MASTER_KEY_B64
PEER_ENDPOINT=$ENDPOINT
PEER_PUBKEY=$WG_PUBLIC
CLUSTER_TOKEN=$CLUSTER_TOKEN_GENERATED
JOIN_SECRET=$JOIN_SECRET_GENERATED

# After the new node joins, it will display its WireGuard public key.
# The mesh self-heals via gossip - no manual peer addition needed!
EOF

    # Also save a script version for easy execution
    sudo tee "$CONFIG_DIR/join_command.sh" > /dev/null << EOF
#!/bin/bash
# Run this script on a new node to join this RustBalance cluster
curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | bash -s -- \\
  --join \\
  --target "$TARGET_ONION" \\
  --master-onion "$MASTER_ONION" \\
  --master-key "$MASTER_KEY_B64" \\
  --peer-endpoint "$ENDPOINT" \\
  --peer-pubkey "$WG_PUBLIC" \\
  --cluster-token "$CLUSTER_TOKEN_GENERATED" \\
  --join-secret "$JOIN_SECRET_GENERATED"
EOF
    sudo chmod +x "$CONFIG_DIR/join_command.sh"
    
    echo "Join info saved to: $CONFIG_DIR/join_info.txt"
    echo "Ready-to-run script: $CONFIG_DIR/join_command.sh"
    echo ""
}

# Join existing cluster as additional node
join_cluster() {
    log "Joining RustBalance cluster as ADDITIONAL NODE..."
    
    # Create config directory
    sudo mkdir -p "$CONFIG_DIR"
    
    # Decode and save master key
    log "Saving master key..."
    MASTER_KEY_FILE="$CONFIG_DIR/master.key"
    echo "$MASTER_KEY" | base64 -d | sudo tee "$MASTER_KEY_FILE" > /dev/null
    sudo chmod 600 "$MASTER_KEY_FILE"
    
    # Generate WireGuard keypair for this node
    log "Generating WireGuard keypair..."
    WG_PRIVATE=$(wg genkey)
    WG_PUBLIC=$(echo "$WG_PRIVATE" | wg pubkey)
    
    # Save WireGuard private key
    echo "$WG_PRIVATE" | sudo tee "$CONFIG_DIR/wireguard.key" > /dev/null
    sudo chmod 600 "$CONFIG_DIR/wireguard.key"
    
    # Generate node ID
    NODE_ID="node-$(openssl rand -hex 4)"
    
    # Determine tunnel IP (increment from .1)
    # For simplicity, use .2 for second node, .3 for third, etc.
    # In production, this should be coordinated
    TUNNEL_IP="10.200.200.$((NODE_PRIORITY % 254 + 1))"
    
    # Parse peer endpoint
    PEER_IP=$(echo "$PEER_ENDPOINT" | cut -d: -f1)
    PEER_PORT=$(echo "$PEER_ENDPOINT" | cut -d: -f2)
    
    # Determine our external endpoint for mesh gossip
    OUR_IP=$(hostname -I | awk '{print $1}')
    OUR_ENDPOINT="${OUR_IP}:51820"
    log "Our external endpoint for gossip: $OUR_ENDPOINT"
    
    # Create config file
    log "Creating configuration file..."
    sudo tee "$CONFIG_DIR/config.toml" > /dev/null << EOF
# RustBalance Configuration
# Generated by deploy.sh --join

# Root-level settings
local_port = 8080
# DEPRECATED: Legacy field, kept for backward compatibility
hidden_service_dir = "/var/lib/tor/rustbalance_hs"

[node]
id = "$NODE_ID"
priority = $NODE_PRIORITY
clock_skew_tolerance_secs = 5
# Node-specific HS directory - Tor generates a UNIQUE address here
# Each node has its own .onion, publisher merges intro points for master
hidden_service_dir = "/var/lib/tor/rustbalance_node_hs"

[master]
onion_address = "$MASTER_ONION"
identity_key_path = "$MASTER_KEY_FILE"

[target]
onion_address = "$TARGET_ONION"
port = 80

[tor]
control_host = "127.0.0.1"
control_port = 9051
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
mode = "wireguard"
heartbeat_interval_secs = 10
heartbeat_timeout_secs = 30
lease_duration_secs = 60
backoff_jitter_secs = 15
cluster_token = "$CLUSTER_TOKEN"
join_secret = "$JOIN_SECRET"

[wireguard]
interface = "wg-rb"
listen_port = 51820
tunnel_ip = "$TUNNEL_IP"
private_key = "$WG_PRIVATE"
public_key = "$WG_PUBLIC"
external_endpoint = "$OUR_ENDPOINT"

[[wireguard.peers]]
id = "node-first"
endpoint = "$PEER_ENDPOINT"
tunnel_ip = "10.200.200.1"
public_key = "$PEER_PUBKEY"
EOF

    # Setup WireGuard interface
    setup_wireguard "wg-rb" 51820 "$WG_PRIVATE" "$TUNNEL_IP"
    
    # Add first node as peer
    add_wireguard_peer "wg-rb" "$PEER_PUBKEY" "$PEER_ENDPOINT" "10.200.200.0/24"
    
    # Save persistent wg-quick config
    save_wireguard_config "wg-rb" 51820 "$WG_PRIVATE" "$TUNNEL_IP"
    add_peer_to_config "wg-rb" "$PEER_PUBKEY" "$PEER_ENDPOINT" "10.200.200.0/24"
    
    # Enable WireGuard on boot
    sudo systemctl enable wg-quick@wg-rb 2>/dev/null || true

    log "Node configured to join cluster!"
    
    # Display info for mesh self-healing
    echo ""
    echo -e "${CYAN}=========================================="
    echo "       NODE READY TO JOIN CLUSTER"
    echo "==========================================${NC}"
    echo ""
    echo -e "${YELLOW}This node's WireGuard public key:${NC}"
    echo "  $WG_PUBLIC"
    echo ""
    echo -e "${YELLOW}This node's tunnel IP:${NC}"
    echo "  $TUNNEL_IP"
    echo ""
    echo -e "${YELLOW}This node's external endpoint:${NC}"
    echo "  $OUR_ENDPOINT"
    echo ""
    echo -e "${GREEN}✓ Mesh self-healing is enabled!${NC}"
    echo "  Once RustBalance starts, this node will be discovered by other nodes"
    echo "  via the gossip protocol. No manual peer addition required."
    echo ""
    echo -e "${YELLOW}For manual peer addition (optional), on the FIRST node run:${NC}"
    echo ""
    echo -e "${GREEN}sudo wg set wg-rb peer \"$WG_PUBLIC\" endpoint \"$OUR_ENDPOINT\" allowed-ips \"$TUNNEL_IP/32\" persistent-keepalive 25${NC}"
    echo ""
    echo "Then restart RustBalance:"
    echo "  sudo systemctl restart rustbalance"
    echo ""
}

# Wait for hidden service to become reachable via Tor
wait_for_hidden_service() {
    local ONION_ADDRESS=$1
    local MAX_WAIT=${2:-300}  # Default 5 minutes
    local CHECK_INTERVAL=10
    local ELAPSED=0
    
    echo ""
    echo -e "${CYAN}=========================================="
    echo "    WAITING FOR HIDDEN SERVICE TO GO LIVE"
    echo "==========================================${NC}"
    echo ""
    echo -e "${YELLOW}Onion address: ${NC}$ONION_ADDRESS"
    echo -e "${YELLOW}Max wait time: ${NC}${MAX_WAIT} seconds"
    echo ""
    
    # Wait for Tor to bootstrap first
    log "Waiting for Tor to fully bootstrap..."
    sleep 5
    
    while [ $ELAPSED -lt $MAX_WAIT ]; do
        # Check if hostname file exists and has content (in node HS dir, not legacy)
        if [ ! -f "$NODE_HS_DIR/hostname" ]; then
            echo -e "  [${ELAPSED}s] Waiting for node hostname file..."
            sleep $CHECK_INTERVAL
            ELAPSED=$((ELAPSED + CHECK_INTERVAL))
            continue
        fi
        
        echo -e "  [${ELAPSED}s] Checking descriptor publication status..."
        
        # Primary check: Tor logs showing descriptor upload
        # This is the authoritative indicator that the HS is ready
        if sudo journalctl -u tor@default --since "5 minutes ago" 2>/dev/null | grep -q "Uploaded rendezvous descriptor"; then
            echo ""
            echo -e "${GREEN}✓ HIDDEN SERVICE DESCRIPTOR PUBLISHED!${NC}"
            echo -e "  Descriptor has been uploaded to HSDir nodes."
            echo -e "  The hidden service should be reachable within 30-60 seconds."
            echo ""
            return 0
        fi
        
        # Secondary check: RustBalance intro point establishment
        if sudo journalctl -u rustbalance --since "2 minutes ago" 2>/dev/null | grep -qE "intro.*point|introduction point|Intro points"; then
            if [ $ELAPSED -ge 30 ]; then
                echo ""
                echo -e "${GREEN}✓ INTRO POINTS ESTABLISHED!${NC}"
                echo -e "  RustBalance has established introduction points."
                echo -e "  Descriptor should be propagating across HSDir nodes..."
                echo ""
                return 0
            fi
        fi
        
        # Tertiary check: RustBalance shows hidden service configured
        if sudo journalctl -u rustbalance --since "2 minutes ago" 2>/dev/null | grep -q "Hidden service hostname:"; then
            if [ $ELAPSED -ge 60 ]; then
                echo ""
                echo -e "${GREEN}✓ HIDDEN SERVICE CONFIGURED!${NC}"
                echo -e "  Hidden service is set up, waiting for descriptor propagation..."
                echo ""
                return 0
            fi
        fi
        
        sleep $CHECK_INTERVAL
        ELAPSED=$((ELAPSED + CHECK_INTERVAL))
    done
    
    echo ""
    echo -e "${YELLOW}⚠ Timeout waiting for hidden service descriptor${NC}"
    echo "This may be normal - Tor hidden services can take several minutes to propagate."
    echo "Check Tor logs: sudo journalctl -u tor@default -f"
    echo "Check RustBalance logs: sudo journalctl -u rustbalance -f"
    echo ""
    return 1
}

# Start RustBalance and verify it's working
start_and_verify() {
    log "Starting RustBalance service..."
    
    # Enable and start the service
    sudo systemctl enable rustbalance
    sudo systemctl start rustbalance
    
    # Wait a moment for it to start
    sleep 3
    
    # Check if it's running
    if ! sudo systemctl is-active --quiet rustbalance; then
        error "RustBalance failed to start! Check logs: sudo journalctl -u rustbalance -e"
    fi
    
    log "RustBalance service is running"
    
    # Wait for the hidden service to be configured
    # In multi-node mode, Tor creates the NODE's unique address in NODE_HS_DIR
    log "Waiting for Tor to configure node hidden service..."
    local WAITED=0
    while [ $WAITED -lt 60 ]; do
        if [ -f "$NODE_HS_DIR/hostname" ]; then
            NODE_ONION=$(sudo cat "$NODE_HS_DIR/hostname" 2>/dev/null)
            if [ -n "$NODE_ONION" ]; then
                log "This node's onion address: $NODE_ONION"
                
                # Update config with master onion if it's still PENDING
                # (master onion is derived from master key, not from hostname file)
                if grep -q "PENDING_FIRST_RUN" "$CONFIG_DIR/config.toml" 2>/dev/null; then
                    # Try to compute master onion from key
                    MASTER_COMPUTED=$(/usr/local/bin/rustbalance debug show-onion --key "$MASTER_KEY_FILE" 2>/dev/null || echo "")
                    if [ -n "$MASTER_COMPUTED" ]; then
                        log "Updating config with master onion: $MASTER_COMPUTED"
                        sudo sed -i "s/PENDING_FIRST_RUN/$MASTER_COMPUTED/" "$CONFIG_DIR/config.toml"
                        echo "$MASTER_COMPUTED" | sudo tee "$CONFIG_DIR/master_onion.txt" > /dev/null
                        
                        # Update join_info.txt with actual master onion address
                        if [ -f "$CONFIG_DIR/join_info.txt" ]; then
                            sudo sed -i "s/PENDING_FIRST_RUN/$MASTER_COMPUTED/g" "$CONFIG_DIR/join_info.txt"
                            sudo sed -i "s/MASTER_ONION=PENDING_FIRST_RUN/MASTER_ONION=$MASTER_COMPUTED/g" "$CONFIG_DIR/join_info.txt"
                        fi
                    fi
                fi
                break
            fi
        fi
        sleep 2
        WAITED=$((WAITED + 2))
    done
    
    if [ -z "$ACTUAL_ONION" ] || [ "$ACTUAL_ONION" = "" ]; then
        warn "Could not read hidden service hostname after 60 seconds"
        ACTUAL_ONION="UNKNOWN"
    fi
    
    echo "$ACTUAL_ONION"
}

# Show status
show_status() {
    echo ""
    echo -e "${CYAN}=========================================="
    echo "         DEPLOYMENT STATUS"
    echo "==========================================${NC}"
    echo ""
    echo "RustBalance binary: /usr/local/bin/rustbalance"
    echo "Config directory:   $CONFIG_DIR"
    echo "Node HS directory:  $NODE_HS_DIR"
    echo ""
    
    TOR_STATUS=$(sudo systemctl is-active tor@default 2>/dev/null || sudo systemctl is-active tor 2>/dev/null || echo "unknown")
    echo "Tor status: $TOR_STATUS"
    echo "Tor control port: $(ss -tlnp 2>/dev/null | grep -q ':9051' && echo 'listening' || echo 'not listening')"
    echo ""
    
    RB_STATUS=$(sudo systemctl is-active rustbalance 2>/dev/null || echo "not running")
    echo -e "RustBalance status: ${GREEN}$RB_STATUS${NC}"
    echo ""
    
    if [ -f "$CONFIG_DIR/config.toml" ]; then
        MASTER_ONION_CFG=$(grep "^onion_address" "$CONFIG_DIR/config.toml" | head -1 | cut -d'"' -f2)
        echo "Master onion (config): $MASTER_ONION_CFG"
    fi
    
    # In multi-node mode, node address is different from master
    if [ -f "$NODE_HS_DIR/hostname" ]; then
        NODE_ONION=$(sudo cat "$NODE_HS_DIR/hostname" 2>/dev/null || echo "not yet generated")
        echo -e "This node's .onion:  ${GREEN}$NODE_ONION${NC}"
    fi
    echo ""
    
    # Show WireGuard status
    echo "WireGuard interface:"
    sudo wg show wg-rb 2>/dev/null | head -10 || echo "  Not configured"
    echo ""
    
    echo "=========================================="
    echo "              USEFUL COMMANDS"
    echo "=========================================="
    echo ""
    echo "View logs:      sudo journalctl -u rustbalance -f"
    echo "Service status: sudo systemctl status rustbalance"
    echo "WireGuard:      sudo wg show"
    echo ""
    if [ "$INIT" = true ]; then
        echo "Join info:      cat $CONFIG_DIR/join_info.txt"
        echo ""
    fi
    echo "=========================================="
    echo ""
}

# Main
main() {
    echo "" > "$LOG_FILE"
    log "RustBalance Deployment Script"
    log "=============================="
    
    # Validate arguments if doing init or join
    if [ "$INIT" = true ] || [ "$JOIN" = true ]; then
        validate_args
    fi
    
    # Handle --clean flag
    if [ "$CLEAN" = true ]; then
        clean
        if [ "$INIT" = false ] && [ "$JOIN" = false ]; then
            exit 0
        fi
    fi
    
    # Full deployment
    install_deps
    install_rust
    configure_tor
    setup_hs_directory
    build_rustbalance
    create_systemd_service
    
    # Initialize or join based on mode
    if [ "$INIT" = true ]; then
        init_first_node
        
        # Auto-start and wait for hidden service
        echo ""
        log "Auto-starting RustBalance and waiting for hidden service..."
        ACTUAL_ONION=$(start_and_verify)
        
        # Wait for hidden service to be reachable
        if [ -n "$ACTUAL_ONION" ] && [ "$ACTUAL_ONION" != "UNKNOWN" ]; then
            wait_for_hidden_service "$ACTUAL_ONION" 300
        fi
        
        # Show final join info
        echo ""
        echo -e "${CYAN}=========================================="
        echo "       NODE 1 DEPLOYMENT COMPLETE!"
        echo "==========================================${NC}"
        echo ""
        if [ -n "$ACTUAL_ONION" ] && [ "$ACTUAL_ONION" != "UNKNOWN" ]; then
            echo -e "${GREEN}✓ Master onion address: $ACTUAL_ONION${NC}"
        fi
        echo ""
        echo -e "${YELLOW}IMPORTANT: Before deploying additional nodes:${NC}"
        echo "1. Verify this hidden service is reachable in Tor Browser"
        echo "2. Test: Visit http://$ACTUAL_ONION in Tor Browser"
        echo "3. Once confirmed working, proceed to deploy node 2"
        echo ""
        echo "Join info for additional nodes:"
        echo "  cat $CONFIG_DIR/join_info.txt"
        echo ""
        
    elif [ "$JOIN" = true ]; then
        join_cluster
        
        echo ""
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}  ⚠  CRITICAL: VERIFY NODE 1 BEFORE PROCEEDING!${NC}"
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "Before this node can join the cluster via Tor Bootstrap Channel,"
        echo "Node 1 MUST be fully operational and its hidden service reachable."
        echo ""
        echo -e "${CYAN}To verify Node 1 is ready:${NC}"
        echo "  1. Open Tor Browser"
        echo "  2. Visit: http://$MASTER_ONION"
        echo "  3. If it loads (even with an error), Node 1 is ready"
        echo ""
        echo -e "${GREEN}Once Node 1 is verified, start this node:${NC}"
        echo "  sudo systemctl enable --now rustbalance"
        echo ""
        echo -e "${CYAN}Then monitor the logs:${NC}"
        echo "  sudo journalctl -u rustbalance -f"
        echo ""
        echo "You should see:"
        echo "  - 'Attempting to join cluster via $MASTER_ONION'"
        echo "  - 'Join successful' or similar"
        echo "  - Heartbeats from Node 1"
        echo ""
        
        # Auto-start (no interactive prompt - doesn't work with curl pipe)
        log "Auto-starting RustBalance..."
        ACTUAL_ONION=$(start_and_verify)
        
        # Monitor for join success
        echo ""
        echo -e "${CYAN}Monitoring for cluster join (30 seconds)...${NC}"
        echo ""
        timeout 30 sudo journalctl -u rustbalance -f --since "now" 2>/dev/null || true
        echo ""
    fi
    
    show_status
    
    log "Deployment complete!"
}

main
