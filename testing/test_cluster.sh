#!/bin/bash
# RustBalance Test Runner
# Runs a full integration test of the two-node cluster

set -e

# Configuration - set these before running
VM1_IP="${VM1_IP:-}"
VM2_IP="${VM2_IP:-}"
SSH_USER="${SSH_USER:-ubuntu}"
SSH_KEY="${SSH_KEY:-}"
BACKEND_ONION="${BACKEND_ONION:-dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[TEST]${NC} $1"; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }

# SSH command builder
ssh_cmd() {
    local host=$1
    shift
    if [ -n "$SSH_KEY" ]; then
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$SSH_USER@$host" "$@"
    else
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$SSH_USER@$host" "$@"
    fi
}

# Check prerequisites
check_prereqs() {
    step "Checking prerequisites..."
    
    [ -z "$VM1_IP" ] && fail "VM1_IP not set"
    [ -z "$VM2_IP" ] && fail "VM2_IP not set"
    
    log "VM1: $VM1_IP"
    log "VM2: $VM2_IP"
    log "User: $SSH_USER"
    log "Backend: $BACKEND_ONION"
}

# Test SSH connectivity
test_ssh() {
    step "Testing SSH connectivity..."
    
    ssh_cmd "$VM1_IP" "echo 'VM1 SSH OK'" || fail "Cannot SSH to VM1"
    pass "VM1 SSH connected"
    
    ssh_cmd "$VM2_IP" "echo 'VM2 SSH OK'" || fail "Cannot SSH to VM2"
    pass "VM2 SSH connected"
}

# Test inter-VM connectivity
test_network() {
    step "Testing inter-VM network..."
    
    ssh_cmd "$VM1_IP" "ping -c 2 $VM2_IP" || fail "VM1 cannot ping VM2"
    pass "VM1 -> VM2 connectivity OK"
    
    ssh_cmd "$VM2_IP" "ping -c 2 $VM1_IP" || fail "VM2 cannot ping VM1"
    pass "VM2 -> VM1 connectivity OK"
}

# Deploy to both VMs
deploy() {
    step "Deploying to VM1..."
    ssh_cmd "$VM1_IP" "curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | bash"
    pass "VM1 deployed"
    
    step "Deploying to VM2..."
    ssh_cmd "$VM2_IP" "curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | bash"
    pass "VM2 deployed"
}

# Initialize cluster on VM1
init_cluster() {
    step "Initializing cluster on VM1..."
    
    # Run init and capture token
    local output=$(ssh_cmd "$VM1_IP" "cd ~/rustbalance && ./target/release/rustbalance init --endpoint $VM1_IP:51820 2>&1")
    echo "$output"
    
    # Extract join token
    JOIN_TOKEN=$(echo "$output" | grep -oP 'rb1:[A-Za-z0-9+/=]+' | head -1)
    
    if [ -z "$JOIN_TOKEN" ]; then
        fail "Could not extract join token from init output"
    fi
    
    log "Join token: ${JOIN_TOKEN:0:50}..."
    pass "Cluster initialized"
}

# Join cluster from VM2
join_cluster() {
    step "Joining cluster from VM2..."
    
    ssh_cmd "$VM2_IP" "cd ~/rustbalance && ./target/release/rustbalance join '$JOIN_TOKEN' --endpoint $VM2_IP:51820"
    pass "VM2 joined cluster"
}

# Verify WireGuard tunnel
verify_wireguard() {
    step "Verifying WireGuard tunnel..."
    
    # Check WireGuard on VM1
    local wg1=$(ssh_cmd "$VM1_IP" "sudo wg show wg0 2>/dev/null || echo 'not configured'")
    echo "VM1 WireGuard: $wg1"
    
    # Check WireGuard on VM2
    local wg2=$(ssh_cmd "$VM2_IP" "sudo wg show wg0 2>/dev/null || echo 'not configured'")
    echo "VM2 WireGuard: $wg2"
    
    # Ping over WireGuard
    ssh_cmd "$VM1_IP" "ping -c 2 10.99.0.2" && pass "WireGuard tunnel working" || warn "WireGuard ping failed"
}

# Add backend
add_backend() {
    step "Adding backend: $BACKEND_ONION..."
    
    ssh_cmd "$VM1_IP" "cd ~/rustbalance && ./target/release/rustbalance backend add --name dread --address $BACKEND_ONION"
    pass "Backend added"
}

# Start RustBalance on both nodes
start_nodes() {
    step "Starting RustBalance on VM1 (background)..."
    ssh_cmd "$VM1_IP" "cd ~/rustbalance && nohup ./target/release/rustbalance run > ~/rustbalance.log 2>&1 &"
    sleep 2
    
    step "Starting RustBalance on VM2 (background)..."
    ssh_cmd "$VM2_IP" "cd ~/rustbalance && nohup ./target/release/rustbalance run > ~/rustbalance.log 2>&1 &"
    sleep 2
    
    pass "Both nodes started"
}

# Check logs
check_logs() {
    step "VM1 recent logs:"
    ssh_cmd "$VM1_IP" "tail -20 ~/rustbalance.log 2>/dev/null || echo 'No logs yet'"
    
    step "VM2 recent logs:"
    ssh_cmd "$VM2_IP" "tail -20 ~/rustbalance.log 2>/dev/null || echo 'No logs yet'"
}

# Cleanup
cleanup() {
    step "Cleaning up both VMs..."
    
    ssh_cmd "$VM1_IP" "cd ~/rustbalance/testing && bash deploy.sh --clean" || true
    ssh_cmd "$VM2_IP" "cd ~/rustbalance/testing && bash deploy.sh --clean" || true
    
    pass "Cleanup complete"
}

# Status check
status() {
    step "Cluster status..."
    
    ssh_cmd "$VM1_IP" "cd ~/rustbalance && ./target/release/rustbalance status 2>/dev/null || echo 'Not running'"
    ssh_cmd "$VM2_IP" "cd ~/rustbalance && ./target/release/rustbalance status 2>/dev/null || echo 'Not running'"
}

# Main test sequence
main() {
    echo "=========================================="
    echo "    RustBalance Integration Test"
    echo "=========================================="
    echo ""
    
    case "${1:-full}" in
        check)
            check_prereqs
            test_ssh
            test_network
            ;;
        deploy)
            check_prereqs
            deploy
            ;;
        init)
            check_prereqs
            init_cluster
            ;;
        join)
            check_prereqs
            join_cluster
            ;;
        start)
            check_prereqs
            start_nodes
            ;;
        logs)
            check_prereqs
            check_logs
            ;;
        status)
            check_prereqs
            status
            ;;
        cleanup)
            check_prereqs
            cleanup
            ;;
        full)
            check_prereqs
            test_ssh
            test_network
            deploy
            init_cluster
            join_cluster
            verify_wireguard
            add_backend
            start_nodes
            sleep 5
            check_logs
            status
            ;;
        *)
            echo "Usage: $0 {check|deploy|init|join|start|logs|status|cleanup|full}"
            exit 1
            ;;
    esac
    
    echo ""
    echo "=========================================="
    echo "              TEST COMPLETE"
    echo "=========================================="
}

main "$@"
