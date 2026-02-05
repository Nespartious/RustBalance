#!/bin/bash
# Test script to run on VM1 to verify RustBalance can fetch and decrypt descriptors

set -e

cd /root/RustBalance

echo "=== Building RustBalance ==="
cargo build --release 2>&1 | tail -5

echo ""
echo "=== Testing descriptor fetch and decrypt ==="
# Run a simple test that fetches the local backend's descriptor

# First, check if Tor is running and the HS is configured
if systemctl is-active --quiet tor; then
    echo "Tor is running"
else
    echo "ERROR: Tor is not running"
    exit 1
fi

# Get the onion address
ONION_DIR="/var/lib/tor/backend_hs"
if [ -f "$ONION_DIR/hostname" ]; then
    ONION_ADDR=$(cat "$ONION_DIR/hostname")
    echo "Backend onion address: $ONION_ADDR"
else
    echo "ERROR: No hostname file found at $ONION_DIR/hostname"
    exit 1
fi

# Get the public key
if [ -f "$ONION_DIR/hs_ed25519_public_key" ]; then
    echo "Public key file exists"
    xxd "$ONION_DIR/hs_ed25519_public_key" | head -3
else
    echo "ERROR: No public key file"
    exit 1
fi

echo ""
echo "=== Running RustBalance test ==="
# Export the onion address for the test config
export RUSTBALANCE_BACKEND_ONION="$ONION_ADDR"

# Run cargo test for descriptor functionality
cargo test test_decrypt -- --nocapture 2>&1 | tail -50 || true

echo ""
echo "=== Done ==="
