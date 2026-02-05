# Development Setup

## Prerequisites

### Required
- Rust 1.75.0 or later (`rustup update stable`)
- WireGuard tools (`apt install wireguard-tools`)
- Tor daemon with ControlPort enabled

### Optional (for full testing)
- Two VPS instances (for multi-node tests)
- cargo-deny (`cargo install cargo-deny`)
- cargo-audit (`cargo install cargo-audit`)

## Quick Start

```bash
# Clone
git clone https://github.com/nespartious/RustBalance.git
cd RustBalance

# Install pre-commit hook
cp scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Build
cargo build

# Run checks
cargo fmt --all
cargo clippy --all-features
cargo test
cargo deny check
```

## Development Workflow

### 1. Before Starting Work
```bash
git checkout main
git pull
git checkout -b feature/my-feature
```

### 2. While Developing
```bash
# After each logical change
cargo check
cargo test

# Before committing (or use pre-commit hook)
cargo fmt --all
cargo clippy --all-features -- -D warnings
```

### 3. Before PR
```bash
# Full check suite
cargo fmt --all -- --check
cargo clippy --all-features -- -D warnings
cargo test
cargo deny check
cargo audit
cargo doc --no-deps
```

## Testing with Real Tor

### Setup Local Tor for Testing
```bash
# Install Tor
sudo apt install tor

# Configure control port
sudo tee -a /etc/tor/torrc << EOF
ControlPort 9051
CookieAuthentication 1
EOF

sudo systemctl restart tor
```

### Test Control Port Connection
```bash
# Should connect successfully
nc -v 127.0.0.1 9051

# Manual auth (in netcat session)
AUTHENTICATE
250 OK
GETINFO version
```

## Debugging

### Enable Trace Logging
```bash
RUST_LOG=rustbalance=trace cargo run
```

### Log Levels
- `error` - Critical failures
- `warn` - Handled problems
- `info` - State changes
- `debug` - Diagnostic info
- `trace` - Everything

### Common Issues

| Issue | Solution |
|-------|----------|
| "Connection refused" on 9051 | Start Tor: `sudo systemctl start tor` |
| "Authentication failed" | Check `CookieAuthentication` in torrc |
| "WireGuard interface not found" | Install wireguard-tools, check permissions |
| Clippy failures | Run `cargo clippy --fix` for auto-fixes |

## Project Structure

```
src/
├── main.rs           # Entry point, CLI parsing
├── lib.rs            # Library exports
├── logging.rs        # Tracing setup
├── balance/          # Core load balancing
│   ├── backend.rs    # Backend state machine
│   ├── health.rs     # Health checking
│   ├── merge.rs      # Descriptor merging
│   └── publish.rs    # Descriptor publishing
├── config/           # Configuration
│   ├── file.rs       # TOML loading
│   └── validation.rs # Config validation
├── coord/            # Coordination
│   ├── election.rs   # Publisher election
│   ├── lease.rs      # Lease management
│   ├── messages.rs   # Protocol messages
│   └── wireguard.rs  # WG transport
├── crypto/           # Cryptography
│   ├── blinding.rs   # v3 key blinding
│   └── keys.rs       # Key management
├── repair/           # Self-repair
│   ├── actions.rs    # Repair action types
│   └── restart.rs    # Service restart
├── scheduler/        # Task orchestration
│   └── loops.rs      # Main loops
├── state/            # Runtime state
│   └── model.rs      # State model
├── tor/              # Tor interaction
│   ├── control.rs    # Control port client
│   ├── descriptors.rs# Descriptor parsing
│   └── hsdir.rs      # HSDir logic
└── util/             # Helpers
    ├── rand.rs       # Secure random
    └── time.rs       # Time utilities
```

## Adding Dependencies

Before adding any crate:

1. **Verify it exists**: `cargo search <crate>`
2. **Check last update**: Look at crates.io page
3. **Check security**: `cargo audit` after adding
4. **Add to CONTRIBUTING.md**: Update verified crate list
5. **Consider alternatives**: Is std library sufficient?

## Testing Strategy

### Unit Tests
Located next to code (`#[cfg(test)]` modules):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_something() {
        // ...
    }
}
```

### Integration Tests
In `tests/` directory:
```
tests/
├── control_port.rs   # Tor control tests (require running Tor)
├── election.rs       # Multi-node election tests
└── descriptor.rs     # Descriptor parse/build tests
```

Run specific test:
```bash
cargo test test_something
cargo test --test control_port  # Run integration test file
```
