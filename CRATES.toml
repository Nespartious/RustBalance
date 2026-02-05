# Verified Crate Registry
# 
# This file tracks all external dependencies with verification status.
# Before adding a crate, verify it exists on crates.io and check:
# 1. Last update date (warn if > 1 year)
# 2. Download count (prefer popular crates)
# 3. Maintenance status
# 4. Security history
#
# Format:
# [crate_name]
# version = "x.y"
# verified_date = "YYYY-MM-DD"
# crates_io_url = "https://crates.io/crates/..."
# last_updated = "YYYY-MM-DD"  # From crates.io
# notes = "Why we use this"

[tokio]
version = "1.35"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/tokio"
notes = "Industry standard async runtime"

[serde]
version = "1.0"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/serde"
notes = "De-facto serialization framework"

[serde_json]
version = "1.0"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/serde_json"
notes = "JSON serialization for coordination messages"

[toml]
version = "0.8"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/toml"
notes = "TOML config file parsing"

[ed25519-dalek]
version = "2.1"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/ed25519-dalek"
notes = "Ed25519 signatures for Tor identity keys"

[x25519-dalek]
version = "2.0"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/x25519-dalek"
notes = "X25519 ECDH for key exchange in join protocol"

[curve25519-dalek]
version = "4.1"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/curve25519-dalek"
notes = "Low-level curve operations for key blinding"

[sha2]
version = "0.10"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/sha2"
notes = "SHA-256/512 hashing"

[sha3]
version = "0.10"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/sha3"
notes = "SHA3-256 for Tor subcredential derivation"

[rand]
version = "0.8"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/rand"
notes = "Cryptographically secure randomness"

[aes-gcm]
version = "0.10"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/aes-gcm"
notes = "AES-GCM encryption for master key in join tokens"

[base64]
version = "0.22"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/base64"
notes = "Base64 encoding for tokens and descriptors"

[data-encoding]
version = "2.5"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/data-encoding"
notes = "Base32 encoding for onion addresses"

[socket2]
version = "0.5"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/socket2"
notes = "Low-level socket options for UDP"

[chrono]
version = "0.4"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/chrono"
notes = "Time handling with timezone support"

[tracing]
version = "0.1"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/tracing"
notes = "Structured logging framework"

[tracing-subscriber]
version = "0.3"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/tracing-subscriber"
notes = "Log output formatting"

[thiserror]
version = "1.0"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/thiserror"
notes = "Derive macro for error types"

[anyhow]
version = "1.0"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/anyhow"
notes = "Flexible error handling for applications"

[clap]
version = "4.4"
verified_date = "2026-02-02"
crates_io_url = "https://crates.io/crates/clap"
notes = "Command-line argument parsing"

# ----- REJECTED CRATES -----

[torut]
status = "REJECTED"
reason = "Unmaintained since 2021. Implementing Tor control protocol directly instead."
alternative = "Direct implementation in src/tor/control.rs"
