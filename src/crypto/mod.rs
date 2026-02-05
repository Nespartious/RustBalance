//! Cryptographic primitives for v3 Onion Services
//!
//! Handles Ed25519 key management and v3 descriptor blinding.
//! All crypto operations are isolated here - no IO allowed.

#![allow(unused_imports)] // Re-exports for public API

pub mod blinding;
pub mod descriptor;
pub mod keys;

pub use blinding::{blind_identity, blind_private_key, current_time_period, derive_subcredential};
pub use descriptor::{decrypt_layer, DescriptorBuilder, DescriptorOutput};
pub use keys::{load_identity_key, pubkey_from_onion_address, MasterIdentity};
