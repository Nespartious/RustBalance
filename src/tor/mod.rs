//! Tor daemon interaction
//!
//! Handles Tor ControlPort communication, descriptor fetching,
//! and HSDir publishing. Tor is treated as a black box.

pub mod control;
pub mod descriptors;
pub mod hsdir;

pub use control::TorController;
pub use descriptors::{HsDescriptor, IntroductionPoint, LinkSpecifier};
