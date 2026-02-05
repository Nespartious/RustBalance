//! Self-repair actions
//!
//! Local recovery operations when failures are detected.

#![allow(unused_imports)] // Re-exports for public API

pub mod actions;
pub mod restart;

pub use actions::{execute_repair, RepairAction};
