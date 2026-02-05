//! RustBalance library crate
//!
//! Core components for Onion Service load balancing with self-healing.
//!
//! # Modules
//!
//! - [`cli`] - Command-line interface (init, join, status)
//! - [`config`] - Configuration loading and validation
//! - [`crypto`] - Ed25519 key management and v3 blinding
//! - [`tor`] - Tor control port and descriptor handling  
//! - [`balance`] - Backend health, descriptor merging, publishing
//! - [`coord`] - WireGuard coordination and lease election
//! - [`repair`] - Self-repair actions (restart, recovery)
//! - [`scheduler`] - Async task orchestration
//! - [`state`] - Runtime state management
//! - [`util`] - Time, randomization, helpers

// Allow common stylistic patterns during development.
// These can be tightened as the codebase matures.
#![allow(dead_code)] // Many functions are scaffolded but not yet called
#![allow(clippy::unused_async)] // Async functions may need await later
#![allow(clippy::unnecessary_wraps)] // Result wrapping for future error handling
#![allow(clippy::missing_const_for_fn)] // Const fn optimization is low priority
#![allow(clippy::doc_markdown)] // Doc formatting is secondary
#![allow(clippy::uninlined_format_args)] // Format string style preference
#![allow(clippy::cast_lossless)] // Explicit casts are fine
#![allow(clippy::unused_self)] // Methods may use self later
#![allow(clippy::unwrap_used)] // Allow unwrap during development
#![allow(clippy::expect_used)] // Allow expect during development
#![allow(clippy::option_if_let_else)] // Style preference
#![allow(clippy::manual_abs_diff)] // Explicit diff is clear
#![allow(clippy::cast_sign_loss)] // Controlled context
#![allow(clippy::cast_possible_wrap)] // Controlled context
#![allow(clippy::format_push_string)] // Clarity over allocation
#![allow(clippy::collection_is_never_read)] // Scaffolding code
#![allow(clippy::use_self)] // Explicit types are clearer
#![allow(clippy::needless_borrows_for_generic_args)] // Style preference
#![allow(clippy::useless_format)] // Will clean up later
#![allow(clippy::significant_drop_tightening)] // Lock scope is intentional
#![allow(clippy::explicit_auto_deref)] // Explicit derefs are clearer
#![allow(clippy::single_char_pattern)] // String patterns for consistency
#![allow(clippy::explicit_iter_loop)] // Explicit iter is clearer
#![allow(clippy::needless_continue)] // Explicit continue is clearer
#![allow(clippy::single_match_else)] // Match for clarity
#![allow(clippy::items_after_statements)] // Local imports are fine
#![allow(clippy::unnecessary_debug_formatting)] // Debug format for paths
#![allow(clippy::new_without_default)] // Explicit new() is fine
#![allow(clippy::match_wildcard_for_single_variants)] // Wildcard for future
#![allow(clippy::or_fun_call)] // or_insert is clearer
#![allow(clippy::redundant_closure_for_method_calls)] // Explicit closures
#![allow(clippy::range_plus_one)] // Explicit ranges are clearer
#![allow(clippy::inefficient_to_string)] // Clarity over micro-optimization
#![allow(clippy::case_sensitive_file_extension_comparisons)] // Intentional
#![allow(clippy::map_unwrap_or)] // map().unwrap_or is clearer
#![allow(clippy::too_many_arguments)] // Some functions need many args
#![allow(clippy::too_many_lines)] // Some functions are complex
#![allow(clippy::debug_assert_with_mut_call)] // Development use

pub mod balance;
pub mod cli;
pub mod config;
pub mod coord;
pub mod crypto;
pub mod logging;
pub mod repair;
pub mod scheduler;
pub mod state;
pub mod tor;
pub mod util;

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
