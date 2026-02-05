//! Load balancing logic
//!
//! Core RustBalance functionality: hidden service management,
//! reverse proxy, health evaluation, and descriptor publishing.

#![allow(unused_imports)] // Re-exports for public API

pub mod backend;
pub mod bootstrap;
pub mod fetch;
pub mod health;
pub mod join_handler;
pub mod merge;
pub mod onion_service;
pub mod publish;

pub use backend::{Backend, BackendState};
pub use bootstrap::BootstrapClient;
pub use fetch::{DescriptorFetcher, FetchResults};
pub use health::{HealthChecker, HealthStatus};
pub use join_handler::JoinHandler;
pub use merge::DescriptorMerger;
pub use onion_service::{NodeInfo, OnionService};
pub use publish::Publisher;
