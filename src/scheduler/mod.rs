//! Task scheduling and main loops
//!
//! Orchestrates all async tasks: polling, heartbeats, publishing.
//! All tokio::spawn calls live here.

mod loops;

pub use loops::run;
