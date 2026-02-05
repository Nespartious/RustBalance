//! Repair action definitions and execution

use anyhow::Result;
use tracing::{info, warn};

/// Types of repair actions
#[derive(Debug, Clone)]
pub enum RepairAction {
    /// Restart the local Tor daemon
    RestartTor,
    /// Restart a specific backend
    RestartBackend { name: String },
    /// Remove a backend from rotation
    ExcludeBackend { name: String },
    /// Re-include a previously excluded backend
    IncludeBackend { name: String },
    /// Force republish descriptor
    ForceRepublish,
    /// Step down from publisher role
    StepDown,
}

/// Execute a repair action
pub async fn execute_repair(action: &RepairAction) -> Result<()> {
    match action {
        RepairAction::RestartTor => {
            info!("Executing repair: restart Tor");
            super::restart::restart_tor().await
        },
        RepairAction::RestartBackend { name } => {
            info!("Executing repair: restart backend {}", name);
            super::restart::restart_backend(name).await
        },
        RepairAction::ExcludeBackend { name } => {
            info!("Executing repair: exclude backend {}", name);
            // Handled at state level
            Ok(())
        },
        RepairAction::IncludeBackend { name } => {
            info!("Executing repair: include backend {}", name);
            // Handled at state level
            Ok(())
        },
        RepairAction::ForceRepublish => {
            info!("Executing repair: force republish");
            // Handled at scheduler level
            Ok(())
        },
        RepairAction::StepDown => {
            warn!("Executing repair: stepping down from publisher");
            // Handled at coordinator level
            Ok(())
        },
    }
}

/// Determine repair action for a failure
pub fn diagnose(failure: &str) -> Option<RepairAction> {
    // Simple heuristics - can be expanded
    if failure.contains("tor") || failure.contains("control port") {
        return Some(RepairAction::RestartTor);
    }
    if failure.contains("descriptor") {
        return Some(RepairAction::ForceRepublish);
    }
    None
}
