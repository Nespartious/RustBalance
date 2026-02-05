//! Backend management command
//!
//! Add, remove, and list backend onion services.

use super::{BackendAction, BackendAddArgs, BackendArgs, BackendRemoveArgs};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

/// Run the backend command
pub async fn run_backend(config_dir: &Path, args: &BackendArgs) -> Result<()> {
    match &args.action {
        BackendAction::Add(add_args) => add_backend(config_dir, add_args).await,
        BackendAction::Remove(remove_args) => remove_backend(config_dir, remove_args).await,
        BackendAction::List => list_backends(config_dir).await,
    }
}

/// Add a backend to the configuration
async fn add_backend(config_dir: &Path, args: &BackendAddArgs) -> Result<()> {
    let config_path = config_dir.join("config.toml");

    if !config_path.exists() {
        bail!(
            "Configuration not found at {:?}. Run 'rustbalance init' or 'rustbalance join' first.",
            config_path
        );
    }

    // Validate onion address format
    let address = args.address.trim().to_lowercase();
    if !is_valid_onion_v3(&address) {
        bail!(
            "Invalid v3 onion address: {}. Must be 56 characters + '.onion'",
            address
        );
    }

    // Read current config
    let config_content = fs::read_to_string(&config_path).context("Failed to read config")?;
    let mut config: toml::Value =
        toml::from_str(&config_content).context("Failed to parse config")?;

    // Get or create backends array
    let backends = config
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("Invalid config format"))?
        .entry("backends")
        .or_insert_with(|| toml::Value::Array(Vec::new()));

    let backends_array = backends
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("backends is not an array"))?;

    // Check if already exists
    for backend in backends_array.iter() {
        if let Some(addr) = backend.get("onion_address").and_then(|v| v.as_str()) {
            if addr == address {
                println!("⚠️  Backend {} already exists", address);
                return Ok(());
            }
        }
    }

    // Create new backend entry
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| format!("backend-{}", backends_array.len() + 1));

    let mut backend_table = toml::map::Map::new();
    backend_table.insert("name".to_string(), toml::Value::String(name.clone()));
    backend_table.insert(
        "onion_address".to_string(),
        toml::Value::String(address.clone()),
    );

    backends_array.push(toml::Value::Table(backend_table));

    // Write back
    let new_content = toml::to_string_pretty(&config).context("Failed to serialize config")?;
    fs::write(&config_path, new_content).context("Failed to write config")?;

    println!("✅ Added backend: {} ({})", name, address);
    println!("   Weight: {}", args.weight);
    println!("\n💡 Restart the daemon to apply changes: rustbalance run");

    Ok(())
}

/// Remove a backend from the configuration
async fn remove_backend(config_dir: &Path, args: &BackendRemoveArgs) -> Result<()> {
    let config_path = config_dir.join("config.toml");

    if !config_path.exists() {
        bail!("Configuration not found at {:?}", config_path);
    }

    let config_content = fs::read_to_string(&config_path).context("Failed to read config")?;
    let mut config: toml::Value =
        toml::from_str(&config_content).context("Failed to parse config")?;

    let backends = config
        .as_table_mut()
        .and_then(|t| t.get_mut("backends"))
        .and_then(|v| v.as_array_mut());

    if backends.is_none() {
        println!("No backends configured");
        return Ok(());
    }

    let backends_array = backends.unwrap();
    let search = args.address.trim().to_lowercase();

    let original_len = backends_array.len();

    backends_array.retain(|backend| {
        let addr = backend
            .get("onion_address")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let name = backend.get("name").and_then(|v| v.as_str()).unwrap_or("");

        addr != search && name != search
    });

    if backends_array.len() == original_len {
        println!("⚠️  Backend not found: {}", args.address);
        return Ok(());
    }

    // Write back
    let new_content = toml::to_string_pretty(&config).context("Failed to serialize config")?;
    fs::write(&config_path, new_content).context("Failed to write config")?;

    println!("✅ Removed backend: {}", args.address);
    println!("\n💡 Restart the daemon to apply changes");

    Ok(())
}

/// List all configured backends
async fn list_backends(config_dir: &Path) -> Result<()> {
    let config_path = config_dir.join("config.toml");

    if !config_path.exists() {
        bail!("Configuration not found at {:?}", config_path);
    }

    let config_content = fs::read_to_string(&config_path).context("Failed to read config")?;
    let config: toml::Value = toml::from_str(&config_content).context("Failed to parse config")?;

    let backends = config
        .get("backends")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[]);

    if backends.is_empty() {
        println!("No backends configured");
        println!("\n💡 Add a backend: rustbalance backend add --address <ONION_ADDRESS>");
        return Ok(());
    }

    println!("📋 Configured Backends ({}):\n", backends.len());
    println!("{:<20} {:<62} {:>6}", "NAME", "ADDRESS", "WEIGHT");
    println!("{}", "-".repeat(92));

    for backend in backends {
        let name = backend
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed");
        let address = backend
            .get("onion_address")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let weight = backend
            .get("weight")
            .and_then(|v| v.as_integer())
            .unwrap_or(100);

        println!("{:<20} {:<62} {:>6}", name, address, weight);
    }

    Ok(())
}

/// Validate v3 onion address format
fn is_valid_onion_v3(address: &str) -> bool {
    // v3 onion addresses are 56 base32 characters + ".onion"
    if !address.ends_with(".onion") {
        return false;
    }

    let name = &address[..address.len() - 6];
    if name.len() != 56 {
        return false;
    }

    // Should be valid base32
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() && c.is_ascii_lowercase() || c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_onion_v3() {
        // Valid v3 address (56 chars)
        let valid = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
        assert!(is_valid_onion_v3(valid));

        // Invalid - too short (v2 length)
        let invalid_v2 = "expyuzz4wqqyqhjn.onion";
        assert!(!is_valid_onion_v3(invalid_v2));

        // Invalid - no .onion
        let invalid_no_suffix = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad";
        assert!(!is_valid_onion_v3(invalid_no_suffix));
    }
}
