//! Configuration file loading

use super::Config;
use anyhow::{Context, Result};
use std::path::Path;

/// Default config file locations
const CONFIG_PATHS: &[&str] = &["/etc/rustbalance/config.toml", "./config.toml"];

/// Load configuration from file
pub fn load_config() -> Result<Config> {
    // Check command line arg first
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 {
        args[1].clone()
    } else {
        find_config_file()?
    };

    load_from_path(&config_path)
}

/// Find first existing config file
fn find_config_file() -> Result<String> {
    for path in CONFIG_PATHS {
        if Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    anyhow::bail!("No configuration file found. Tried: {:?}", CONFIG_PATHS)
}

/// Load and parse config from path
pub fn load_from_path(path: &str) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path))?;

    let config: Config = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse config file: {}", path))?;

    super::validate(&config)?;

    Ok(config)
}
