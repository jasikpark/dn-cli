use anyhow::{Result, anyhow};

/// Runtime configuration, sourced entirely from the environment so the API key
/// can be injected per-invocation via `op run` and never persisted to disk.
pub struct Config {
    pub api_key: String,
    pub api_url: String,
}

const DEFAULT_API_URL: &str = "https://api.defined.net";

impl Config {
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("DEFINED_API_KEY").map_err(|_| {
            anyhow!("DEFINED_API_KEY is not set. Run via `op run -- dn ...`, or export it.")
        })?;
        let api_url =
            std::env::var("DEFINED_API_URL").unwrap_or_else(|_| DEFAULT_API_URL.to_string());
        Ok(Self { api_key, api_url })
    }
}
