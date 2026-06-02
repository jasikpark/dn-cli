use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::config::Config;

/// Minimal clean-room client for the Defined Networking REST API.
///
/// Endpoints are version-prefixed (`/v1/`, `/v2/`) per-verb; callers pass the
/// full versioned path. This tracer exposes reads only; writes and deletes are
/// a deliberate later phase gated behind confirmation + permission rules.
pub struct Client {
    config: Config,
}

impl Client {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// GET a versioned path and return the parsed JSON body.
    pub fn get(&self, path: &str) -> Result<Value> {
        let url = format!("{}{}", self.config.api_url, path);
        let auth = format!("Bearer {}", self.config.api_key);

        match ureq::get(&url).header("Authorization", &auth).call() {
            Ok(mut res) => res
                .body_mut()
                .read_json::<Value>()
                .context("failed to parse Defined API response as JSON"),
            Err(ureq::Error::StatusCode(code)) => {
                bail!("Defined API responded with HTTP {code}")
            }
            Err(err) => Err(err).context("request to Defined API failed"),
        }
    }

    pub fn list_hosts(&self) -> Result<Value> {
        // TODO(write-phase): add ?networkID= filtering once the exact query
        // param is confirmed against the api repo.
        self.get("/v1/hosts")
    }
}
