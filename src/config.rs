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
            anyhow!(
                "DEFINED_API_KEY is not set.\n\
                 `op run` injects it only when the name is mapped to a 1Password secret \
                 reference — bare `op run -- dn ...` won't. Set it up once:\n\
                 \n    cp .env.example .env   # maps DEFINED_API_KEY to an op:// reference\
                 \n    op run --env-file=.env -- dn hosts list   # or: just run hosts list\n\
                 \nOr export it directly: export DEFINED_API_KEY=\"op://<vault>/<item>/credential\""
            )
        })?;
        let api_url =
            std::env::var("DEFINED_API_URL").unwrap_or_else(|_| DEFAULT_API_URL.to_string());
        Ok(Self { api_key, api_url })
    }
}
