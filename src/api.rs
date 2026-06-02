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
    agent: ureq::Agent,
}

impl Client {
    pub fn new(config: Config) -> Self {
        // Disable ureq's default "non-2xx is an Error::StatusCode" behavior so
        // error responses arrive as Ok(_) and we can read the DN error body
        // (Error::StatusCode carries only the numeric code, never the body).
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        Self { config, agent }
    }

    /// GET a versioned path and return the parsed JSON body.
    pub fn get(&self, path: &str) -> Result<Value> {
        let url = format!("{}{}", self.config.api_url, path);
        let auth = format!("Bearer {}", self.config.api_key);

        let mut res = self
            .agent
            .get(&url)
            .header("Authorization", &auth)
            .call()
            .context("request to Defined API failed")?;

        let status = res.status();
        // x-request-id is worth surfacing on errors — it's the handle support
        // uses to find the request server-side.
        let request_id = res
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        if status.is_success() {
            return res
                .body_mut()
                .read_json::<Value>()
                .context("failed to parse Defined API response as JSON");
        }

        let body = res.body_mut().read_to_string().unwrap_or_default();
        bail!("{}", format_api_error(status.as_u16(), &body, request_id.as_deref()));
    }

    pub fn list_hosts(&self) -> Result<Value> {
        // TODO(write-phase): add ?networkID= filtering once the exact query
        // param is confirmed against the api repo.
        self.get("/v1/hosts")
    }
}

/// Render a Defined API error response into a human-readable message.
///
/// The DN error envelope is `{ "errors": [{ "code", "message", "path"? }] }`
/// (see <https://github.com/DefinedNet/api> webclient `src/api/errors.ts`).
/// Falls back to the raw body when the response isn't that shape (e.g. an
/// upstream proxy 502 or an empty 401).
fn format_api_error(status: u16, body: &str, request_id: Option<&str>) -> String {
    use std::fmt::Write;

    let mut msg = format!("Defined API error (HTTP {status})");

    let parsed = serde_json::from_str::<Value>(body).ok();
    let errors = parsed
        .as_ref()
        .and_then(|v| v.get("errors"))
        .and_then(Value::as_array)
        .filter(|errors| !errors.is_empty());

    match errors {
        Some(errors) => {
            for err in errors {
                let code = err.get("code").and_then(Value::as_str).unwrap_or("ERR_UNKNOWN");
                let message = err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("(no message)");
                match err.get("path").and_then(Value::as_str) {
                    Some(path) => {
                        let _ = write!(msg, "\n  {code}: {message} [{path}]");
                    }
                    None => {
                        let _ = write!(msg, "\n  {code}: {message}");
                    }
                }
            }
        }
        None => {
            let detail = body.trim();
            let detail = if detail.is_empty() { "(no response body)" } else { detail };
            let _ = write!(msg, ": {detail}");
        }
    }

    if let Some(id) = request_id {
        let _ = write!(msg, "\n  request id: {id}");
    }

    msg
}
