use std::fmt;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::config::Config;

/// Minimal client for the Defined Networking REST API.
///
/// Endpoints are version-prefixed (`/v1/`, `/v2/`) per-verb; callers pass the
/// full versioned path. This tracer exposes reads only; writes and deletes are
/// a deliberate later phase gated behind confirmation + permission rules.
pub struct Client {
    config: Config,
    agent: ureq::Agent,
}

/// A non-2xx response from the Defined API, carried as a typed error so the
/// `--json` (agent) path can serialize the structured fields rather than a
/// flattened string. `Display` is the human (stderr) rendering.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub errors: Vec<ApiErrorDetail>,
    /// Raw body, kept only when it wasn't the expected `{errors:[...]}` shape
    /// (e.g. an upstream proxy 502 or an empty 401), so agents still have
    /// something to inspect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// One entry from the Defined API error envelope: `{ code, message, path? }`.
#[derive(Debug, Serialize)]
pub struct ApiErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl ApiError {
    fn from_response(status: u16, body: &str, request_id: Option<String>) -> Self {
        let errors = serde_json::from_str::<Value>(body)
            .ok()
            .as_ref()
            .and_then(|v| v.get("errors"))
            .and_then(Value::as_array)
            .map(|arr| arr.iter().map(ApiErrorDetail::from_value).collect::<Vec<_>>())
            .unwrap_or_default();

        // Only fall back to the raw body when we couldn't extract any structured
        // errors — otherwise it's redundant with `errors`.
        let raw = if errors.is_empty() {
            let trimmed = body.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        } else {
            None
        };

        ApiError { status, request_id, errors, raw }
    }
}

impl ApiErrorDetail {
    fn from_value(value: &Value) -> Self {
        ApiErrorDetail {
            code: value
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("ERR_UNKNOWN")
                .to_string(),
            message: value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("(no message)")
                .to_string(),
            path: value.get("path").and_then(Value::as_str).map(str::to_owned),
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Defined API error (HTTP {})", self.status)?;

        if self.errors.is_empty() {
            match &self.raw {
                Some(raw) => write!(f, ": {raw}")?,
                None => write!(f, ": (no response body)")?,
            }
        } else {
            for err in &self.errors {
                match &err.path {
                    Some(path) => write!(f, "\n  {}: {} [{}]", err.code, err.message, path)?,
                    None => write!(f, "\n  {}: {}", err.code, err.message)?,
                }
            }
        }

        if let Some(id) = &self.request_id {
            write!(f, "\n  request id: {id}")?;
        }

        Ok(())
    }
}

impl std::error::Error for ApiError {}

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
        Err(ApiError::from_response(status.as_u16(), &body, request_id).into())
    }

    pub fn list_hosts(&self) -> Result<Value> {
        // TODO(write-phase): add ?networkID= filtering once the exact query
        // param is confirmed against the api repo.
        self.get("/v1/hosts")
    }
}
