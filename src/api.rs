use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};

use crate::config::Config;

const MAX_RETRIES: u32 = 3;

/// Minimal client for the Defined Networking REST API.
///
/// Endpoints are version-prefixed (`/v1/`, `/v2/`) per-verb; callers pass the
/// full versioned path. Every verb reports a non-2xx response as a typed
/// [`ApiError`] rather than a flattened string.
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
            .map(|arr| {
                arr.iter()
                    .map(ApiErrorDetail::from_value)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Only fall back to the raw body when we couldn't extract any structured
        // errors — otherwise it's redundant with `errors`.
        let raw = if errors.is_empty() {
            let trimmed = body.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        } else {
            None
        };

        ApiError {
            status,
            request_id,
            errors,
            raw,
        }
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
            .timeout_global(Some(Duration::from_secs(60)))
            .build()
            .into();
        Self { config, agent }
    }

    fn call_with_retry<F>(&self, send: F) -> Result<ureq::http::Response<ureq::Body>>
    where
        F: Fn() -> Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    {
        for attempt in 0..MAX_RETRIES {
            let res = send().context("request to Defined API failed")?;
            if res.status().as_u16() != 429 {
                return Ok(res);
            }
            let delay = retry_delay(&res, attempt);
            eprintln!(
                "rate limited, retrying in {:.1}s ({}/{MAX_RETRIES})...",
                delay.as_secs_f64(),
                attempt + 1
            );
            std::thread::sleep(delay);
        }
        let res = send().context("request to Defined API failed")?;
        Ok(res)
    }

    /// GET a versioned path and return the parsed JSON body.
    pub fn get(&self, path: &str) -> Result<Value> {
        self.get_with_query(path, &[])
    }

    /// GET a versioned path with query parameters, returning the parsed JSON
    /// body. ureq handles percent-encoding of the values.
    fn get_with_query(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        let url = format!("{}{}", self.config.api_url, path);
        let auth = format!("Bearer {}", self.config.api_key);

        let mut res = self.call_with_retry(|| {
            let mut req = self.agent.get(&url).header("Authorization", &auth);
            for (key, value) in query {
                req = req.query(*key, *value);
            }
            req.call()
        })?;
        error_for_status(&mut res)?;

        res.body_mut()
            .read_json::<Value>()
            .context("failed to parse Defined API response as JSON")
    }

    /// POST a JSON body to a versioned path and return the parsed JSON
    /// response.
    pub fn post_json(&self, path: &str, body: &Value) -> Result<Value> {
        let url = format!("{}{}", self.config.api_url, path);
        let auth = format!("Bearer {}", self.config.api_key);

        let mut res = self.call_with_retry(|| {
            self.agent
                .post(&url)
                .header("Authorization", &auth)
                .send_json(body)
        })?;
        error_for_status(&mut res)?;

        res.body_mut()
            .read_json::<Value>()
            .context("failed to parse Defined API response as JSON")
    }

    /// PUT a JSON body to a versioned path and return the parsed JSON
    /// response.
    pub fn put_json(&self, path: &str, body: &Value) -> Result<Value> {
        let url = format!("{}{}", self.config.api_url, path);
        let auth = format!("Bearer {}", self.config.api_key);

        let mut res = self.call_with_retry(|| {
            self.agent
                .put(&url)
                .header("Authorization", &auth)
                .send_json(body)
        })?;
        error_for_status(&mut res)?;

        res.body_mut()
            .read_json::<Value>()
            .context("failed to parse Defined API response as JSON")
    }

    /// DELETE a versioned path. A 2xx carries an empty `{data, metadata}`
    /// envelope, so nothing is parsed — the status is the whole answer.
    pub fn delete(&self, path: &str) -> Result<()> {
        let url = format!("{}{}", self.config.api_url, path);
        let auth = format!("Bearer {}", self.config.api_key);

        let mut res = self.call_with_retry(|| {
            self.agent
                .delete(&url)
                .header("Authorization", &auth)
                .call()
        })?;

        error_for_status(&mut res)
    }

    /// List every host (v2 endpoint — dual-stack `ipAddresses`), following
    /// cursor pagination to completion.
    ///
    /// The Defined API returns one page per call (`{ data, metadata }`); an
    /// agent consuming a single page would silently see only the first slice,
    /// so we walk the cursor and return one merged envelope. The last page's
    /// `metadata` (carrying `totalCount`) is preserved so the count still
    /// reflects the server's view.
    ///
    /// TODO(write-phase): add ?networkID= filtering once the exact query
    /// param is confirmed against the live API.
    pub fn list_hosts(&self) -> Result<Value> {
        let mut data: Vec<Value> = Vec::new();
        let mut metadata = Value::Null;
        let mut cursor: Option<String> = None;

        loop {
            let page = match &cursor {
                Some(c) => self.get_with_query("/v2/hosts", &[("cursor", c)])?,
                None => self.get("/v2/hosts")?,
            };

            if let Some(rows) = page.get("data").and_then(Value::as_array) {
                data.extend(rows.iter().cloned());
            }
            if let Some(m) = page.get("metadata") {
                metadata = m.clone();
            }

            match next_cursor(page.get("metadata")) {
                // Guard against a server that reports a next page but never
                // advances the cursor — better a short result than a spin.
                Some(next) if Some(&next) != cursor.as_ref() => cursor = Some(next),
                _ => break,
            }
        }

        Ok(json!({ "data": data, "metadata": metadata }))
    }

    /// List every role, following cursor pagination to completion.
    pub fn list_roles(&self) -> Result<Value> {
        let mut data: Vec<Value> = Vec::new();
        let mut metadata = Value::Null;
        let mut cursor: Option<String> = None;

        loop {
            let page = match &cursor {
                Some(c) => self.get_with_query("/v1/roles", &[("cursor", c)])?,
                None => self.get("/v1/roles")?,
            };

            if let Some(rows) = page.get("data").and_then(Value::as_array) {
                data.extend(rows.iter().cloned());
            }
            if let Some(m) = page.get("metadata") {
                metadata = m.clone();
            }

            match next_cursor(page.get("metadata")) {
                Some(next) if Some(&next) != cursor.as_ref() => cursor = Some(next),
                _ => break,
            }
        }

        Ok(json!({ "data": data, "metadata": metadata }))
    }

    /// Prove a key works with the least privilege the CLI relies on: a
    /// one-item `GET /v2/hosts` needs only `hosts:list`, so a key scoped
    /// exactly as the README suggests still passes.
    pub fn verify_key(&self) -> Result<()> {
        self.get_with_query("/v2/hosts", &[("pageSize", "1")])
            .map(|_| ())
    }

    /// Fetch the first page of networks. Used by `hosts create` to
    /// auto-pick when the account has exactly one (the common case at signup)
    /// — paginating to completion isn't worth it since accounts with enough
    /// networks to exceed one page will pass `--network` explicitly anyway.
    pub fn list_networks(&self) -> Result<Value> {
        self.get("/v2/networks")
    }

    /// Fetch one network. `hosts create --network <id>` needs its `cidrs` to
    /// auto-assign an IPv4, since the API only does so when handed the
    /// network's own IPv4 prefix.
    pub fn get_network(&self, id: &str) -> Result<Value> {
        self.get(&format!("/v2/networks/{id}"))
    }

    /// Fetch one host (v2 — dual-stack `ipAddresses`), which needs the
    /// `hosts:read` scope. `hosts delete` reads the host first so the
    /// confirmation prompt can name what is about to be removed.
    pub fn get_host(&self, id: &str) -> Result<Value> {
        self.get(&format!("/v2/hosts/{id}"))
    }

    /// Update a host (v3). The body is the full host object — PUT is not
    /// field-partial, so callers GET first and send the modified whole.
    /// v2 network hosts require v3 for mutations.
    pub fn update_host(&self, id: &str, body: &Value) -> Result<Value> {
        self.put_json(&format!("/v3/hosts/{id}"), body)
    }

    /// Delete a host, which needs the `hosts:delete` scope. v1 is the only
    /// version of the API with a host delete.
    pub fn delete_host(&self, id: &str) -> Result<()> {
        self.delete(&format!("/v1/hosts/{id}"))
    }

    /// Create a host (or lighthouse / relay) AND its enrollment code in one
    /// transaction. Wraps `POST /v2/host-and-enrollment-code` — the coupled
    /// endpoint exists because the OTP-issuing surface is the natural pair of
    /// host creation, so callers don't have to chase a second request and
    /// reason about partial-failure cleanup.
    pub fn create_host_with_enrollment(&self, body: &Value) -> Result<Value> {
        self.post_json("/v2/host-and-enrollment-code", body)
    }
}

/// Turn a non-2xx response into a typed [`ApiError`] carrying the API's
/// `{code, message, path}` entries, so the `--json` envelope can serialize
/// them directly. A successful response is left with its body unread, for the
/// caller to parse or ignore. `x-request-id` is worth surfacing on errors —
/// it's the handle support uses to find the request server-side.
fn error_for_status(res: &mut ureq::http::Response<ureq::Body>) -> Result<()> {
    let status = res.status();
    if status.is_success() {
        return Ok(());
    }

    let request_id = res
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = res.body_mut().read_to_string().unwrap_or_default();
    Err(ApiError::from_response(status.as_u16(), &body, request_id).into())
}

fn retry_delay(res: &ureq::http::Response<ureq::Body>, attempt: u32) -> Duration {
    let header_val = res
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok());
    retry_delay_from(header_val, attempt, cheap_jitter())
}

fn retry_delay_from(header: Option<&str>, attempt: u32, jitter: f64) -> Duration {
    let from_header = header
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|s| (0.0..=60.0).contains(s));

    let base = from_header.unwrap_or_else(|| 2.0_f64.powi(attempt as i32));
    Duration::from_secs_f64(base + jitter * 0.5 * base)
}

fn cheap_jitter() -> f64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let mixed = nanos ^ std::process::id().wrapping_mul(2654435761);
    (mixed % 1000) as f64 / 1000.0
}

/// Pull the next-page cursor out of a list response's `metadata`, or `None`
/// when there are no more pages.
///
/// Per the Defined API's shared `PaginationMetadata`, the next-page cursor
/// comes back as `nextCursor` and is accompanied by a `hasNextPage` flag
/// (both present whether or not `includeCounts` was requested). We only
/// advance when `hasNextPage` is true *and* a non-empty cursor is present, so
/// a missing/false flag stops the walk cleanly. `cursor` is accepted as a
/// fallback purely as insurance against field-name drift.
fn next_cursor(metadata: Option<&Value>) -> Option<String> {
    let metadata = metadata?;
    if !metadata
        .get("hasNextPage")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }

    metadata
        .get("nextCursor")
        .or_else(|| metadata.get("cursor"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_response_parses_structured_errors() {
        let body = r#"{"errors":[{"code":"ERR_BAD","message":"nope","path":"name"}]}"#;
        let err = ApiError::from_response(422, body, Some("req-1".into()));

        assert_eq!(err.status, 422);
        assert_eq!(err.request_id.as_deref(), Some("req-1"));
        assert_eq!(err.errors.len(), 1);
        assert_eq!(err.errors[0].code, "ERR_BAD");
        assert_eq!(err.errors[0].message, "nope");
        assert_eq!(err.errors[0].path.as_deref(), Some("name"));
        // Structured errors present -> raw is redundant and dropped.
        assert!(err.raw.is_none());
    }

    #[test]
    fn from_response_defaults_missing_error_fields() {
        let err = ApiError::from_response(400, r#"{"errors":[{}]}"#, None);

        assert_eq!(err.errors.len(), 1);
        assert_eq!(err.errors[0].code, "ERR_UNKNOWN");
        assert_eq!(err.errors[0].message, "(no message)");
        assert!(err.errors[0].path.is_none());
    }

    #[test]
    fn from_response_keeps_raw_for_non_envelope_body() {
        // e.g. an upstream proxy 502 returning HTML, not the DN error shape.
        let err = ApiError::from_response(502, "<html>Bad Gateway</html>", None);

        assert!(err.errors.is_empty());
        assert_eq!(err.raw.as_deref(), Some("<html>Bad Gateway</html>"));
        assert!(err.to_string().contains("Bad Gateway"));
    }

    #[test]
    fn from_response_empty_body_has_no_raw() {
        // e.g. an empty 401.
        let err = ApiError::from_response(401, "   ", None);

        assert!(err.errors.is_empty());
        assert!(err.raw.is_none());
        assert!(err.to_string().contains("(no response body)"));
    }

    #[test]
    fn display_lists_each_error_and_request_id() {
        let body = r#"{"errors":[{"code":"A","message":"first"},{"code":"B","message":"second","path":"x"}]}"#;
        let rendered = ApiError::from_response(422, body, Some("req-9".into())).to_string();

        assert!(rendered.contains("HTTP 422"));
        assert!(rendered.contains("A: first"));
        assert!(rendered.contains("B: second [x]"));
        assert!(rendered.contains("request id: req-9"));
    }

    #[test]
    fn next_cursor_advances_when_more_pages() {
        // Canonical shape from the API's PaginationMetadata.
        let md = json!({"hasNextPage": true, "hasPrevPage": true, "nextCursor": "abc"});
        assert_eq!(next_cursor(Some(&md)).as_deref(), Some("abc"));
    }

    #[test]
    fn next_cursor_accepts_cursor_fallback() {
        let md = json!({"hasNextPage": true, "cursor": "xyz"});
        assert_eq!(next_cursor(Some(&md)).as_deref(), Some("xyz"));
    }

    #[test]
    fn retry_delay_uses_header_when_valid() {
        let d = retry_delay_from(Some("5"), 0, 0.0);
        assert_eq!(d, Duration::from_secs(5));
    }

    #[test]
    fn retry_delay_honors_zero_header() {
        let d = retry_delay_from(Some("0"), 0, 0.0);
        assert_eq!(d, Duration::from_secs(0));
    }

    #[test]
    fn retry_delay_caps_header_at_60() {
        let d = retry_delay_from(Some("61"), 0, 0.0);
        assert_eq!(d, Duration::from_secs(1));
    }

    #[test]
    fn retry_delay_rejects_nan_and_inf() {
        let d_nan = retry_delay_from(Some("NaN"), 0, 0.0);
        let d_inf = retry_delay_from(Some("inf"), 0, 0.0);
        assert_eq!(d_nan, Duration::from_secs(1));
        assert_eq!(d_inf, Duration::from_secs(1));
    }

    #[test]
    fn retry_delay_rejects_negative() {
        let d = retry_delay_from(Some("-1"), 0, 0.0);
        assert_eq!(d, Duration::from_secs(1));
    }

    #[test]
    fn retry_delay_rejects_http_date() {
        let d = retry_delay_from(Some("Fri, 31 May 2024 23:59:59 GMT"), 0, 0.0);
        assert_eq!(d, Duration::from_secs(1));
    }

    #[test]
    fn retry_delay_exponential_fallback() {
        assert_eq!(retry_delay_from(None, 0, 0.0), Duration::from_secs(1));
        assert_eq!(retry_delay_from(None, 1, 0.0), Duration::from_secs(2));
        assert_eq!(retry_delay_from(None, 2, 0.0), Duration::from_secs(4));
    }

    #[test]
    fn retry_delay_adds_jitter() {
        let d = retry_delay_from(None, 1, 1.0);
        assert_eq!(d, Duration::from_secs(3));
    }

    #[test]
    fn cheap_jitter_in_range() {
        let j = cheap_jitter();
        assert!((0.0..1.0).contains(&j), "jitter {j} out of [0.0, 1.0)");
    }

    #[test]
    fn next_cursor_stops_on_last_page() {
        assert!(next_cursor(Some(&json!({"hasNextPage": false, "nextCursor": "abc"}))).is_none());
        // Missing flag is treated as "no more pages".
        assert!(next_cursor(Some(&json!({"nextCursor": "abc"}))).is_none());
        // Flag set but no usable cursor -> stop rather than re-request page one.
        assert!(next_cursor(Some(&json!({"hasNextPage": true}))).is_none());
        assert!(next_cursor(Some(&json!({"hasNextPage": true, "nextCursor": ""}))).is_none());
        assert!(next_cursor(None).is_none());
    }
}
