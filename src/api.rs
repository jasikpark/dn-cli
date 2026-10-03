use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};
use ureq::Body;
use ureq::http::Response;

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
    /// Always present (`null` when the response had no `X-Request-ID`), so
    /// every `--json` error envelope carries the same keys.
    pub request_id: Option<String>,
    /// Never empty: a body without the expected `{errors:[...]}` shape (e.g. an
    /// upstream proxy 502 or an empty 401) becomes one `ERR_HTTP_<status>`
    /// entry carrying the raw body, so callers can always read `errors[0]`.
    pub errors: Vec<ApiErrorDetail>,
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
        let mut errors = serde_json::from_str::<Value>(body)
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

        if errors.is_empty() {
            let trimmed = body.trim();
            errors.push(ApiErrorDetail {
                code: format!("ERR_HTTP_{status}"),
                message: if trimmed.is_empty() {
                    "(no response body)".to_string()
                } else {
                    trimmed.to_string()
                },
                path: None,
            });
        }

        ApiError {
            status,
            request_id,
            errors,
        }
    }
}

impl ApiErrorDetail {
    fn from_value(value: &Value) -> Self {
        let field = |key| value.get(key).and_then(Value::as_str);
        ApiErrorDetail {
            code: field("code").unwrap_or("ERR_UNKNOWN").to_string(),
            message: field("message").unwrap_or("(no message)").to_string(),
            path: field("path").map(str::to_owned),
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Defined API error (HTTP {})", self.status)?;

        for err in &self.errors {
            match &err.path {
                Some(path) => write!(f, "\n  {}: {} [{}]", err.code, err.message, path)?,
                None => write!(f, "\n  {}: {}", err.code, err.message)?,
            }
        }

        if let Some(id) = &self.request_id {
            write!(f, "\n  request id: {id}")?;
        }

        Ok(())
    }
}

impl std::error::Error for ApiError {}

/// The repository URL names this unofficial client, so its traffic can't be
/// mistaken for a first-party `dn-cli`.
const USER_AGENT: &str = concat!(
    "dn-cli/",
    env!("CARGO_PKG_VERSION"),
    " (+",
    env!("CARGO_PKG_REPOSITORY"),
    ")"
);

impl Client {
    pub fn new(config: Config) -> Self {
        // Disable ureq's default "non-2xx is an Error::StatusCode" behavior so
        // error responses arrive as Ok(_) and we can read the DN error body
        // (Error::StatusCode carries only the numeric code, never the body).
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
            .user_agent(USER_AGENT)
            .build()
            .into();
        Self { config, agent }
    }

    fn call_with_retry(
        &self,
        send: impl Fn() -> Result<Response<Body>, ureq::Error>,
    ) -> Result<Response<Body>> {
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
        send().context("request to Defined API failed")
    }

    /// Send one request to a versioned path and fail on a non-2xx with a
    /// typed [`ApiError`]. `build` makes the request from the full URL and
    /// the `Authorization` value.
    fn send(
        &self,
        path: &str,
        build: impl Fn(&str, &str) -> Result<Response<Body>, ureq::Error>,
    ) -> Result<Response<Body>> {
        let url = format!("{}{}", self.config.api_url, path);
        let auth = format!("Bearer {}", self.config.api_key);
        let mut res = self.call_with_retry(|| build(&url, &auth))?;
        error_for_status(&mut res)?;
        Ok(res)
    }

    /// GET a versioned path and return the parsed JSON body.
    pub fn get(&self, path: &str) -> Result<Value> {
        self.get_with_query(path, &[])
    }

    /// GET a versioned path with query parameters, returning the parsed JSON
    /// body. ureq handles percent-encoding of the values.
    fn get_with_query(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        read_json(self.send(path, |url, auth| {
            let mut req = self.agent.get(url).header("Authorization", auth);
            for (key, value) in query {
                req = req.query(*key, *value);
            }
            req.call()
        })?)
    }

    /// List every host (v2 endpoint — dual-stack `ipAddresses`), following
    /// cursor pagination to completion.
    ///
    /// TODO(write-phase): add ?networkID= filtering once the exact query
    /// param is confirmed against the live API.
    pub fn list_hosts(&self) -> Result<Value> {
        self.list_all("/v2/hosts", &[])
    }

    /// Search hosts by a free-text query, following cursor pagination to
    /// completion. Wraps `GET /v2/hosts?filter.search=<q>` — a server-side
    /// case-insensitive LIKE across a host's name, IP addresses, assigned
    /// role name, and tags (the same surface the admin panel's host search
    /// box drives). The API rejects a query shorter than two characters with
    /// a 400 (`ERR_TOO_SHORT`); callers should preflight to spare the round
    /// trip. Needs the `hosts:list` scope, same as `list_hosts`.
    ///
    /// `filter.search` is undocumented in the public OpenAPI spec (only the
    /// structured `filter.*` params are), so this is pinned to the admin panel's
    /// observed behaviour rather than a published contract.
    pub fn search_hosts(&self, query: &str) -> Result<Value> {
        self.list_all("/v2/hosts", &[("filter.search", query)])
    }

    /// List every role, following cursor pagination to completion.
    pub fn list_roles(&self) -> Result<Value> {
        self.list_all("/v1/roles", &[])
    }

    /// Fetch one role with its `firewallRules`, which `list_roles` only
    /// counts. Needs the `roles:read` scope.
    pub fn get_role(&self, id: &str) -> Result<Value> {
        self.get(&format!("/v1/roles/{id}"))
    }

    /// List every tag, following cursor pagination to completion. Tags list
    /// only on v2; `GET /v1/tags` answers 405. Needs the `tags:list` scope.
    pub fn list_tags(&self) -> Result<Value> {
        self.list_all("/v2/tags", &[])
    }

    /// Fetch one tag (`key:value`) with its `firewallRules`, config
    /// overrides and route subscriptions. Needs the `tags:read` scope.
    pub fn get_tag(&self, name: &str) -> Result<Value> {
        self.get(&tag_path(name))
    }

    /// List every network, following cursor pagination to completion. Backs
    /// `networks list`; `hosts create` auto-picks from it when the account
    /// has exactly one network.
    pub fn list_networks(&self) -> Result<Value> {
        self.list_all("/v2/networks", &[])
    }

    /// Fetch every page of a list endpoint and return one merged envelope.
    ///
    /// The Defined API returns one page per call (`{ data, metadata }`); an
    /// agent consuming a single page would silently see only the first slice,
    /// so we walk the cursor and return one merged envelope. The last page's
    /// `metadata` is passed through for `--json`.
    /// `params` are extra query pairs applied to every page (e.g. a
    /// `filter.search` term); the cursor is threaded in on top of them.
    fn list_all(&self, path: &str, params: &[(&str, &str)]) -> Result<Value> {
        let mut data: Vec<Value> = Vec::new();
        let mut metadata = Value::Null;
        let mut cursor: Option<String> = None;

        loop {
            let mut query: Vec<(&str, &str)> = params.to_vec();
            if let Some(c) = &cursor {
                query.push(("cursor", c));
            }
            let page = self.get_with_query(path, &query)?;

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

    /// Prove a key works with the least privilege the CLI relies on: a
    /// one-item `GET /v2/hosts` needs only `hosts:list`, so a key scoped
    /// exactly as the README suggests still passes.
    pub fn verify_key(&self) -> Result<()> {
        self.get_with_query("/v2/hosts", &[("pageSize", "1")])
            .map(|_| ())
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
        read_json(self.send(&format!("/v3/hosts/{id}"), |url, auth| {
            self.agent
                .put(url)
                .header("Authorization", auth)
                .send_json(body)
        })?)
    }

    /// Delete a host, which needs the `hosts:delete` scope. v1 is the only
    /// version of the API with a host delete.
    pub fn delete_host(&self, id: &str) -> Result<()> {
        self.delete(&format!("/v1/hosts/{id}"))
    }

    /// Delete a role, which needs the `roles:delete` scope.
    pub fn delete_role(&self, id: &str) -> Result<()> {
        self.delete(&format!("/v1/roles/{id}"))
    }

    /// Delete a tag (`key:value`), which needs the `tags:delete` scope.
    pub fn delete_tag(&self, name: &str) -> Result<()> {
        self.delete(&tag_path(name))
    }

    /// Delete a network, which needs the `networks:delete` scope. Only v1
    /// has a network delete; the API refuses (`ERR_HAS_DEPENDENTS`) while
    /// the network still has hosts.
    pub fn delete_network(&self, id: &str) -> Result<()> {
        self.delete(&format!("/v1/networks/{id}"))
    }

    /// DELETE a versioned path. A 2xx carries an empty `{data, metadata}`
    /// envelope, so nothing is parsed.
    fn delete(&self, path: &str) -> Result<()> {
        self.send(path, |url, auth| {
            self.agent.delete(url).header("Authorization", auth).call()
        })
        .map(drop)
    }

    /// Create a host (or lighthouse / relay) AND its enrollment code in one
    /// transaction. Wraps `POST /v2/host-and-enrollment-code` — the coupled
    /// endpoint exists because the OTP-issuing surface is the natural pair of
    /// host creation, so callers don't have to chase a second request and
    /// reason about partial-failure cleanup.
    pub fn create_host_with_enrollment(&self, body: &Value) -> Result<Value> {
        read_json(self.send("/v2/host-and-enrollment-code", |url, auth| {
            self.agent
                .post(url)
                .header("Authorization", auth)
                .send_json(body)
        })?)
    }
}

/// Turn a non-2xx response into a typed [`ApiError`] carrying the API's
/// `{code, message, path}` entries, so the `--json` envelope can serialize
/// them directly. A successful response is left with its body unread, for the
/// caller to parse or ignore. `x-request-id` is worth surfacing on errors —
/// it's the handle support uses to find the request server-side.
fn error_for_status(res: &mut Response<Body>) -> Result<()> {
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

fn read_json(mut res: Response<Body>) -> Result<Value> {
    res.body_mut()
        .read_json()
        .context("failed to parse Defined API response as JSON")
}

fn retry_delay(res: &Response<Body>, attempt: u32) -> Duration {
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

fn tag_path(name: &str) -> String {
    format!("/v1/tags/{}", encode_path_segment(name))
}

/// Percent-encode one URL path segment: everything but RFC 3986 unreserved
/// characters and `:` (tag names are `key:value`). Tag values may hold any
/// character, so a raw `/`, `?`, `#` or `%` would otherwise
/// change which resource is requested.
fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_path_segment_keeps_tag_colon_and_escapes_url_structure() {
        assert_eq!(encode_path_segment("env:prod"), "env:prod");
        assert_eq!(encode_path_segment("a:b/c?d#e%f"), "a:b%2Fc%3Fd%23e%25f");
        assert_eq!(encode_path_segment("k:é"), "k:%C3%A9");
    }

    #[test]
    fn tag_path_keeps_the_name_in_one_segment() {
        assert_eq!(
            tag_path("a:b/../../hosts"),
            "/v1/tags/a:b%2F..%2F..%2Fhosts"
        );
    }

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
    fn from_response_wraps_a_non_envelope_body_in_one_error() {
        // e.g. an upstream proxy 502 returning HTML, not the DN error shape.
        let err = ApiError::from_response(502, "<html>Bad Gateway</html>", None);

        assert_eq!(err.errors.len(), 1);
        assert_eq!(err.errors[0].code, "ERR_HTTP_502");
        assert_eq!(err.errors[0].message, "<html>Bad Gateway</html>");
        assert!(
            err.to_string()
                .contains("ERR_HTTP_502: <html>Bad Gateway</html>")
        );
    }

    #[test]
    fn from_response_reports_an_empty_body_as_one_error() {
        // e.g. an empty 401.
        let err = ApiError::from_response(401, "   ", None);

        assert_eq!(err.errors.len(), 1);
        assert_eq!(err.errors[0].code, "ERR_HTTP_401");
        assert_eq!(err.errors[0].message, "(no response body)");
        assert!(err.to_string().contains("(no response body)"));
    }

    #[test]
    fn serializes_a_missing_request_id_as_null() {
        let err = ApiError::from_response(401, "", None);
        let value = serde_json::to_value(&err).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "status": 401,
                "request_id": null,
                "errors": [{ "code": "ERR_HTTP_401", "message": "(no response body)" }],
            })
        );
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
