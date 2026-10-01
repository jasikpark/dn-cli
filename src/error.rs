use serde_json::{Value, json};

use crate::api::ApiError;
use crate::output::sanitize_for_display;

/// Error codes for failures raised before (or without) an API response. They
/// share the API's `ERR_*` namespace so agents branch on one field, and
/// `status: null` tells them the request never reached the API.
const ERR_USAGE: &str = "ERR_USAGE";

const ERR_INVALID_ARGUMENT: &str = "ERR_INVALID_ARGUMENT";

const ERR_LOCAL: &str = "ERR_LOCAL";

/// A client-side validation failure, tagged so `--json` reports it as
/// [`ERR_INVALID_ARGUMENT`] rather than the catch-all [`ERR_LOCAL`].
#[derive(Debug)]
pub struct InvalidArgument(pub anyhow::Error);

impl std::fmt::Display for InvalidArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl std::error::Error for InvalidArgument {}

/// The API's error envelope for an error that never got an HTTP response, so
/// `--json` callers parse one shape whatever failed.
fn local_error_envelope(code: &str, message: &str) -> Value {
    json!({
        "status": null,
        "request_id": null,
        "errors": [{ "code": code, "message": message }],
    })
}

/// Render an error per dn-cli's two-faces design (the axocli envelope-split
/// pattern, reimplemented on anyhow): in `--json` mode emit a machine-readable
/// envelope to stdout AND a human hint to stderr; otherwise just the human
/// hint to stderr. Every envelope has the API's `{status, request_id, errors}`
/// shape: typed [`ApiError`]s carry the server's own, and local failures get
/// `status: null` and a local code (see [`error_envelope`]).
pub fn report_error(err: &anyhow::Error, json: bool) {
    if json && let Ok(payload) = serde_json::to_string(&error_envelope(err)) {
        println!("{payload}");
    }

    // API error messages are server-controlled, so strip terminal escapes.
    eprintln!("error: {}", sanitize_for_display(&format!("{err:#}")));
}

fn error_envelope(err: &anyhow::Error) -> Value {
    if let Some(api) = err.downcast_ref::<ApiError>()
        && let Ok(mut value) = serde_json::to_value(api)
    {
        // Context added on top of the API error (e.g. "pass --ipv4 or
        // --no-ipv4") is often the actionable part, so lead each message
        // with it, the way the stderr hint does.
        let context: Vec<String> = err
            .chain()
            .take_while(|cause| !cause.is::<ApiError>())
            .map(ToString::to_string)
            .collect();
        if !context.is_empty()
            && let Some(errors) = value["errors"].as_array_mut()
        {
            let prefix = context.join(": ");
            for error in errors {
                if let Some(message) = error["message"].as_str() {
                    error["message"] = json!(format!("{prefix}: {message}"));
                }
            }
        }
        return value;
    }
    let code = if err.downcast_ref::<InvalidArgument>().is_some() {
        ERR_INVALID_ARGUMENT
    } else {
        ERR_LOCAL
    };
    local_error_envelope(code, &format!("{err:#}"))
}

/// Whether `--json` appears among the raw arguments, for reporting an error
/// clap raised before it could tell us. Arguments after `--` are positional.
/// `--json=<value>` counts too: clap rejects it, but the caller wants JSON.
pub fn json_requested<I: IntoIterator<Item = std::ffi::OsString>>(args: I) -> bool {
    args.into_iter()
        .skip(1)
        .take_while(|arg| arg != "--")
        .any(|arg| arg == "--json" || arg.to_str().is_some_and(|a| a.starts_with("--json=")))
}

/// Exit on a clap parse failure. `--help` and `--version` pass through
/// untouched; a real usage error also gets an [`ERR_USAGE`] envelope on stdout
/// under `--json`, so a caller parsing stdout reads the failure instead of
/// empty input. Clap's own message still goes to stderr, and the exit code
/// stays 2 so usage errors remain distinct from runtime failures (1).
pub fn report_usage_error(err: clap::Error, json: bool) -> ! {
    if json && err.use_stderr() {
        println!("{}", local_error_envelope(ERR_USAGE, &usage_message(&err)));
    }
    err.exit()
}

/// Clap's headline for a usage error on one line, without the `error: `
/// prefix or the tips and usage after the first blank line. A headline can
/// span lines ("the following required arguments were not provided:" then
/// one indented line per argument), so those are joined.
fn usage_message(err: &clap::Error) -> String {
    let rendered = err.render().to_string();
    let headline = rendered
        .lines()
        .map(str::trim)
        .take_while(|line| !line.is_empty() && !line.starts_with("Usage:"))
        .collect::<Vec<_>>()
        .join(" ");
    match headline.strip_prefix("error: ") {
        Some(rest) => rest.to_string(),
        None => headline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_requested_scans_flags_before_double_dash() {
        let requested = |args: &[&str]| json_requested(args.iter().map(Into::into));
        assert!(requested(&["dn", "host", "bogus", "--json"]));
        assert!(requested(&["dn", "--json=true", "host", "list"]));
        assert!(!requested(&["dn", "host", "bogus"]));
        assert!(!requested(&["dn", "host", "bogus", "--", "--json"]));
        assert!(!requested(&["dn", "--jsonx"]));
        // argv[0] is the program, never a flag.
        assert!(!requested(&["--json"]));
    }
}
