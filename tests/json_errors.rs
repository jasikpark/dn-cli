//! Every `--json` failure puts the same `{status, request_id, errors}`
//! envelope on stdout, whether it came from the API, local validation, or
//! argument parsing.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::thread;

/// Run `dn` with no credentials against an API URL that refuses connections,
/// so nothing here can reach a real API.
fn dn(args: &[&str]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_dn"))
        .args(args)
        .env("DN_CONFIG_DIR", dir.path())
        .env("DEFINED_API_URL", "http://127.0.0.1:1")
        .env_remove("DEFINED_API_KEY")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// Run `dn` with a dummy key against a local server that answers every
/// request with `status` and `body`.
fn dn_against(status: &'static str, body: &'static str, args: &[&str]) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            // Drain the request line and headers; these are bodiless GETs.
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    let dir = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_dn"))
        .args(args)
        .env("DN_CONFIG_DIR", dir.path())
        .env("DEFINED_API_URL", url)
        .env("DEFINED_API_KEY", "fake-test-key")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn api_error(output: &Output) -> serde_json::Value {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {output:?}"))
}

fn local_error(output: &Output) -> (String, String) {
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {output:?}"));
    assert!(payload["status"].is_null(), "{payload}");
    assert!(payload["request_id"].is_null(), "{payload}");
    let errors = payload["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1, "{payload}");
    (
        errors[0]["code"].as_str().unwrap().to_string(),
        errors[0]["message"].as_str().unwrap().to_string(),
    )
}

#[test]
fn validation_errors_use_the_api_envelope() {
    let output = dn(&["host", "search", "o", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let (code, message) = local_error(&output);
    assert_eq!(code, "ERR_INVALID_ARGUMENT");
    assert_eq!(message, "search query must be at least 2 characters");
    assert!(String::from_utf8_lossy(&output.stderr).contains("at least 2 characters"));
}

/// Every check that rejects the caller's arguments runs before credentials
/// load (there are none here), so each reports ERR_INVALID_ARGUMENT, never a
/// missing-key ERR_LOCAL that hides the real problem.
#[test]
fn argument_errors_are_invalid_argument_before_credentials() {
    for (args, expected) in [
        (&["role", "get", "bad/id", "--json"][..], "role id"),
        (&["tag", "get", "no-colon", "--json"], "key:value"),
        (&["host", "edit", "host-1", "--json"], "nothing to edit"),
        (
            &["host", "create", "lh", "--lighthouse", "--json"],
            "--static-address",
        ),
        (
            &["host", "delete", "a/b", "--yes", "--json"],
            "invalid character '/'",
        ),
        (&["host", "delete", "host-1", "--json"], "pass --yes"),
        (&["auth", "login", "--ref", "notop", "--json"], "op://"),
        (&["auth", "login", "--json"], "pass --ref"),
    ] {
        let output = dn(args);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        let (code, message) = local_error(&output);
        assert_eq!(code, "ERR_INVALID_ARGUMENT", "{args:?}: {message}");
        assert!(
            message.contains(expected),
            "{args:?}: expected {expected:?} in {message:?}"
        );
    }
}

#[test]
fn other_local_failures_are_err_local() {
    let output = dn(&["host", "list", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let (code, _) = local_error(&output);
    assert_eq!(code, "ERR_LOCAL");
}

#[test]
fn an_ambiguous_network_is_invalid_argument() {
    let output = dn_against(
        "200 OK",
        r#"{"data":[{"id":"network-a"},{"id":"network-b"}],"metadata":{}}"#,
        &["host", "create", "web", "--json"],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let (code, message) = local_error(&output);
    assert_eq!(code, "ERR_INVALID_ARGUMENT");
    assert!(message.contains("pass --network"), "{message}");
}

#[test]
fn api_errors_without_an_envelope_still_have_one_error() {
    for (body, message) in [
        ("", "(no response body)"),
        ("<html>Bad Gateway</html>", "<html>Bad Gateway</html>"),
    ] {
        let payload = api_error(&dn_against(
            "502 Bad Gateway",
            body,
            &["host", "list", "--json"],
        ));
        assert_eq!(
            payload,
            serde_json::json!({
                "status": 502,
                "request_id": null,
                "errors": [{ "code": "ERR_HTTP_502", "message": message }],
            })
        );
    }
}

#[test]
fn api_errors_keep_the_context_dn_added() {
    let payload = api_error(&dn_against(
        "403 Forbidden",
        r#"{"errors":[{"code":"ERR_FORBIDDEN","message":"missing networks:read"}]}"#,
        &["host", "create", "web", "--network", "network-a", "--json"],
    ));
    assert_eq!(payload["status"], 403);
    assert_eq!(payload["errors"][0]["code"], "ERR_FORBIDDEN");
    let message = payload["errors"][0]["message"].as_str().unwrap();
    assert!(
        message.starts_with("could not read network network-a"),
        "{message}"
    );
    assert!(message.contains("--no-ipv4"), "{message}");
    assert!(message.ends_with(": missing networks:read"), "{message}");
}

#[test]
fn usage_errors_use_the_api_envelope_and_exit_2() {
    for (args, expected) in [
        (
            &["host", "bogus", "--json"][..],
            "unrecognized subcommand 'bogus'",
        ),
        (
            &["--json", "host", "list", "--nope"],
            "unexpected argument '--nope'",
        ),
        (&["host", "--json"], "'dn host' requires a subcommand"),
        // A multi-line headline keeps the lines that name the argument.
        (
            &["host", "delete", "--json"],
            "the following required arguments were not provided: <HOST_ID>",
        ),
        (&["host", "list", "--json=true"], "unexpected value 'true'"),
    ] {
        let output = dn(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        let (code, message) = local_error(&output);
        assert_eq!(code, "ERR_USAGE", "{args:?}");
        assert!(
            message.contains(expected),
            "{args:?}: expected {expected:?} in {message:?}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).is_empty(),
            "{args:?}"
        );
    }
}

#[test]
fn usage_errors_without_json_keep_stdout_empty() {
    let output = dn(&["host", "bogus"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
}

#[test]
fn json_after_double_dash_is_positional() {
    let output = dn(&["host", "bogus", "--", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "{output:?}");
}

#[test]
fn help_and_version_are_not_errors() {
    for args in [&["--help", "--json"][..], &["--version", "--json"]] {
        let output = dn(args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).is_err(),
            "{args:?} should print help/version text, not an envelope"
        );
    }
}
