//! Every `--json` failure puts the same `{status, request_id, errors}`
//! envelope on stdout, whether it came from the API, local validation, or
//! argument parsing.

use std::process::{Command, Output};

fn dn(args: &[&str]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_dn"))
        .args(args)
        .env("DN_CONFIG_DIR", dir.path())
        .env("DEFINED_API_URL", "http://127.0.0.1:1")
        .env_remove("DEFINED_API_KEY")
        .output()
        .unwrap()
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
