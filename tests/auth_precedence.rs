use std::fs;
use std::process::Command;

#[test]
fn auth_status_uses_environment_before_stored_credentials() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("auth.json"), "not valid JSON").unwrap();

    for (key, source, reference, message) in [
        (Some("dummy-test-key"), "env", None, None),
        (
            Some("op://vault/item/field"),
            "env-ref",
            Some("op://vault/item/field"),
            None,
        ),
        (
            Some("   "),
            "invalid",
            None,
            Some("DEFINED_API_KEY is set but empty"),
        ),
        (
            Some("op://invalid"),
            "invalid",
            None,
            Some("DEFINED_API_KEY holds an invalid op:// reference"),
        ),
        (None, "invalid", None, Some("failed to parse")),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dn"));
        command
            .args(["--json", "auth", "status"])
            .env("DN_CONFIG_DIR", dir.path())
            .env_remove("DEFINED_API_KEY")
            // Status must not invoke op, even for an environment reference.
            .env("PATH", "");
        if let Some(key) = key {
            command.env("DEFINED_API_KEY", key);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{:?}", output);
        let payload: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(payload["source"], source);
        assert_eq!(payload["api_key_ref"], serde_json::json!(reference));
        match message {
            Some(message) => assert!(payload["message"].as_str().unwrap().contains(message)),
            None => assert!(payload["message"].is_null()),
        }
        assert!(!String::from_utf8_lossy(&output.stdout).contains("dummy-test-key"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("dummy-test-key"));
    }
}

#[test]
fn environment_auth_does_not_depend_on_stored_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    fs::write(&auth_path, "not valid JSON").unwrap();

    // Without --yes, delete stops after loading credentials and before HTTP.
    // Each subprocess has its own environment; no global env mutation or real
    // credentials are needed, even when the test suite runs in parallel.
    for (key, expected) in [
        (
            Some("dummy-test-key"),
            "pass --yes to delete without a confirmation prompt",
        ),
        (Some("   "), "DEFINED_API_KEY is set but empty"),
        (
            Some("op://invalid"),
            "DEFINED_API_KEY holds an invalid op:// reference",
        ),
        (None, "failed to parse"),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dn"));
        command
            .args(["hosts", "delete", "host-test", "--json"])
            .env("DN_CONFIG_DIR", dir.path())
            .env("DEFINED_API_URL", "http://127.0.0.1:1")
            .env_remove("DEFINED_API_KEY");
        if let Some(key) = key {
            command.env("DEFINED_API_KEY", key);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        let payload: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let error = payload["error"].as_str().unwrap();
        assert!(
            error.contains(expected),
            "expected {expected:?}, got {error:?}"
        );
        if key.is_none() {
            assert!(error.contains("auth.json"));
        }
    }

    assert_eq!(fs::read_to_string(&auth_path).unwrap(), "not valid JSON");
}
