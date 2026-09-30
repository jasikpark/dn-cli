//! Named profiles in `auth.json`, and the migration of the single-reference
//! layout that came before them.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{Value, json};

const LEGACY: &str = r#"{"api_key_ref":"op://Personal/dn/credential"}"#;

/// Run `dn` against `dir` as its config directory, with no key in the
/// environment and an API URL that refuses connections.
fn dn(dir: &Path, args: &[&str]) -> Output {
    dn_with(dir, args, &[])
}

fn dn_with(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dn"));
    command
        .args(args)
        .env("DN_CONFIG_DIR", dir)
        .env_remove("DEFINED_API_KEY")
        .env_remove("DEFINED_API_URL")
        .env_remove("DN_PROFILE")
        .stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {output:?}"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn auth_json(dir: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join("auth.json")).unwrap()).unwrap()
}

fn migrated() -> Value {
    json!({
        "version": 2,
        "default_profile": "default",
        "profiles": { "default": { "key": "op://Personal/dn/credential" } },
    })
}

#[test]
fn any_call_migrates_the_old_layout_once() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("auth.json"), LEGACY).unwrap();

    let first = dn(dir.path(), &["auth", "status", "--json"]);
    assert!(first.status.success(), "{first:?}");
    assert_eq!(auth_json(dir.path()), migrated());
    assert!(
        stderr(&first).contains("to the profiles format"),
        "{first:?}"
    );
    let status = stdout_json(&first);
    assert_eq!(status["profile"], "default");
    assert_eq!(status["source"], "file");
    assert_eq!(status["api_key_ref"], "op://Personal/dn/credential");

    let second = dn(dir.path(), &["auth", "status", "--json"]);
    assert!(second.status.success(), "{second:?}");
    assert!(second.stderr.is_empty(), "{second:?}");
    assert_eq!(stdout_json(&second), status);
}

#[test]
fn a_failing_command_still_migrates() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("auth.json"), LEGACY).unwrap();

    let output = dn(dir.path(), &["host", "search", "o", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(auth_json(dir.path()), migrated());
    // The notice is stderr-only, so stdout is still exactly one envelope.
    assert_eq!(
        stdout_json(&output)["errors"][0]["code"],
        "ERR_INVALID_ARGUMENT"
    );
}

#[test]
fn parallel_calls_migrate_to_one_valid_file() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("auth.json"), LEGACY).unwrap();

    let children: Vec<_> = (0..8)
        .map(|_| {
            Command::new(env!("CARGO_BIN_EXE_dn"))
                .args(["auth", "status", "--json"])
                .env("DN_CONFIG_DIR", dir.path())
                .env_remove("DEFINED_API_KEY")
                .env_remove("DN_PROFILE")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(stdout_json(&output)["profile"], "default");
    }
    assert_eq!(auth_json(dir.path()), migrated());
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|name| name != "auth.json")
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
}

#[test]
#[cfg(unix)]
fn a_read_only_directory_warns_and_still_runs() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("auth.json"), LEGACY).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let writable = fs::write(dir.path().join("probe"), "").is_ok();
    if writable {
        // Root ignores directory permissions, so there is nothing to test.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("skipped: this user can write to a read-only directory");
        return;
    }

    let output = dn(dir.path(), &["auth", "status", "--json"]);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(stderr(&output).contains("could not migrate"), "{output:?}");
    assert_eq!(stdout_json(&output)["profile"], "default");
    assert_eq!(
        fs::read_to_string(dir.path().join("auth.json")).unwrap(),
        LEGACY
    );
}

#[test]
fn a_corrupt_file_is_not_migrated() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("auth.json"), "not valid JSON").unwrap();

    let output = dn(dir.path(), &["auth", "status", "--json"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout_json(&output)["source"], "invalid");
    assert!(!stderr(&output).contains("migrat"), "{output:?}");
    assert_eq!(
        fs::read_to_string(dir.path().join("auth.json")).unwrap(),
        "not valid JSON"
    );
}

fn login(dir: &Path, args: &[&str]) -> Value {
    let mut all = vec!["auth", "login", "--no-verify", "--json"];
    all.extend_from_slice(args);
    let output = dn(dir, &all);
    assert!(output.status.success(), "{args:?}: {output:?}");
    stdout_json(&output)
}

#[test]
fn profiles_can_be_added_listed_switched_and_removed() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    let staging = login(
        d,
        &[
            "--profile",
            "staging",
            "--ref",
            "op://Dev/dn-staging/credential",
            "--api-url",
            "https://staging.example/",
        ],
    );
    assert_eq!(staging["profile"], "staging");
    assert_eq!(staging["api_url"], "https://staging.example");
    assert_eq!(
        staging["default"], true,
        "the first profile becomes the default"
    );

    let prod = login(
        d,
        &["--profile", "prod", "--ref", "op://Personal/dn/credential"],
    );
    assert_eq!(prod["default"], false, "a login never moves the default");
    assert_eq!(prod["api_url"], "https://api.defined.net");

    let list = stdout_json(&dn(d, &["auth", "list", "--json"]));
    assert_eq!(
        list,
        json!({
            "default_profile": "staging",
            "profiles": [
                { "name": "prod", "default": false, "api_url": "https://api.defined.net",
                  "api_key_ref": "op://Personal/dn/credential" },
                { "name": "staging", "default": true, "api_url": "https://staging.example",
                  "api_key_ref": "op://Dev/dn-staging/credential" },
            ],
        })
    );

    let status = |args: &[&str], env: &[(&str, &str)]| {
        let mut all = vec!["auth", "status", "--json"];
        all.extend_from_slice(args);
        stdout_json(&dn_with(d, &all, env))
    };
    assert_eq!(status(&[], &[])["profile"], "staging");
    assert_eq!(status(&["--profile", "prod"], &[])["profile"], "prod");
    let from_env = status(&[], &[("DN_PROFILE", "prod")]);
    assert_eq!(from_env["profile"], "prod");
    assert_eq!(from_env["api_key_ref"], "op://Personal/dn/credential");
    // The flag beats the environment, and DEFINED_API_URL beats the profile.
    let both = status(
        &["--profile", "staging"],
        &[
            ("DN_PROFILE", "prod"),
            ("DEFINED_API_URL", "https://override.test"),
        ],
    );
    assert_eq!(both["profile"], "staging");
    assert_eq!(both["api_url"], "https://override.test");

    let switched = stdout_json(&dn(d, &["auth", "switch", "prod", "--json"]));
    assert_eq!(switched["default_profile"], "prod");
    assert_eq!(status(&[], &[])["profile"], "prod");

    let logout = stdout_json(&dn(
        d,
        &["auth", "logout", "--profile", "staging", "--json"],
    ));
    assert_eq!(logout["removed"], true);
    assert_eq!(logout["profile"], "staging");
    assert_eq!(logout["default_profile"], "prod");

    let logout = stdout_json(&dn(d, &["auth", "logout", "--json"]));
    assert_eq!(logout["profile"], "prod");
    assert!(
        !d.join("auth.json").exists(),
        "the last logout removes the file"
    );
}

#[test]
fn logout_all_removes_every_profile() {
    let dir = tempfile::tempdir().unwrap();
    login(dir.path(), &["--profile", "a", "--ref", "op://v/a/f"]);
    login(dir.path(), &["--profile", "b", "--ref", "op://v/b/f"]);

    let output = stdout_json(&dn(dir.path(), &["auth", "logout", "--all", "--json"]));
    assert_eq!(output["removed"], true);
    assert!(!dir.path().join("auth.json").exists());
}

#[test]
fn profile_errors_name_the_problem() {
    let dir = tempfile::tempdir().unwrap();
    login(dir.path(), &["--ref", "op://v/i/f"]);

    for (args, env, code, expected) in [
        (
            &["host", "list", "--profile", "qa", "--json"][..],
            &[][..],
            "ERR_LOCAL",
            "no profile named \"qa\"",
        ),
        (
            &["host", "list", "--json"],
            &[("DN_PROFILE", "qa")][..],
            "ERR_LOCAL",
            "no profile named \"qa\"",
        ),
        (
            &["host", "list", "--profile", "a/b", "--json"],
            &[],
            "ERR_INVALID_ARGUMENT",
            "invalid profile name",
        ),
        (
            &["auth", "switch", "qa", "--json"],
            &[],
            "ERR_INVALID_ARGUMENT",
            "no profile named \"qa\"",
        ),
        (
            &[
                "auth",
                "login",
                "--ref",
                "op://v/i/f",
                "--api-url",
                "staging",
                "--json",
            ],
            &[],
            "ERR_INVALID_ARGUMENT",
            "--api-url must be",
        ),
    ] {
        let output = dn_with(dir.path(), args, env);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        let payload = stdout_json(&output);
        assert_eq!(payload["errors"][0]["code"], code, "{args:?}: {payload}");
        let message = payload["errors"][0]["message"].as_str().unwrap();
        assert!(message.contains(expected), "{args:?}: {message}");
    }
}

/// A local API that answers every request with an empty host list and
/// records each request line.
fn serve_empty_hosts() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            log.lock().unwrap().push(request_line.trim().to_string());
            let body = r#"{"data":[],"metadata":{}}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    (url, seen)
}

#[test]
fn api_calls_go_to_the_selected_profile_url() {
    let dir = tempfile::tempdir().unwrap();
    let (url, seen) = serve_empty_hosts();
    login(dir.path(), &["--profile", "prod", "--ref", "op://v/prod/f"]);
    login(
        dir.path(),
        &[
            "--profile",
            "staging",
            "--ref",
            "op://v/staging/f",
            "--api-url",
            &url,
        ],
    );

    // An environment key replaces the profile's key but keeps its URL.
    let output = dn_with(
        dir.path(),
        &["host", "list", "--profile", "staging", "--json"],
        &[("DEFINED_API_KEY", "fake-test-key")],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout_json(&output)["data"], json!([]));
    let seen = seen.lock().unwrap();
    assert!(
        seen.iter().any(|line| line.starts_with("GET /v2/hosts")),
        "{seen:?}"
    );
}
