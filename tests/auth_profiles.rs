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
    assert!(stderr(&first).contains("converted"), "{first:?}");
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

/// Start `n` `auth status --json` calls at once and wait for all of them.
fn run_in_parallel(dir: &Path, n: usize) {
    let children: Vec<_> = (0..n)
        .map(|_| {
            Command::new(env!("CARGO_BIN_EXE_dn"))
                .args(["auth", "status", "--json"])
                .env("DN_CONFIG_DIR", dir)
                .env_remove("DEFINED_API_KEY")
                .env_remove("DEFINED_API_URL")
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
        assert_eq!(stdout_json(&output)["profile"], "default", "{output:?}");
    }
    let leftovers: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|name| name != "auth.json")
        .collect();
    assert!(leftovers.is_empty(), "files left behind: {leftovers:?}");
}

#[test]
fn parallel_calls_migrate_to_one_valid_file() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("auth.json"), LEGACY).unwrap();
    run_in_parallel(dir.path(), 8);
    assert_eq!(auth_json(dir.path()), migrated());
}

/// Moving `api_url` touches two files; a call that sees `config.json`
/// already stripped must also see the migrated `auth.json`, or the URL
/// would be lost. Repeated to give an interleaving a chance to show up.
#[test]
fn parallel_calls_never_lose_the_moved_api_url() {
    let mut want = migrated();
    want["profiles"]["default"]["api_url"] = json!("https://staging.example");
    for _ in 0..10 {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("auth.json"), LEGACY).unwrap();
        fs::write(
            dir.path().join("config.json"),
            r#"{"api_url":"https://staging.example"}"#,
        )
        .unwrap();
        run_in_parallel(dir.path(), 8);
        assert_eq!(auth_json(dir.path()), want);
    }
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

/// The `profiles` entry named `name` in a command's JSON output.
fn entry<'a>(out: &'a Value, name: &str) -> &'a Value {
    out["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == name)
        .unwrap_or_else(|| panic!("no profile {name} in {out}"))
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
    assert_eq!(staging["default_profile"], "staging");
    assert_eq!(
        entry(&staging, "staging")["api_url"],
        "https://staging.example"
    );

    // The latest login becomes the default, like `gh` and `tg`...
    let prod = login(
        d,
        &["--profile", "prod", "--ref", "op://Personal/dn/credential"],
    );
    assert_eq!(prod["default_profile"], "prod");
    assert_eq!(entry(&prod, "prod")["api_url"], "https://api.defined.net");
    assert_eq!(prod["profiles"].as_array().unwrap().len(), 2);

    // ...unless asked not to.
    let qa = login(
        d,
        &[
            "--profile",
            "qa",
            "--ref",
            "op://Dev/dn-qa/credential",
            "--keep-default",
        ],
    );
    assert_eq!(qa["default_profile"], "prod");
    assert_eq!(entry(&qa, "qa")["default"], false);

    let list = stdout_json(&dn(d, &["auth", "list", "--json"]));
    assert_eq!(
        list,
        json!({
            "default_profile": "prod",
            "profiles": [
                { "name": "prod", "default": true, "api_url": "https://api.defined.net",
                  "api_key_ref": "op://Personal/dn/credential" },
                { "name": "qa", "default": false, "api_url": "https://api.defined.net",
                  "api_key_ref": "op://Dev/dn-qa/credential" },
                { "name": "staging", "default": false, "api_url": "https://staging.example",
                  "api_key_ref": "op://Dev/dn-staging/credential" },
            ],
        })
    );

    let status = |args: &[&str], env: &[(&str, &str)]| {
        let mut all = vec!["auth", "status", "--json"];
        all.extend_from_slice(args);
        stdout_json(&dn_with(d, &all, env))
    };
    assert_eq!(status(&[], &[])["profile"], "prod");
    assert_eq!(status(&["--profile", "staging"], &[])["profile"], "staging");
    let from_env = status(&[], &[("DN_PROFILE", "staging")]);
    assert_eq!(from_env["profile"], "staging");
    assert_eq!(from_env["api_key_ref"], "op://Dev/dn-staging/credential");
    assert_eq!(from_env["api_url"], "https://staging.example");
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

    let switched = stdout_json(&dn(d, &["auth", "switch", "staging", "--json"]));
    assert_eq!(switched["default_profile"], "staging");
    assert_eq!(switched["profiles"].as_array().unwrap().len(), 3);
    assert_eq!(status(&[], &[])["profile"], "staging");

    // Removing a profile that isn't the default leaves the default alone.
    let logout = stdout_json(&dn(d, &["auth", "logout", "--profile", "qa", "--json"]));
    assert_eq!(logout["removed"], true);
    assert_eq!(logout["profile"], "qa");
    assert_eq!(logout["default_profile"], "staging");

    // Removing the default picks another one.
    let logout = stdout_json(&dn(d, &["auth", "logout", "--json"]));
    assert_eq!(logout["profile"], "staging");
    assert_eq!(logout["default_profile"], "prod");
    assert_eq!(logout["profiles"].as_array().unwrap().len(), 1);

    let logout = stdout_json(&dn(d, &["auth", "logout", "--json"]));
    assert_eq!(logout["profile"], "prod");
    assert_eq!(logout["default_profile"], Value::Null);
    assert_eq!(logout["profiles"], json!([]));
    assert!(
        !d.join("auth.json").exists(),
        "the last logout removes the file"
    );
}

#[test]
fn changing_commands_list_the_profiles_for_humans() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let text = |args: &[&str]| {
        let output = dn(d, args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap()
    };

    let out = text(&[
        "auth",
        "login",
        "--no-verify",
        "--profile",
        "a",
        "--ref",
        "op://v/a/f",
    ]);
    assert!(out.contains("Default profile is now \"a\"."), "{out}");
    assert!(out.contains("PROFILE"), "{out}");
    let out = text(&[
        "auth",
        "login",
        "--no-verify",
        "--profile",
        "b",
        "--ref",
        "op://v/b/f",
    ]);
    assert!(out.contains("Default profile is now \"b\"."), "{out}");
    assert!(out.contains("*  b"), "{out}");
    let out = text(&["auth", "switch", "a"]);
    assert!(out.contains("*  a"), "{out}");
    let out = text(&["auth", "logout"]);
    assert!(out.contains("Removed profile \"a\"."), "{out}");
    assert!(out.contains("Default profile is now \"b\"."), "{out}");
    assert!(out.contains("*  b"), "{out}");
}

#[test]
fn config_api_url_moves_into_the_default_profile() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    fs::write(d.join("auth.json"), LEGACY).unwrap();
    fs::write(
        d.join("config.json"),
        r#"{"api_url":"https://staging.example/"}"#,
    )
    .unwrap();

    let output = dn(d, &["auth", "status", "--json"]);
    assert!(output.status.success(), "{output:?}");
    assert!(stderr(&output).contains("moved api_url"), "{output:?}");
    assert_eq!(stdout_json(&output)["api_url"], "https://staging.example");
    let mut want = migrated();
    want["profiles"]["default"]["api_url"] = json!("https://staging.example");
    assert_eq!(auth_json(d), want);
    assert!(
        !d.join("config.json").exists(),
        "an emptied config.json is removed"
    );
}

#[test]
fn config_api_url_alone_becomes_a_keyless_default_profile() {
    // DEFINED_API_KEY users could set only a URL in config.json.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    fs::write(
        d.join("config.json"),
        r#"{"api_url":"https://staging.example","other":1}"#,
    )
    .unwrap();

    let output = dn_with(
        d,
        &["auth", "status", "--json"],
        &[("DEFINED_API_KEY", "k")],
    );
    assert!(output.status.success(), "{output:?}");
    let status = stdout_json(&output);
    assert_eq!(status["source"], "env");
    assert_eq!(status["profile"], "default");
    assert_eq!(status["api_url"], "https://staging.example");
    assert_eq!(
        auth_json(d),
        json!({
            "version": 2,
            "default_profile": "default",
            "profiles": { "default": { "api_url": "https://staging.example" } },
        })
    );
    let config: Value =
        serde_json::from_str(&fs::read_to_string(d.join("config.json")).unwrap()).unwrap();
    assert_eq!(config, json!({ "other": 1 }), "other settings stay put");
}

#[test]
fn config_api_url_never_overrides_a_profile_url() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    login(
        d,
        &[
            "--ref",
            "op://v/i/f",
            "--api-url",
            "https://profile.example",
        ],
    );
    fs::write(
        d.join("config.json"),
        r#"{"api_url":"https://config.example"}"#,
    )
    .unwrap();

    let status = stdout_json(&dn(d, &["auth", "status", "--json"]));
    assert_eq!(status["api_url"], "https://profile.example");
    assert!(!d.join("config.json").exists());
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
            "--api-url: expected an https:// URL",
        ),
        (
            &[
                "auth",
                "login",
                "--ref",
                "op://v/i/f",
                "--api-url",
                "http://staging.example",
                "--json",
            ],
            &[],
            "ERR_INVALID_ARGUMENT",
            "refusing to send the API key over plain http://",
        ),
        (
            &["host", "list", "--json"],
            &[
                ("DEFINED_API_KEY", "k"),
                ("DEFINED_API_URL", "http://staging.example"),
            ],
            "ERR_LOCAL",
            "DEFINED_API_URL is not usable: refusing to send the API key over plain http://",
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

#[test]
fn a_non_production_url_is_noted_for_humans_only() {
    let dir = tempfile::tempdir().unwrap();
    let (url, _) = serve_empty_hosts();
    login(
        dir.path(),
        &[
            "--profile",
            "mock",
            "--ref",
            "op://v/i/f",
            "--api-url",
            &url,
        ],
    );
    let env = [("DEFINED_API_KEY", "fake-test-key")];

    let human = dn_with(dir.path(), &["host", "list"], &env);
    assert!(human.status.success(), "{human:?}");
    assert_eq!(
        stderr(&human).trim(),
        format!("note: using {url} (from profile \"mock\")")
    );

    let json_output = dn_with(dir.path(), &["host", "list", "--json"], &env);
    assert!(json_output.status.success(), "{json_output:?}");
    assert!(json_output.stderr.is_empty(), "{json_output:?}");
}
