//! API keys stored in the OS keyring. Debug builds read `DN_TEST_KEYRING`
//! as a stand-in keyring (a JSON file of profile → key), so these tests
//! never touch the machine's real keyring.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{Value, json};

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn keyring(&self) -> PathBuf {
        self.dir.path().join("test-keyring.json")
    }

    fn keyring_entries(&self) -> Value {
        match fs::read_to_string(self.keyring()) {
            Ok(text) => serde_json::from_str(&text).unwrap(),
            Err(_) => json!({}),
        }
    }

    fn auth_json(&self) -> Value {
        serde_json::from_str(&fs::read_to_string(self.dir.path().join("auth.json")).unwrap())
            .unwrap()
    }

    /// Run `dn` with `stdin` as its input, the test keyring, no key in the
    /// environment, and an API URL that refuses connections.
    fn run(&self, args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
        let keyring = self.keyring();
        let mut command = Command::new(env!("CARGO_BIN_EXE_dn"));
        command
            .args(args)
            .env("DN_CONFIG_DIR", self.dir.path())
            .env("DN_TEST_KEYRING", &keyring)
            .env_remove("DEFINED_API_KEY")
            .env_remove("DEFINED_API_URL")
            .env_remove("DN_PROFILE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn ok(&self, args: &[&str], stdin: &str) -> Value {
        let output = self.run(args, stdin, &[]);
        assert!(output.status.success(), "{args:?}: {output:?}");
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn login(&self, profile: &str, key: &str, extra: &[&str]) -> Value {
        let mut args = vec![
            "auth",
            "login",
            "--profile",
            profile,
            "--key-stdin",
            "--no-verify",
            "--json",
        ];
        args.extend_from_slice(extra);
        self.ok(&args, key)
    }
}

fn error_message(output: &Output) -> String {
    let payload: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {output:?}"));
    payload["errors"][0]["message"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn login_stores_the_key_in_the_keyring_not_on_disk() {
    let env = Env::new();
    let out = env.login("default", "  dnkey-secret-1\n", &[]);
    assert_eq!(out["profile"], "default");
    let entry = &out["profiles"][0];
    assert_eq!(entry["key_source"], "keyring");
    assert_eq!(entry["api_key_ref"], Value::Null);

    assert_eq!(
        env.keyring_entries(),
        json!({ "default": "dnkey-secret-1" })
    );
    assert_eq!(env.auth_json()["profiles"]["default"]["key"], "keyring");
    let auth_text = fs::read_to_string(env.dir.path().join("auth.json")).unwrap();
    assert!(!auth_text.contains("dnkey-secret-1"), "{auth_text}");

    let status = env.ok(&["auth", "status", "--json"], "");
    assert_eq!(status["source"], "keyring");
    assert_eq!(status["profile"], "default");
    assert_eq!(status["api_key_ref"], Value::Null);
}

/// A local API that records each request's Authorization header and answers
/// with an empty list.
fn serve() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap() <= 2 {
                    break;
                }
                if let Some(value) = line.strip_prefix("authorization: ") {
                    log.lock().unwrap().push(value.trim().to_string());
                } else if let Some(value) = line.strip_prefix("Authorization: ") {
                    log.lock().unwrap().push(value.trim().to_string());
                }
            }
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
fn api_calls_send_the_keyring_key_for_the_selected_profile() {
    let env = Env::new();
    let (url, seen) = serve();
    env.login("prod", "prod-key", &["--api-url", &url]);
    env.login("staging", "staging-key", &["--api-url", &url]);

    for (profile, key) in [("prod", "prod-key"), ("staging", "staging-key")] {
        let output = env.run(&["host", "list", "--profile", profile, "--json"], "", &[]);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            seen.lock().unwrap().last().map(String::as_str),
            Some(format!("Bearer {key}").as_str())
        );
    }

    // DEFINED_API_KEY still wins over the keyring.
    let output = env.run(
        &["host", "list", "--json"],
        "",
        &[("DEFINED_API_KEY", "env-key")],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        seen.lock().unwrap().last().map(String::as_str),
        Some("Bearer env-key")
    );
}

#[test]
fn login_verifies_the_key_before_storing_it() {
    let env = Env::new();
    // An API that refuses connections: verification fails, nothing is saved.
    let output = env.run(
        &[
            "auth",
            "login",
            "--key-stdin",
            "--api-url",
            "http://127.0.0.1:1",
            "--json",
        ],
        "some-key",
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        error_message(&output).contains("could not reach the API"),
        "{output:?}"
    );
    assert_eq!(env.keyring_entries(), json!({}));
    assert!(!env.dir.path().join("auth.json").exists());
}

#[test]
fn logging_out_removes_the_keyring_entry() {
    let env = Env::new();
    env.login("a", "key-a", &[]);
    env.login("b", "key-b", &[]);

    env.ok(&["auth", "logout", "--profile", "a", "--json"], "");
    assert_eq!(env.keyring_entries(), json!({ "b": "key-b" }));

    env.login("c", "key-c", &[]);
    env.ok(&["auth", "logout", "--all", "--json"], "");
    assert_eq!(env.keyring_entries(), json!({}));
}

#[test]
fn switching_a_profile_to_1password_removes_its_keyring_entry() {
    let env = Env::new();
    env.login("default", "key", &[]);
    let out = env.ok(
        &[
            "auth",
            "login",
            "--ref",
            "op://Personal/dn/credential",
            "--no-verify",
            "--json",
        ],
        "",
    );
    assert_eq!(out["profiles"][0]["key_source"], "1password");
    assert_eq!(env.keyring_entries(), json!({}));
}

#[test]
fn a_missing_keyring_entry_says_how_to_fix_it() {
    let env = Env::new();
    env.login("work", "key", &[]);
    fs::write(env.keyring(), "{}").unwrap();

    let output = env.run(&["host", "list", "--json"], "", &[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let message = error_message(&output);
    assert!(
        message.contains("dn auth login --profile work"),
        "{message}"
    );
}

#[test]
fn an_unavailable_keyring_points_at_the_alternatives() {
    let env = Env::new();
    let output = env.run(
        &["auth", "login", "--key-stdin", "--no-verify", "--json"],
        "key",
        &[("DN_TEST_KEYRING", "unavailable")],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let message = error_message(&output);
    assert!(message.contains("no OS keyring is available"), "{message}");
    assert!(message.contains("--ref"), "{message}");
    assert!(message.contains("DEFINED_API_KEY"), "{message}");
    assert!(
        !env.dir.path().join("auth.json").exists(),
        "a failed keyring write saves nothing"
    );
}

#[test]
fn non_interactive_login_needs_key_stdin_or_ref() {
    let env = Env::new();
    for (args, stdin, expected) in [
        (&["auth", "login", "--json"][..], "", "pass --key-stdin"),
        (
            &["auth", "login", "--key-stdin", "--no-verify", "--json"],
            "   \n",
            "no API key entered",
        ),
        (
            &["auth", "login", "--key-stdin", "--no-verify", "--json"],
            "two words",
            "no spaces or line breaks",
        ),
    ] {
        let output = env.run(args, stdin, &[]);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        let message = error_message(&output);
        assert!(message.contains(expected), "{args:?}: {message}");
    }
    let output = env.run(
        &[
            "auth",
            "login",
            "--key-stdin",
            "--ref",
            "op://v/i/f",
            "--json",
        ],
        "",
        &[],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}
