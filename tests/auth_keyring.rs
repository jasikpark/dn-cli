//! API keys stored in the OS keyring. Debug builds read `DN_TEST_KEYRING`
//! as a stand-in keyring (a JSON file of account → key), so these tests
//! never touch the machine's real keyring. Release builds ignore it, so the
//! file only compiles with debug assertions: under `cargo test --release`
//! these tests would overwrite and delete the developer's real entries.
#![cfg(debug_assertions)]

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Write};
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

    /// The keyring account `profile` points at in auth.json: what follows
    /// `keyring:` in its `key`, or the profile name for a bare `keyring`.
    fn account(&self, profile: &str) -> String {
        let key = self.auth_json()["profiles"][profile]["key"].clone();
        match key.as_str().unwrap() {
            "keyring" => profile.to_string(),
            key => key.strip_prefix("keyring:").unwrap().to_string(),
        }
    }

    /// The keyring as profile → key, read through each profile's account.
    /// Panics on an entry no profile points at.
    fn keys_by_profile(&self) -> Value {
        let mut entries = self.keyring_entries().as_object().unwrap().clone();
        let mut keys = serde_json::Map::new();
        if let Some(profiles) = self.auth_json()["profiles"].as_object() {
            for (name, profile) in profiles {
                if profile["key"]
                    .as_str()
                    .is_some_and(|k| k.starts_with("keyring"))
                    && let Some(key) = entries.remove(&self.account(name))
                {
                    keys.insert(name.clone(), key);
                }
            }
        }
        assert!(
            entries.is_empty(),
            "entries no profile points at: {entries:?}"
        );
        Value::Object(keys)
    }

    fn auth_json(&self) -> Value {
        serde_json::from_str(&fs::read_to_string(self.dir.path().join("auth.json")).unwrap())
            .unwrap()
    }

    /// Run `dn` with `stdin` as its input, the test keyring, no key in the
    /// environment, and no `op` on PATH. A profile logged in without
    /// `--api-url` talks to the production API, so `auth status` there needs
    /// `--offline`.
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
            .env("PATH", "")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn().unwrap();
        // A command that fails preflight exits without reading stdin, so the
        // write can race its exit and hit a closed pipe.
        match child.stdin.take().unwrap().write_all(stdin.as_bytes()) {
            Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
            result => result.unwrap(),
        }
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
        env.keys_by_profile(),
        json!({ "default": "dnkey-secret-1" })
    );
    let account = env.account("default");
    let id = account.strip_prefix("default/").expect(&account);
    assert_eq!(id.len(), 16, "{account}");
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "{account}");
    let auth_text = fs::read_to_string(env.dir.path().join("auth.json")).unwrap();
    assert!(!auth_text.contains("dnkey-secret-1"), "{auth_text}");

    let status = env.ok(&["auth", "status", "--offline", "--json"], "");
    assert_eq!(status["source"], "keyring");
    assert_eq!(status["profile"], "default");
    assert_eq!(status["api_key_ref"], Value::Null);
}

/// A local API that records each request's Authorization header and answers
/// with an empty list.
fn serve() -> (String, Arc<Mutex<Vec<String>>>) {
    serve_accepting(None)
}

/// Like [`serve`], but with `Some(key)` only `Bearer <key>` gets a 200; any
/// other key gets the API's 401.
fn serve_accepting(accepted: Option<&'static str>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            let mut authorization = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap() <= 2 {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("authorization: ") {
                    authorization = line[line.len() - value.len()..].trim().to_string();
                    log.lock().unwrap().push(authorization.clone());
                }
            }
            let ok = accepted.is_none_or(|key| authorization == format!("Bearer {key}"));
            let (status, body) = if ok {
                ("200 OK", r#"{"data":[],"metadata":{}}"#)
            } else {
                (
                    "401 Unauthorized",
                    r#"{"errors":[{"code":"ERR_UNAUTHORIZED","message":"bad key"}]}"#,
                )
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
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
fn login_accepts_a_key_without_host_list_permission() {
    let env = Env::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut line = String::new();
        let mut authorization = String::new();
        while reader.read_line(&mut line).unwrap() > 2 {
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("authorization: ") {
                authorization = line[line.len() - value.len()..].trim().to_string();
            }
            line.clear();
        }
        let (status, body) = if request_line.trim() == "GET /v2/whoami HTTP/1.1"
            && authorization == "Bearer scoped-key"
        {
            (
                "200 OK",
                r#"{"data":{"actorType":"apiKey","actor":{"id":"dnkey-test"},"organization":{"id":"org-test"}},"metadata":{}}"#,
            )
        } else {
            (
                "403 Forbidden",
                r#"{"errors":[{"code":"ERR_FORBIDDEN","message":"missing hosts:list"}]}"#,
            )
        };
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        request_line
    });

    let output = env.run(
        &["auth", "login", "--key-stdin", "--api-url", &url, "--json"],
        "scoped-key",
        &[],
    );
    let request_line = server.join().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(request_line.trim(), "GET /v2/whoami HTTP/1.1");
    assert_eq!(env.keys_by_profile(), json!({ "default": "scoped-key" }));
}

#[test]
fn logging_out_removes_the_keyring_entry() {
    let env = Env::new();
    env.login("a", "key-a", &[]);
    env.login("b", "key-b", &[]);

    env.ok(&["auth", "logout", "--profile", "a", "--json"], "");
    assert_eq!(env.keys_by_profile(), json!({ "b": "key-b" }));

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
    assert_eq!(out["profiles"][0]["key_source"], "file");
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
fn a_keyring_entry_edited_outside_dn_is_trimmed_or_refused() {
    let env = Env::new();
    let (url, seen) = serve();
    env.login("work", "key", &["--api-url", &url]);

    let account = env.account("work");
    fs::write(
        env.keyring(),
        json!({ &account: "  edited-key\n" }).to_string(),
    )
    .unwrap();
    let output = env.run(&["host", "list", "--json"], "", &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        seen.lock().unwrap().last().map(String::as_str),
        Some("Bearer edited-key")
    );

    for bad in ["", "two words"] {
        fs::write(env.keyring(), json!({ &account: bad }).to_string()).unwrap();
        let output = env.run(&["host", "list", "--json"], "", &[]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(
            error_message(&output).contains("is not an API key"),
            "{output:?}"
        );
    }
}

#[test]
fn a_hand_edited_profile_name_is_refused_and_never_reset() {
    let env = Env::new();
    let file = env.dir.path().join("auth.json");
    let text = r#"{"version":2,"default_profile":"Work","profiles":{"Work":{"key":"keyring"},"work":{"key":"keyring"}}}"#;
    fs::write(&file, text).unwrap();

    for (args, stdin) in [
        (&["host", "list", "--json"][..], ""),
        (
            &["auth", "login", "--key-stdin", "--no-verify", "--json"][..],
            "key",
        ),
    ] {
        let output = env.run(args, stdin, &[]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(
            error_message(&output).contains("rename it in auth.json"),
            "{output:?}"
        );
    }
    // DEFINED_API_KEY skips a file it can't read, but not this one, whose
    // default profile may point at another API.
    let output = env.run(
        &["auth", "status", "--offline", "--json"],
        "",
        &[("DEFINED_API_KEY", "env-key")],
    );
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["source"], "invalid", "{output:?}");
    assert_eq!(fs::read_to_string(&file).unwrap(), text);
    assert_eq!(env.keyring_entries(), json!({}));
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
fn an_unavailable_keyring_fails_before_reading_a_key() {
    let env = Env::new();
    // Stdin is a 1Password reference, which the key check would reject;
    // the keyring error coming first shows the key was never read.
    let output = env.run(
        &["auth", "login", "--key-stdin", "--no-verify", "--json"],
        "op://vault/item/field",
        &[("DN_TEST_KEYRING", "unavailable")],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        error_message(&output).contains("no OS keyring is available"),
        "{output:?}"
    );
}

#[test]
fn a_key_at_the_length_cap_with_a_trailing_newline_is_accepted() {
    let env = Env::new();
    let key = "k".repeat(1280);
    let output = env.run(
        &["auth", "login", "--key-stdin", "--no-verify", "--json"],
        &format!("{key}\n"),
        &[],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(env.keys_by_profile(), json!({ "default": key }));
}

#[test]
fn a_key_over_the_length_cap_is_refused() {
    let env = Env::new();
    let output = env.run(
        &["auth", "login", "--key-stdin", "--no-verify", "--json"],
        &"k".repeat(1281),
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(error_message(&output).contains("1280"), "{output:?}");
    assert_eq!(env.keyring_entries(), json!({}));
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

#[test]
fn login_checks_the_key_itself_against_the_api() {
    let env = Env::new();
    let (url, seen) = serve_accepting(Some("good-key"));
    let login = |key: &str| {
        env.run(
            &["auth", "login", "--key-stdin", "--api-url", &url, "--json"],
            key,
            &[],
        )
    };

    let rejected = login("wrong-key");
    assert_eq!(rejected.status.code(), Some(1), "{rejected:?}");
    let message = error_message(&rejected);
    assert!(message.starts_with("the API rejected the key"), "{message}");
    assert_eq!(
        env.keyring_entries(),
        json!({}),
        "a rejected key is not stored"
    );
    assert!(!env.dir.path().join("auth.json").exists());

    let accepted = login("good-key\r\n");
    assert!(accepted.status.success(), "{accepted:?}");
    assert_eq!(env.keys_by_profile(), json!({ "default": "good-key" }));
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        ["Bearer wrong-key", "Bearer good-key"]
    );
}

#[test]
fn logging_in_again_replaces_the_stored_key() {
    let env = Env::new();
    env.login("default", "old-key", &[]);
    let old_account = env.account("default");
    env.login("default", "new-key", &[]);
    assert_ne!(env.account("default"), old_account);
    assert_eq!(env.keys_by_profile(), json!({ "default": "new-key" }));
}

#[test]
fn config_directories_sharing_a_keyring_keep_their_own_keys() {
    let (one, two) = (Env::new(), Env::new());
    let shared = one.keyring();
    let shared = [("DN_TEST_KEYRING", shared.to_str().unwrap())];
    let login = |env: &Env, key: &str| {
        let args = ["auth", "login", "--key-stdin", "--no-verify", "--json"];
        assert!(env.run(&args, key, &shared).status.success());
    };
    login(&one, "key-one");
    login(&two, "key-two");
    assert_eq!(
        one.keyring_entries(),
        json!({ one.account("default"): "key-one", two.account("default"): "key-two" })
    );

    let logout = two.run(&["auth", "logout", "--json"], "", &shared);
    assert!(logout.status.success(), "{logout:?}");
    assert_eq!(one.keys_by_profile(), json!({ "default": "key-one" }));
}

/// A profile whose `key` is the bare `keyring`, as every login was stored
/// through 0.4.9, with its entry under the profile name.
fn profile_stored_under_its_name(env: &Env, url: &str) {
    fs::write(env.keyring(), r#"{"default":"old-key"}"#).unwrap();
    fs::write(
        env.dir.path().join("auth.json"),
        json!({"version": 2, "default_profile": "default",
            "profiles": {"default": {"key": "keyring", "api_url": url}}})
        .to_string(),
    )
    .unwrap();
}

#[test]
fn a_profile_stored_under_its_name_is_still_read() {
    let env = Env::new();
    let (url, seen) = serve();
    profile_stored_under_its_name(&env, &url);

    let output = env.run(&["host", "list", "--json"], "", &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(seen.lock().unwrap().as_slice(), ["Bearer old-key"]);
    let list = env.ok(&["auth", "list", "--json"], "");
    assert_eq!(list["profiles"][0]["key_source"], "keyring");
    assert_eq!(list["profiles"][0]["api_key_ref"], Value::Null);
}

#[test]
fn logging_in_or_out_removes_an_entry_stored_under_the_profile_name() {
    let env = Env::new();
    profile_stored_under_its_name(&env, "http://127.0.0.1:1");
    env.login("default", "new-key", &[]);
    assert_ne!(env.account("default"), "default");
    assert_eq!(env.keys_by_profile(), json!({ "default": "new-key" }));

    profile_stored_under_its_name(&env, "http://127.0.0.1:1");
    env.ok(&["auth", "logout", "--json"], "");
    assert_eq!(env.keyring_entries(), json!({}));
}

#[test]
fn a_keyring_account_dn_could_not_have_written_is_refused() {
    let env = Env::new();
    for account in ["", "Work/abc", "work/", "work/ABC", "a b"] {
        fs::write(
            env.dir.path().join("auth.json"),
            json!({"version": 2, "default_profile": "work",
                "profiles": {"work": {"key": format!("keyring:{account}")}}})
            .to_string(),
        )
        .unwrap();
        let status = env.ok(&["auth", "status", "--offline", "--json"], "");
        assert_eq!(status["source"], "invalid", "{account:?}");
        let message = status["message"].as_str().unwrap();
        assert!(
            message.contains("dn auth login --profile work"),
            "{message}"
        );
    }
}

#[test]
fn invalid_keyring_accounts_are_not_deleted_on_login_or_logout() {
    let env = Env::new();
    let write_bad = || {
        fs::write(
            env.dir.path().join("auth.json"),
            json!({"version": 2, "default_profile": "work",
                "profiles": {"work": {"key": "keyring:Work/abc"}}})
            .to_string(),
        )
        .unwrap();
    };
    write_bad();
    // With an unavailable keyring, attempting to delete the bogus entry would
    // warn and report `work` in `keyring_left`.
    let out = env.run(
        &["auth", "logout", "--profile", "work", "--json"],
        "",
        &[("DN_TEST_KEYRING", "unavailable")],
    );
    assert!(out.status.success(), "{out:?}");
    let payload: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["keyring_left"], json!([]));
    assert!(
        String::from_utf8_lossy(&out.stderr).is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    write_bad();
    let out = env.run(
        &[
            "auth",
            "login",
            "--profile",
            "work",
            "--ref",
            "op://Vault/Item/key",
            "--no-verify",
            "--json",
        ],
        "",
        &[("DN_TEST_KEYRING", "unavailable")],
    );
    assert!(out.status.success(), "{out:?}");
    let payload: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["keyring_left"], json!([]));
    assert!(
        String::from_utf8_lossy(&out.stderr).is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_profile_table_shows_keyring_without_the_account() {
    let env = Env::new();
    env.login("default", "key", &[]);
    let output = env.run(&["auth", "list"], "", &[]);
    let table = String::from_utf8_lossy(&output.stdout);
    assert!(table.trim_end().ends_with(" keyring"), "{table}");
}

#[test]
fn keys_that_cant_be_api_keys_are_refused() {
    let env = Env::new();
    let huge = "k".repeat(5000);
    for (stdin, expected) in [
        ("op://Personal/dn/credential", "pass it with --ref"),
        ("abc\u{0}def", "printable ASCII"),
        ("clé", "printable ASCII"),
        (huge.as_str(), "longer than"),
    ] {
        let output = env.run(
            &["auth", "login", "--key-stdin", "--no-verify", "--json"],
            stdin,
            &[],
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let message = error_message(&output);
        assert!(message.contains(expected), "{expected}: {message}");
    }
    assert_eq!(env.keyring_entries(), json!({}));
}

#[test]
fn logout_with_an_unavailable_keyring_warns_and_still_logs_out() {
    let env = Env::new();
    env.login("a", "key-a", &[]);
    env.login("b", "key-b", &[]);

    let output = env.run(
        &["auth", "logout", "--profile", "a", "--json"],
        "",
        &[("DN_TEST_KEYRING", "unavailable")],
    );
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("could not remove the OS keyring entry for profile \"a\""),
        "{stderr}"
    );
    assert!(env.auth_json()["profiles"].get("a").is_none());
    let out: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(out["keyring_left"], json!(["a"]));
}

#[test]
fn profile_names_must_be_lowercase() {
    // Windows Credential Manager can't tell "Work" and "work" apart.
    let env = Env::new();
    let output = env.run(
        &[
            "auth",
            "login",
            "--profile",
            "Work",
            "--key-stdin",
            "--no-verify",
            "--json",
        ],
        "key",
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(error_message(&output).contains("lowercase"), "{output:?}");
    assert_eq!(env.keyring_entries(), json!({}));
}

/// A login whose keyring write succeeds but whose auth.json save fails,
/// because a directory sits at `blocked` in the config dir once `setup` has
/// run. `auth.json.lock` there fails the save at taking the lock (a directory
/// can't be opened for writing); `auth.json` fails it later, at renaming the
/// new file into place. Both fail for every user, root included; a read-only
/// config dir would not stop root, which is what containers and some CI
/// runners run tests as.
fn login_whose_save_fails(env: &Env, blocked: &str, setup: impl FnOnce(&Env)) -> Output {
    let config = env.dir.path().join("config");
    fs::create_dir(&config).unwrap();
    let config_env = Env {
        dir: tempfile::tempdir_in(&config).unwrap(),
    };
    setup(&config_env);
    fs::create_dir(config_env.dir.path().join(blocked)).unwrap();
    env.run(
        &["auth", "login", "--key-stdin", "--no-verify", "--json"],
        "new-key",
        &[("DN_CONFIG_DIR", config_env.dir.path().to_str().unwrap())],
    )
}

#[test]
fn a_failed_save_removes_a_new_keyring_entry() {
    let env = Env::new();
    let output = login_whose_save_fails(&env, "auth.json.lock", |_| {});
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        error_message(&output).contains("auth.json.lock"),
        "{output:?}"
    );
    assert_eq!(env.keyring_entries(), json!({}));
}

/// A save that takes the lock and then fails at replacing auth.json rolls
/// the keyring back too.
#[test]
fn a_save_that_fails_after_the_lock_removes_a_new_keyring_entry() {
    let env = Env::new();
    let output = login_whose_save_fails(&env, "auth.json", |_| {});
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let message = error_message(&output);
    assert!(
        message.contains("failed to replace") && !message.contains("auth.json.lock"),
        "{output:?}"
    );
    assert_eq!(env.keyring_entries(), json!({}));
}

#[test]
fn a_failed_save_leaves_the_key_an_existing_profile_uses() {
    let env = Env::new();
    fs::write(env.keyring(), r#"{"default":"old-key"}"#).unwrap();
    let output = login_whose_save_fails(&env, "auth.json.lock", |config| {
        fs::write(
            config.dir.path().join("auth.json"),
            r#"{"version":2,"default_profile":"default","profiles":{"default":{"key":"keyring"}}}"#,
        )
        .unwrap();
    });
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(env.keyring_entries(), json!({ "default": "old-key" }));
}

#[test]
fn parallel_logins_to_different_profiles_all_land() {
    // Each login writes the keyring before taking the auth.json lock, so the
    // logins overlap there; auth.json itself is read, changed and written
    // under the lock. Neither may lose another login's profile or key.
    let env = Arc::new(Env::new());
    let names: Vec<String> = (0..8).map(|i| format!("p{i}")).collect();
    let logins: Vec<_> = names
        .iter()
        .map(|name| {
            let env = Arc::clone(&env);
            let name = name.clone();
            thread::spawn(move || {
                let key = format!("key-{name}");
                env.run(
                    &[
                        "auth",
                        "login",
                        "--profile",
                        &name,
                        "--key-stdin",
                        "--no-verify",
                        "--json",
                    ],
                    &key,
                    &[],
                )
            })
        })
        .collect();
    for (name, login) in names.iter().zip(logins) {
        let output = login.join().unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
    }

    let auth = env.auth_json();
    let keyring = env.keyring_entries();
    for name in &names {
        assert!(
            auth["profiles"].get(name).is_some(),
            "{name} missing from {auth}"
        );
        assert_eq!(
            keyring[env.account(name)],
            format!("key-{name}"),
            "{name} in {keyring}"
        );
    }
}
