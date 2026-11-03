//! `dn host wait` against a mock that answers each request with the next
//! body in a script, repeating the last, so a host can "check in" mid-wait.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

use common::mock_id;
use serde_json::{Value, json};

/// Serve `script` in order, one `(status, body)` per request, the last one
/// repeating. Returns the URL and the request targets seen.
fn serve(script: Vec<(&'static str, String)>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for (n, stream) in listener.incoming().enumerate() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            let mut parts = request_line.split(' ');
            let method = parts.next().unwrap_or_default();
            let target = parts.next().unwrap_or_default();
            log.lock().unwrap().push(format!("{method} {target}"));
            let (status, body) = &script[n.min(script.len() - 1)];
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

fn dn(url: &str, args: &[&str]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_dn"))
        .args(args)
        .env("DN_CONFIG_DIR", dir.path())
        .env("DEFINED_API_URL", url)
        .env("DEFINED_API_KEY", "fake-test-key")
        .output()
        .unwrap()
}

fn host(id: &str, last_seen: Value) -> (&'static str, String) {
    let body = json!({"data": {
        "id": id,
        "name": "Build Server",
        "ipAddresses": ["100.100.0.12"],
        "metadata": {"lastSeenAt": last_seen, "platform": "dnclient", "version": "0.9.3", "os": "linux"},
    }, "metadata": {}});
    ("200 OK", body.to_string())
}

fn stdout_json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout isn't JSON ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

#[test]
fn waits_until_the_host_checks_in() {
    let id = mock_id("host", "build server");
    let (url, seen) = serve(vec![
        host(&id, Value::Null),
        host(&id, json!("2026-11-03T01:00:00Z")),
    ]);
    let out = dn(&url, &["host", "wait", &id, "--interval", "1s"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.starts_with(&format!("\"Build Server\" ({id}) checked in.\n")),
        "{stdout}"
    );
    assert!(
        stdout.contains("Client:        dnclient 0.9.3 on linux\n"),
        "{stdout}"
    );
    assert!(
        stderr.contains(&format!(
            "Waiting for \"Build Server\" ({id}) to check in (up to 10m, every 1s)"
        )),
        "{stderr}"
    );
    let path = format!("GET /v2/hosts/{id}");
    assert_eq!(*seen.lock().unwrap(), [path.clone(), path]);
}

#[test]
fn json_prints_the_host_and_stays_quiet_while_waiting() {
    let id = mock_id("host", "build server");
    let (url, _) = serve(vec![
        host(&id, Value::Null),
        host(&id, json!("2026-11-03T01:00:00Z")),
    ]);
    let out = dn(&url, &["host", "wait", &id, "--interval", "1s", "--json"]);
    assert!(out.status.success());
    let res = stdout_json(&out);
    assert_eq!(res["data"]["id"], id.as_str());
    assert_eq!(
        res["data"]["metadata"]["lastSeenAt"],
        "2026-11-03T01:00:00Z"
    );
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_timeout_is_err_timeout_with_exit_1() {
    let id = mock_id("host", "build server");
    let (url, seen) = serve(vec![host(&id, Value::Null)]);
    let out = dn(
        &url,
        &[
            "host",
            "wait",
            &id,
            "--timeout",
            "1s",
            "--interval",
            "1s",
            "--json",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let envelope = stdout_json(&out);
    assert_eq!(envelope["status"], Value::Null);
    assert_eq!(envelope["errors"][0]["code"], "ERR_TIMEOUT");
    let message = envelope["errors"][0]["message"].as_str().unwrap();
    assert!(message.contains("hasn't checked in after 1s"), "{message}");
    // One check at the start and one on the deadline.
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[test]
fn since_skips_a_check_in_from_before_it() {
    let id = mock_id("host", "build server");
    let (url, _) = serve(vec![
        host(&id, json!("2026-11-02T12:00:00Z")),
        host(&id, json!("2026-11-03T01:00:05Z")),
    ]);
    let out = dn(
        &url,
        &[
            "host",
            "wait",
            &id,
            "--since",
            "2026-11-03T01:00:00Z",
            "--interval",
            "1s",
            "--json",
        ],
    );
    assert!(out.status.success());
    assert_eq!(
        stdout_json(&out)["data"]["metadata"]["lastSeenAt"],
        "2026-11-03T01:00:05Z"
    );
}

#[test]
fn a_missing_host_fails_on_the_first_check() {
    let id = mock_id("host", "deleted");
    let (url, seen) = serve(vec![(
        "404 Not Found",
        r#"{"errors":[{"code":"ERR_NOT_FOUND","message":"host not found"}]}"#.to_string(),
    )]);
    let out = dn(&url, &["host", "wait", &id, "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let envelope = stdout_json(&out);
    assert_eq!(envelope["status"], 404);
    assert_eq!(envelope["errors"][0]["code"], "ERR_NOT_FOUND");
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn bad_arguments_fail_before_any_request() {
    let id = mock_id("host", "build server");
    let (url, seen) = serve(vec![host(&id, Value::Null)]);
    for (args, exit, code) in [
        (vec!["--interval", "500ms"], 2, "ERR_USAGE"),
        (vec!["--timeout", "0s"], 2, "ERR_USAGE"),
        (vec!["--timeout", "1d"], 2, "ERR_USAGE"),
        (vec!["--since", "yesterday"], 1, "ERR_INVALID_ARGUMENT"),
    ] {
        let mut argv = vec!["host", "wait", id.as_str(), "--json"];
        argv.extend(&args);
        let out = dn(&url, &argv);
        assert_eq!(out.status.code(), Some(exit), "{args:?}");
        assert_eq!(stdout_json(&out)["errors"][0]["code"], code, "{args:?}");
    }
    let out = dn(&url, &["host", "wait", "host/x", "--json"]);
    assert_eq!(
        stdout_json(&out)["errors"][0]["code"],
        "ERR_INVALID_ARGUMENT"
    );
    assert!(seen.lock().unwrap().is_empty());
}
