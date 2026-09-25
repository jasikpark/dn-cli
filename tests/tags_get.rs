use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

/// Serve `tag_body` for `GET /v1/tags/…` and one Admins role for
/// `GET /v1/roles…`, recording each request's path and query.
fn serve(tag_body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
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
            // Drain the headers; these are bodiless GETs.
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            let target = request_line
                .split(' ')
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let body = if target.starts_with("/v1/roles") {
                r#"{"data":[{"id":"role-ADM","name":"Admins"}],"metadata":{}}"#
            } else {
                tag_body
            };
            log.lock().unwrap().push(target);
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

const TAG: &str = r#"{"data":{"name":"env:prod","hostCount":2,"firewallRulesCount":1,
    "firewallRules":[{"protocol":"TCP","portRange":{"from":22,"to":22},
    "allowedRoleID":"role-ADM","allowedTags":null,"description":"ssh"}]}}"#;

#[test]
fn tags_get_names_rule_roles_from_the_roles_list() {
    let (url, seen) = serve(TAG);
    let out = dn(&url, &["tags", "get", "env:prod"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("env:prod\nHosts: 2\n"), "{stdout}");
    assert!(stdout.contains("\"Admins\" hosts"), "{stdout}");
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0], "/v1/tags/env:prod");
    assert!(seen[1].starts_with("/v1/roles"), "{seen:?}");
}

#[test]
fn tags_get_json_passes_the_response_through_without_a_roles_lookup() {
    let (url, seen) = serve(TAG);
    let out = dn(&url, &["--json", "tags", "get", "env:prod"]);
    assert!(out.status.success(), "{out:?}");
    let got: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let want: serde_json::Value = serde_json::from_str(TAG).unwrap();
    assert_eq!(got, want);
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn tags_get_rejects_non_object_data() {
    let (url, _) = serve(r#"{"data":[]}"#);
    let out = dn(&url, &["tags", "get", "env:prod"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("missing tag data"),
        "{out:?}"
    );
}

#[test]
fn tags_get_rejects_a_malformed_tag_before_any_request() {
    let (url, seen) = serve(TAG);
    let out = dn(&url, &["tags", "get", "nocolon"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(seen.lock().unwrap().is_empty());
}
