use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

/// Serve a two-page audit log: a request carrying `cursor=p2` gets `PAGE_2`,
/// any other gets `PAGE_1`. Records each request's path and query.
fn serve() -> (String, Arc<Mutex<Vec<String>>>) {
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
            let body = if target.contains("cursor=p2") {
                PAGE_2
            } else {
                PAGE_1
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

const PAGE_1: &str = r#"{"data":[
    {"id":"log-3","timestamp":"2026-01-03T00:00:00.5Z",
     "actor":{"type":"user","id":"user-1","email":"a@example.com"},
     "target":{"type":"host","id":"host-1"},"event":{"type":"UPDATED"}},
    {"id":"log-2","timestamp":"2026-01-02T00:00:00Z",
     "actor":{"type":"apiKey","id":"dnkey-1","name":"ci"},
     "target":{"type":"role","id":"role-1"},"event":{"type":"CREATED"}}
  ],"metadata":{"hasNextPage":true,"hasPrevPage":false,"nextCursor":"p2"}}"#;

const PAGE_2: &str = r#"{"data":[
    {"id":"log-1","timestamp":"2026-01-01T00:00:00Z","actor":{"type":"system"},
     "target":{"type":"ca","id":"ca-1"},"event":{"type":"CREATED"}}
  ],"metadata":{"hasNextPage":true,"hasPrevPage":true,"nextCursor":"p3","prevCursor":"p1"}}"#;

#[test]
fn audit_log_list_asks_for_one_newest_first_page() {
    let (url, seen) = serve();
    let out = dn(&url, &["audit-log", "list"]);
    assert!(out.status.success(), "{out:?}");
    // One page only, even though the server reports another.
    assert_eq!(
        *seen.lock().unwrap(),
        ["/v1/audit-logs?sortDirection=desc&pageSize=500"]
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<Vec<&str>> = stdout
        .lines()
        .map(|l| l.split_whitespace().collect())
        .collect();
    assert_eq!(
        lines,
        [
            vec!["TIME", "EVENT", "TARGET", "TYPE", "TARGET", "ACTOR"],
            vec![
                "2026-01-03T00:00:00Z",
                "UPDATED",
                "host",
                "host-1",
                "a@example.com"
            ],
            vec![
                "2026-01-02T00:00:00Z",
                "CREATED",
                "role",
                "role-1",
                "API",
                "key",
                "ci"
            ],
        ],
        "{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!(
            "next page: {} audit-log list --cursor=p2",
            env!("CARGO_BIN_EXE_dn")
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("previous page"), "{stderr}");
}

#[test]
fn audit_log_list_resumes_from_a_cursor() {
    let (url, seen) = serve();
    let out = dn(
        &url,
        &[
            "--json",
            "audit-logs",
            "list",
            "--cursor",
            "p2",
            "--limit",
            "2",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
    assert_eq!(
        *seen.lock().unwrap(),
        ["/v1/audit-logs?sortDirection=desc&cursor=p2&pageSize=2"]
    );
    let got: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(got["data"][0]["id"], "log-1");
    assert_eq!(got["metadata"]["nextCursor"], "p3");
    assert_eq!(got["metadata"]["prevCursor"], "p1");
}

#[test]
fn audit_log_list_passes_target_filters() {
    let (url, seen) = serve();
    let out = dn(
        &url,
        &[
            "audit-log",
            "list",
            "--target",
            "host-1",
            "--target-type",
            "host",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        *seen.lock().unwrap(),
        [
            "/v1/audit-logs?filter.targetID=host-1&filter.targetType=host&sortDirection=desc&pageSize=500"
        ]
    );
}
