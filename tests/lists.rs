mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

use common::mock_id;

/// Answer every request with `PAGE`, a middle page that has both neighbours.
/// Records each request's path and query.
fn serve() -> (String, Arc<Mutex<Vec<String>>>) {
    serve_body(PAGE)
}

fn serve_body(body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
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
            let target = request_line.split(' ').nth(1).unwrap_or_default();
            log.lock().unwrap().push(target.to_string());
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

const PAGE: &str = r#"{"data":[{"id":"x-1","name":"one"}],
  "metadata":{"hasNextPage":true,"hasPrevPage":true,"nextCursor":"n1","prevCursor":"p1"}}"#;

#[test]
fn every_list_fetches_one_page_of_500_by_default() {
    let cases: [(&[&str], &str); 6] = [
        (&["host", "list"], "/v2/hosts?pageSize=500"),
        (&["route", "list"], "/v1/routes?pageSize=500"),
        (
            &["host", "search", "web"],
            "/v2/hosts?filter.search=web&pageSize=500",
        ),
        (&["role", "list"], "/v1/roles?pageSize=500"),
        (&["tag", "list"], "/v2/tags?sortDirection=desc&pageSize=500"),
        (&["network", "list"], "/v2/networks?pageSize=500"),
    ];
    for (args, want) in cases {
        let (url, seen) = serve();
        let out = dn(&url, args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        assert_eq!(*seen.lock().unwrap(), [want], "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!(
                "next page: {0} {1} --cursor=n1\nprevious page: {0} {1} --cursor=p1\n",
                env!("CARGO_BIN_EXE_dn"),
                args.join(" ")
            )),
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn a_list_passes_the_cursor_and_page_size_it_is_given() {
    let (url, seen) = serve();
    let out = dn(
        &url,
        &["role", "list", "--cursor", "n1", "--page-size", "10"],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(*seen.lock().unwrap(), ["/v1/roles?cursor=n1&pageSize=10"]);
}

#[test]
fn host_filters_become_filter_query_parameters() {
    let (url, seen) = serve();
    let out = dn(
        &url,
        &[
            "host",
            "list",
            "--role",
            "null",
            "--tag",
            "env:prod",
            "--tag",
            "region:us-east-1",
            "--lighthouse",
            "--blocked=false",
            "--never-seen",
            "--limit",
            "10",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        *seen.lock().unwrap(),
        [
            "/v2/hosts?filter.roleID=null&filter.tag=env%3Aprod&filter.tag=region%3Aus-east-1\
          &filter.isLighthouse=true&filter.isBlocked=false&filter.metadata.lastSeenAt=null\
          &pageSize=10"
        ]
    );
}

#[test]
fn host_search_takes_the_same_filters_as_host_list() {
    let (url, seen) = serve();
    let network = mock_id("network", "lab");
    let out = dn(
        &url,
        &[
            "host",
            "search",
            "web",
            "--network",
            &network,
            "--relay=false",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        *seen.lock().unwrap(),
        [format!(
            "/v2/hosts?filter.search=web&filter.networkID={network}&filter.isRelay=false&pageSize=500"
        )]
    );
}

#[test]
fn a_malformed_host_filter_fails_before_any_request() {
    let (url, seen) = serve();
    let out = dn(&url, &["host", "list", "--tag", "no-separator"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(seen.lock().unwrap().is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--tag"), "{stderr}");
}

#[test]
fn json_lists_keep_both_cursors_and_say_nothing_on_stderr() {
    let (url, _) = serve();
    let out = dn(&url, &["--json", "network", "list"]);
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
    let got: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(got["metadata"]["nextCursor"], "n1");
    assert_eq!(got["metadata"]["prevCursor"], "p1");
}

#[test]
fn an_empty_page_with_more_after_it_does_not_claim_there_are_none() {
    let (url, _) = serve_body(r#"{"data":[],"metadata":{"hasNextPage":true,"nextCursor":"n1"}}"#);
    let out = dn(&url, &["host", "list"]);
    assert!(out.status.success(), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!(
            "next page: {} host list --cursor=n1",
            env!("CARGO_BIN_EXE_dn")
        )),
        "{stderr}"
    );
}
