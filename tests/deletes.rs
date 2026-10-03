use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

/// Answer every request with the API's empty delete envelope, recording each
/// request's method and path.
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
            // Drain the headers; these are bodiless requests.
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            let mut parts = request_line.split(' ');
            let method = parts.next().unwrap_or_default();
            let target = parts.next().unwrap_or_default();
            log.lock().unwrap().push(format!("{method} {target}"));
            let body = r#"{"data":{},"metadata":{}}"#;
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

/// Run `dn` against `url`. `output()` gives the child a closed, non-terminal
/// stdin, so nothing can answer a confirmation prompt.
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

fn stdout_json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn host_delete_with_yes_deletes_on_v1_without_a_lookup() {
    let (url, seen) = serve();
    let out = dn(&url, &["--json", "host", "delete", "host-1", "--yes"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        stdout_json(&out),
        serde_json::json!({"id": "host-1", "deleted": true})
    );
    assert_eq!(*seen.lock().unwrap(), ["DELETE /v1/hosts/host-1"]);
}

#[test]
fn role_delete_with_yes_deletes_on_v1_without_a_lookup() {
    let (url, seen) = serve();
    let out = dn(&url, &["--json", "role", "delete", "role-ABC", "-y"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        stdout_json(&out),
        serde_json::json!({"id": "role-ABC", "deleted": true})
    );
    assert_eq!(*seen.lock().unwrap(), ["DELETE /v1/roles/role-ABC"]);
}

#[test]
fn network_delete_with_yes_deletes_on_v1_without_a_lookup() {
    let (url, seen) = serve();
    let out = dn(
        &url,
        &["--json", "network", "delete", "network-XYZ", "--yes"],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        stdout_json(&out),
        serde_json::json!({"id": "network-XYZ", "deleted": true})
    );
    assert_eq!(*seen.lock().unwrap(), ["DELETE /v1/networks/network-XYZ"]);
}

#[test]
fn tag_delete_with_yes_prints_the_tag_it_deleted() {
    let (url, seen) = serve();
    let out = dn(&url, &["tags", "delete", "env:prod", "--yes"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "Deleted tag env:prod.\n"
    );
    assert_eq!(*seen.lock().unwrap(), ["DELETE /v1/tags/env:prod"]);
}

#[test]
fn tag_delete_json_echoes_the_name_and_keeps_it_in_one_path_segment() {
    let (url, seen) = serve();
    let out = dn(&url, &["--json", "tag", "delete", "a:b/c", "--yes"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        stdout_json(&out),
        serde_json::json!({"name": "a:b/c", "deleted": true})
    );
    assert_eq!(*seen.lock().unwrap(), ["DELETE /v1/tags/a:b%2Fc"]);
}

#[test]
fn deletes_without_yes_are_refused_before_any_request() {
    for args in [
        &["host", "delete", "host-1"][..],
        &["--json", "host", "delete", "host-1"],
        &["role", "delete", "role-1"],
        &["--json", "role", "delete", "role-1"],
        &["network", "delete", "network-1"],
        &["--json", "network", "delete", "network-1"],
        &["tag", "delete", "env:prod"],
        &["--json", "tag", "delete", "env:prod"],
    ] {
        let (url, seen) = serve();
        let out = dn(&url, args);
        assert!(!out.status.success(), "{args:?}: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("pass --yes"),
            "{args:?}: {out:?}"
        );
        assert!(seen.lock().unwrap().is_empty(), "{args:?}");
    }
}

#[test]
fn deletes_reject_malformed_ids_before_any_request() {
    for args in [
        &["role", "delete", "role/../hosts", "--yes"][..],
        &["tag", "delete", "nocolon", "--yes"],
        &["network", "delete", "network-1/x", "--yes"],
        &["host", "delete", "host-1?x", "--yes"],
    ] {
        let (url, seen) = serve();
        let out = dn(&url, args);
        assert!(!out.status.success(), "{args:?}: {out:?}");
        assert!(seen.lock().unwrap().is_empty(), "{args:?}");
    }
}
