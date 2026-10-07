use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

/// Serve `body` for every request except `GET /v1/roles/…`, which answers
/// with `role` (status line and body), recording each request's path.
fn serve(
    body: &'static str,
    role: (&'static str, &'static str),
) -> (String, Arc<Mutex<Vec<String>>>) {
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
            let (status, body) = if target.starts_with("/v1/roles/") {
                role
            } else {
                ("200 OK", body)
            };
            log.lock().unwrap().push(target);
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

const HOST: &str = r#"{"data":{"id":"host-EXAMPLE","networkID":"network-EXAMPLE",
    "roleID":"role-WEB","name":"web-1","ipAddresses":["100.100.0.29"],
    "staticAddresses":[],"listenPort":0,"isLighthouse":false,"isRelay":false,
    "isBlocked":false,"createdAt":"2025-01-25T18:15:27Z","tags":["env:prod"],
    "configOverrides":[],"metadata":{"lastSeenAt":null,"platform":null,
    "updateAvailable":null,"version":null}},"metadata":{}}"#;

const ROLE_OK: (&str, &str) = (
    "200 OK",
    r#"{"data":{"id":"role-WEB","name":"Web servers"}}"#,
);

const NETWORK: &str = r#"{"data":{"id":"network-EXAMPLE","name":"office",
    "cidrs":["100.100.0.0/22"],"hostCount":3,"certVersion":2,
    "lighthousesAsRelays":false,"disableManagedLighthouses":true,"curve":"25519"},
    "metadata":{}}"#;

#[test]
fn hosts_get_reads_v2_and_names_the_role() {
    let (url, seen) = serve(HOST, ROLE_OK);
    let out = dn(&url, &["host", "get", "host-EXAMPLE"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("web-1\n"), "{stdout}");
    assert!(stdout.contains("Web servers (role-WEB)"), "{stdout}");
    assert!(stdout.contains("never"), "{stdout}");
    assert_eq!(
        *seen.lock().unwrap(),
        ["/v2/hosts/host-EXAMPLE", "/v1/roles/role-WEB"]
    );
}

#[test]
fn hosts_get_falls_back_to_the_role_id_when_the_lookup_fails() {
    let (url, _) = serve(
        HOST,
        (
            "403 Forbidden",
            r#"{"errors":[{"code":"ERR_FORBIDDEN","message":"no"}]}"#,
        ),
    );
    let out = dn(&url, &["host", "get", "host-EXAMPLE"]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("role lookup failed"), "{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let role = stdout.lines().find(|l| l.starts_with("Role:"));
    assert_eq!(
        role.map(|l| l.split_whitespace().collect::<Vec<_>>()),
        Some(vec!["Role:", "role-WEB"]),
        "{stdout}"
    );
}

#[test]
fn hosts_get_json_passes_the_response_through_without_a_role_lookup() {
    let (url, seen) = serve(HOST, ROLE_OK);
    let out = dn(&url, &["--json", "hosts", "get", "host-EXAMPLE"]);
    assert!(out.status.success(), "{out:?}");
    let got: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let want: serde_json::Value = serde_json::from_str(HOST).unwrap();
    assert_eq!(got, want);
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn networks_get_reads_v2() {
    let (url, seen) = serve(NETWORK, ROLE_OK);
    let out = dn(&url, &["network", "get", "network-EXAMPLE"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("office\n"), "{stdout}");
    assert!(stdout.contains("Managed lighthouses:    no\n"), "{stdout}");
    assert_eq!(*seen.lock().unwrap(), ["/v2/networks/network-EXAMPLE"]);
}

#[test]
fn networks_get_json_passes_the_response_through() {
    let (url, _) = serve(NETWORK, ROLE_OK);
    let out = dn(&url, &["--json", "networks", "get", "network-EXAMPLE"]);
    assert!(out.status.success(), "{out:?}");
    let got: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let want: serde_json::Value = serde_json::from_str(NETWORK).unwrap();
    assert_eq!(got, want);
}

#[test]
fn gets_reject_non_object_data() {
    for (args, kind) in [
        (["host", "get", "host-EXAMPLE"], "host"),
        (["network", "get", "network-EXAMPLE"], "network"),
    ] {
        let (url, _) = serve(r#"{"data":[]}"#, ROLE_OK);
        let out = dn(&url, &args);
        assert!(!out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(&format!("missing {kind} data")),
            "{out:?}"
        );
    }
}

#[test]
fn gets_reject_malformed_ids_before_any_request() {
    for args in [
        ["host", "get", "host-1/../roles"],
        ["host", "get", ""],
        ["network", "get", "network-1?x"],
    ] {
        let (url, seen) = serve(HOST, ROLE_OK);
        let out = dn(&url, &args);
        assert!(!out.status.success(), "{args:?}: {out:?}");
        assert!(seen.lock().unwrap().is_empty(), "{args:?}");
    }
}
