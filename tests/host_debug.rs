//! What `host debug …` puts on the wire and prints, against a mock that
//! answers every request with one canned body. The bodies follow the
//! examples in the `hostCommand` operation of the OpenAPI spec.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

use common::mock_id;
use serde_json::{Value, json};

/// One recorded request: method, target, and the parsed JSON body.
type Request = (String, String, Value);

fn serve(body: String) -> (String, Arc<Mutex<Vec<Request>>>) {
    serve_status("200 OK", body)
}

/// Like [`serve`], answering every request with `status`.
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

fn stdout(out: &Output) -> String {
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn cert() -> Value {
    json!({
        "details": {
            "curve": "CURVE25519",
            "groups": ["role:ops"],
            "ips": ["10.255.0.5/9"],
            "isCa": false,
            "issuer": "c652a897fee60414423b3e5e16951151099558799fc562c37f6ec73c376ecc15",
            "name": "build-server",
            "notAfter": "2027-04-22T11:22:52-04:00",
            "notBefore": "2026-04-22T11:21:52-04:00",
            "publicKey": "2f97c72ca059c1d148aaada0593379be5b21dc034d57121c95d4a96282555f65",
            "subnets": []
        },
        "fingerprint": "7a8d0a73c93aaddae1589e53cf6d5bd160a9d8cb79a0c0c6d6d33ff7de24acb1",
        "signature": "679b2e"
    })
}

#[test]
fn each_subcommand_posts_its_command_to_v1() {
    let host = mock_id("host", "laptop");
    let peer = json!({"target": "10.255.0.5"});
    let cases = [
        ("cert", Some("10.255.0.5"), "PrintCert", peer.clone()),
        ("tunnel", Some("10.255.0.5"), "PrintTunnel", peer.clone()),
        ("create-tunnel", Some("10.255.0.5"), "CreateTunnel", peer),
        (
            "lighthouse",
            Some("10.255.0.1"),
            "QueryLighthouse",
            json!({"target": "10.255.0.1"}),
        ),
        ("stack", None, "DebugStack", json!({})),
    ];
    for (name, target, command, args) in cases {
        let (url, seen) = serve(json!({"data": {}}).to_string());
        let mut argv = vec!["--json", "host", "debug", name, &host];
        argv.extend(target);
        let out = dn(&url, &argv);
        assert!(out.status.success(), "{name}: {out:?}");
        assert_eq!(
            requests(&seen),
            [(
                "POST".to_string(),
                format!("/v1/hosts/{host}/command"),
                json!({"command": command, "args": args})
            )],
            "{name}"
        );
    }
}

#[test]
fn json_prints_the_response_as_the_api_sent_it() {
    let host = mock_id("host", "laptop");
    let body = json!({"data": cert()});
    let (url, _) = serve(body.to_string());
    let out = dn(
        &url,
        &["--json", "host", "debug", "cert", &host, "10.255.0.5"],
    );
    let printed: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(printed, body);
}

#[test]
fn cert_shows_who_the_peer_is_and_when_its_cert_runs_out() {
    let host = mock_id("host", "laptop");
    let (url, _) = serve(json!({"data": cert()}).to_string());
    let out = dn(&url, &["host", "debug", "cert", &host, "10.255.0.5"]);
    insta::assert_snapshot!(stdout(&out));
}

#[test]
fn tunnel_shows_the_address_in_use_and_the_others() {
    let host = mock_id("host", "laptop");
    let tunnel = json!({
        "vpnIp": "10.255.0.11",
        "localIndex": 3758197150_u64,
        "remoteIndex": 65044350,
        "remoteAddrs": [
            {"ip": "100.64.1.2", "port": 57304},
            {"ip": "198.51.100.135", "port": 57304},
            {"ip": "2001:db8::7", "port": 57304}
        ],
        "cachedPackets": 0,
        "cert": cert(),
        "messageCounter": 4,
        "currentRemote": {"ip": "198.51.100.135", "port": 57304},
        "currentRelaysToMe": [],
        "currentRelaysThroughMe": []
    });
    let (url, _) = serve(json!({"data": tunnel}).to_string());
    let out = dn(&url, &["host", "debug", "tunnel", &host, "10.255.0.11"]);
    insta::assert_snapshot!(stdout(&out));
}

#[test]
fn lighthouse_lists_each_host_it_knows() {
    let host = mock_id("host", "laptop");
    let map = json!({
        "10.128.42.11": {
            "reported": [{"ip": "198.51.100.135", "port": 52148}, {"ip": "192.168.68.34", "port": 52148}],
            "relay": []
        },
        "10.255.89.11": {"learned": [{"ip": "203.0.113.8", "port": 52148}], "relay": []}
    });
    let (url, _) = serve(json!({"data": map}).to_string());
    let out = dn(&url, &["host", "debug", "lighthouse", &host, "10.255.0.1"]);
    insta::assert_snapshot!(stdout(&out));
}

#[test]
fn an_empty_lighthouse_map_says_to_ask_again() {
    let host = mock_id("host", "laptop");
    let (url, _) = serve(json!({"data": {}}).to_string());
    let out = dn(&url, &["host", "debug", "lighthouse", &host, "10.255.0.1"]);
    assert!(stdout(&out).contains("Run it again"));
}

#[test]
fn create_tunnel_repeats_what_dnclient_said() {
    let host = mock_id("host", "laptop");
    let (url, _) = serve(json!({"data": "Created"}).to_string());
    let out = dn(
        &url,
        &["host", "debug", "create-tunnel", &host, "10.255.0.5"],
    );
    assert_eq!(
        stdout(&out),
        format!("Asked {host} to open a tunnel to 10.255.0.5; dnclient said \"Created\".\n")
    );
}

#[test]
fn a_stack_keeps_its_lines_but_loses_escape_codes() {
    let host = mock_id("host", "laptop");
    let trace = "goroutine 1 [running]:\nmain.main()\n\t/src/main.go:12 +0x1d\x1b[2J";
    let (url, _) = serve(json!({"data": trace}).to_string());
    let out = stdout(&dn(&url, &["host", "debug", "stack", &host]));
    assert_eq!(out.lines().count(), 3, "{out}");
    assert!(!out.contains('\x1b'), "{out:?}");
    assert!(out.contains("main.main()"));
}

#[test]
fn a_shape_the_renderer_does_not_know_prints_as_json() {
    let host = mock_id("host", "laptop");
    let (url, _) = serve(json!({"data": {"goroutines": 12}}).to_string());
    let out = stdout(&dn(&url, &["host", "debug", "stack", &host]));
    let printed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(printed, json!({"goroutines": 12}));
}

#[test]
fn a_missing_scope_comes_back_in_the_json_error_envelope() {
    let host = mock_id("host", "laptop");
    let body = json!({"errors": [{
        "code": "ERR_FORBIDDEN",
        "message": "api key must support the following scopes: hosts:debug"
    }]});
    let (url, _) = serve_status("403 Forbidden", body.to_string());
    let out = dn(&url, &["--json", "host", "debug", "stack", &host]);
    assert!(!out.status.success());
    let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(printed["errors"][0]["code"], "ERR_FORBIDDEN");
    assert_eq!(printed["status"], 403);
}

#[test]
fn bad_arguments_never_reach_the_api() {
    let host = mock_id("host", "laptop");
    let (url, seen) = serve(json!({"data": {}}).to_string());
    for args in [
        vec!["host", "debug", "cert", &host, "not-an-ip"],
        vec!["host", "debug", "cert", &host, "10.0.0.256"],
        vec!["host", "debug", "stack", "host-x/../../v2/hosts"],
        vec!["host", "debug", "stack", ""],
        vec!["host", "debug", "lighthouse", &host],
    ] {
        let out = dn(&url, &args);
        assert!(!out.status.success(), "{args:?} succeeded");
    }
    assert!(requests(&seen).is_empty());
}
