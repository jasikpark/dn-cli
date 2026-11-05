//! What `host debug …` puts on the wire and prints, against a mock that
//! answers every request with one canned body. The bodies follow the
//! examples in the `hostCommand` operation of the OpenAPI spec.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
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

/// Read one request off `stream`: its method, target and JSON body.
fn read_request(stream: &TcpStream) -> Request {
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
    (method, target, sent)
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
            log.lock().unwrap().push(read_request(&stream));
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

/// A version 2 certificate as dnclient 0.9.10 prints it: `curve` and
/// `publicKey` beside `details`, and `networks` / `unsafeNetworks` in place
/// of `ips` / `subnets`.
fn cert_v2() -> Value {
    json!({
        "curve": "CURVE25519",
        "details": {
            "groups": ["role:Lighthouse"],
            "isCa": false,
            "issuer": "c652a897fee60414423b3e5e16951151099558799fc562c37f6ec73c376ecc15",
            "name": "lighthouse-1",
            "networks": ["10.255.0.1/22", "fd00:c0:c0::1/80"],
            "notAfter": "2026-12-08T14:20:31-06:00",
            "notBefore": "2026-10-09T15:15:31-05:00",
            "unsafeNetworks": null
        },
        "fingerprint": "4f0c2e9d7b1a86335d0e9a4c1f27b8e6a3d5c7091b2e4f6a8c0d1e3f5a7b9c2d",
        "publicKey": "2f97c72c",
        "signature": "679b2e",
        "version": 2
    })
}

/// dnclient 0.9.10 answers PrintCert as `{"cert": …}`, not the bare
/// certificate of the spec's example.
#[test]
fn cert_reads_a_version_2_certificate() {
    let host = mock_id("host", "laptop");
    let (url, _) = serve(json!({"data": {"cert": cert_v2()}}).to_string());
    let out = dn(&url, &["host", "debug", "cert", &host, "10.255.0.1"]);
    insta::assert_snapshot!(stdout(&out));
}

/// PrintTunnel from dnclient 0.9.10: the tunnel under `host`, the peer's
/// addresses in `vpnAddrs`, and underlay addresses as `ip:port` strings.
#[test]
fn tunnel_reads_the_answer_dnclient_0_9_10_gives() {
    let host = mock_id("host", "laptop");
    let tunnel = json!({
        "vpnAddrs": ["10.255.0.1", "fd00:c0:c0::1"],
        "localIndex": 837260587,
        "remoteIndex": 3614089855_u64,
        "remoteAddrs": ["198.51.100.135:4242", "[2001:db8::7]:4242"],
        "cert": cert_v2(),
        "messageCounter": 47,
        "currentRemote": "198.51.100.135:4242",
        "currentRelaysToMe": [],
        "currentRelaysThroughMe": []
    });
    let (url, _) = serve(json!({"data": {"host": tunnel}}).to_string());
    let out = dn(&url, &["host", "debug", "tunnel", &host, "10.255.0.1"]);
    insta::assert_snapshot!(stdout(&out));
}

/// A host with no tunnel to the peer answers `null` for both, and exits 0.
#[test]
fn no_tunnel_to_the_peer_is_said_in_words() {
    let host = mock_id("host", "laptop");
    let (url, _) = serve(json!({"data": {"host": null}}).to_string());
    let out = dn(&url, &["host", "debug", "tunnel", &host, "10.255.0.9"]);
    assert_eq!(
        stdout(&out),
        format!("{host} has no tunnel to 10.255.0.9.\n")
    );

    let (url, _) = serve(json!({"data": {"cert": null}}).to_string());
    let out = dn(&url, &["host", "debug", "cert", &host, "10.255.0.9"]);
    assert_eq!(
        stdout(&out),
        format!("{host} has no tunnel to 10.255.0.9, so it holds no certificate for it.\n")
    );
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

/// QueryLighthouse from dnclient 0.9.10: the map under `cache`, addresses as
/// `ip:port` strings.
#[test]
fn lighthouse_reads_the_answer_dnclient_0_9_10_gives() {
    let host = mock_id("host", "laptop");
    let cache = json!({
        "10.255.0.1": {"learned": ["198.51.100.135:4242"], "relay": []},
        "10.255.0.11": {
            "reported": ["203.0.113.8:52148", "192.168.68.34:52148"],
            "relay": ["10.255.0.2"]
        }
    });
    let (url, _) = serve(json!({"data": {"cache": cache}}).to_string());
    let out = dn(&url, &["host", "debug", "lighthouse", &host, "10.255.0.1"]);
    insta::assert_snapshot!(stdout(&out));
}

#[test]
fn an_empty_lighthouse_answer_says_to_ask_again() {
    let host = mock_id("host", "laptop");
    // dnclient logs `cache=null` for a lighthouse with nothing cached yet.
    for empty in [
        json!({}),
        Value::Null,
        json!({"cache": null}),
        json!({"cache": {}}),
    ] {
        let (url, _) = serve(json!({"data": empty}).to_string());
        let out = dn(&url, &["host", "debug", "lighthouse", &host, "10.255.0.1"]);
        assert!(stdout(&out).contains("Run it again"), "{empty}");
    }
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

/// dnclient 0.9.10 answers CreateTunnel with `{}`, not the spec's "Created".
#[test]
fn create_tunnel_with_an_empty_answer_says_what_was_asked() {
    let host = mock_id("host", "laptop");
    let (url, _) = serve(json!({"data": {}}).to_string());
    let out = dn(
        &url,
        &["host", "debug", "create-tunnel", &host, "10.255.0.5"],
    );
    assert_eq!(
        stdout(&out),
        format!("Asked {host} to open a tunnel to 10.255.0.5.\n")
    );
}

/// The trace is `data` itself in the spec, and `data.stackTrace` from
/// dnclient 0.9.10.
#[test]
fn a_stack_keeps_its_lines_but_loses_escape_codes() {
    let host = mock_id("host", "laptop");
    let trace = "goroutine 1 [running]:\nmain.main()\n\t/src/main.go:12 +0x1d\x1b[2J";
    for data in [json!(trace), json!({"stackTrace": trace})] {
        let (url, _) = serve(json!({"data": data}).to_string());
        let out = stdout(&dn(&url, &["host", "debug", "stack", &host]));
        assert_eq!(out.lines().count(), 3, "{out}");
        assert!(!out.contains('\x1b'), "{out:?}");
        assert!(out.contains("main.main()"));
    }
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

/// What the API answers, after about 30 seconds, for a host that is offline
/// or whose client takes no commands.
#[test]
fn a_host_that_does_not_answer_points_at_when_it_last_checked_in() {
    let host = mock_id("host", "laptop");
    let body = json!({"errors": [{
        "code": "ERR_DNCLIENT_NOT_REACHABLE",
        "message": "dnclient not reachable"
    }]});
    let (url, _) = serve_status("408 Request Timeout", body.to_string());
    let out = dn(&url, &["--json", "host", "debug", "stack", &host]);
    assert!(!out.status.success());
    let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(printed["status"], 408);
    assert_eq!(printed["errors"][0]["code"], "ERR_DNCLIENT_NOT_REACHABLE");
    let message = printed["errors"][0]["message"].as_str().unwrap();
    assert!(message.contains("lastSeenAt"), "{message}");
    assert!(message.ends_with("dnclient not reachable"), "{message}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("dn host get"));
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

/// What [`serve_stream`] hands back: the url, the request log, the signal
/// that lets the rest of the body go, and whether it has gone yet.
type StreamMock = (
    String,
    Arc<Mutex<Vec<Request>>>,
    std::sync::mpsc::Sender<()>,
    Arc<std::sync::atomic::AtomicBool>,
);

/// Serve one StreamLogs response with no length, so the body runs until the
/// connection closes: `first`, then (once `go` fires, or after 10s) `rest`.
fn serve_stream(first: String, rest: String) -> StreamMock {
    use std::sync::atomic::{AtomicBool, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let sent_rest = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&sent_rest);
    let (go, wait) = std::sync::mpsc::channel::<()>();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        log.lock().unwrap().push(read_request(&stream));
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n{first}"
        )
        .unwrap();
        stream.flush().unwrap();
        let _ = wait.recv_timeout(std::time::Duration::from_secs(10));
        flag.store(true, Ordering::SeqCst);
        let _ = write!(stream, "{rest}");
    });
    (url, seen, go, sent_rest)
}

const STARTED: &str = r#"{"durationSeconds":30,"level":"info","msg":"Log streaming session started","time":"2026-11-05T10:00:00-06:00"}"#;
const HANDSHAKE: &str = r#"{"handshake":{"stage":1,"style":"ix_psk0"},"level":"info","msg":"Handshake message sent","time":"2026-11-05T10:00:05-06:00","vpnIp":"10.255.0.11"}"#;

#[test]
fn logs_print_each_line_as_it_arrives() {
    use std::sync::atomic::Ordering;
    let host = mock_id("host", "laptop");
    // The API's own framing: each entry under `data`, and an empty `data`
    // as the stream opens and closes.
    let (url, seen, go, sent_rest) = serve_stream(
        format!("{{\"data\":{{}}}}\n{{\"data\":{STARTED}}}\n"),
        format!("{{\"data\":{HANDSHAKE}}}\n{{\"data\":{{}}}}\n"),
    );
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_dn"))
        .args([
            "--json",
            "host",
            "debug",
            "logs",
            &host,
            "--duration",
            "30s",
        ])
        .env("DN_CONFIG_DIR", dir.path())
        .env("DEFINED_API_URL", &url)
        .env("DEFINED_API_KEY", "fake-test-key")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

    let line = lines.next().unwrap().unwrap();
    assert!(
        !sent_rest.load(Ordering::SeqCst),
        "the first line only showed up once the host had sent everything"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["msg"],
        "Log streaming session started"
    );

    go.send(()).unwrap();
    let line = lines.next().unwrap().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["vpnIp"],
        "10.255.0.11"
    );
    assert!(lines.next().is_none());
    assert!(child.wait().unwrap().success());

    assert_eq!(
        requests(&seen),
        [(
            "POST".to_string(),
            format!("/v1/hosts/{host}/command"),
            json!({"command": "StreamLogs", "args": {"durationSeconds": 30, "level": "info"}})
        )]
    );
}

/// The spec's StreamLogs example is one document, its entries in a `data`
/// string with a backslash and an `n` between them, not a newline.
#[test]
fn logs_read_the_documented_example_shape_too() {
    let host = mock_id("host", "laptop");
    let wrapped = json!({"data": format!("{STARTED}\\n{HANDSHAKE}\\n")});
    let (url, _, go, _) = serve_stream(format!("{wrapped}\n"), String::new());
    go.send(()).unwrap();
    let out = stdout(&dn(
        &url,
        &["host", "debug", "logs", &host, "--level", "debug"],
    ));
    insta::assert_snapshot!(out);
}

/// `dn … logs | head -1`: once nobody reads stdout the command is done, not
/// failed, in either output mode.
#[test]
fn logs_stop_without_an_error_when_stdout_closes() {
    let host = mock_id("host", "laptop");
    for json in [true, false] {
        let rest = format!("{HANDSHAKE}\n").repeat(1000);
        let (url, _, go, _) = serve_stream(format!("{STARTED}\n"), rest);
        let dir = tempfile::tempdir().unwrap();
        let mut args = vec!["host", "debug", "logs", &host];
        if json {
            args.insert(0, "--json");
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_dn"))
            .args(&args)
            .env("DN_CONFIG_DIR", dir.path())
            .env("DEFINED_API_URL", &url)
            .env("DEFINED_API_KEY", "fake-test-key")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        assert!(lines.next().unwrap().unwrap().contains("session started"));
        drop(lines);
        go.send(()).unwrap();

        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "json={json}: {stderr}");
        assert!(!stderr.contains("error"), "json={json}: {stderr}");
    }
}

#[test]
fn logs_refuse_more_than_ten_minutes_before_any_request() {
    let host = mock_id("host", "laptop");
    let (url, seen) = serve(json!({"data": ""}).to_string());
    for duration in ["11m", "1.5s", "0s"] {
        let out = dn(
            &url,
            &["host", "debug", "logs", &host, "--duration", duration],
        );
        assert_eq!(out.status.code(), Some(2), "{duration}: {out:?}");
    }
    assert!(requests(&seen).is_empty());
}
