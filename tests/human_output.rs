//! Snapshots of every command's human output, run against a mock API that
//! answers each route with a fixed synthetic body. Review changes with
//! `cargo insta review`.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;

/// One canned answer: method, path (query string ignored), status line, body.
type Route = (&'static str, &'static str, &'static str, &'static str);

/// Serve `routes`, answering anything unrouted with a 404 that names the
/// request, so a missing route shows up in the snapshot instead of hanging.
fn serve(routes: &'static [Route]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
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
            // Drain a create/edit body so the client sees the response.
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();

            let mut parts = request_line.split(' ');
            let method = parts.next().unwrap_or_default();
            let target = parts.next().unwrap_or_default();
            let path = target.split('?').next().unwrap_or_default();
            let unrouted = format!(
                r#"{{"errors":[{{"code":"ERR_NOT_FOUND","message":"unrouted {method} {path}"}}]}}"#
            );
            let (status, body) = routes
                .iter()
                .find(|(m, p, _, _)| *m == method && *p == path)
                .map_or(("404 Not Found", unrouted.as_str()), |(_, _, s, b)| (s, b));
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    url
}

/// Run `dn args` against `url` from an empty config dir, plus any files in
/// `config`, and render what a person would see: stdout, then stderr and the
/// exit code when there are any. The mock's random port reads as `<API_URL>`,
/// and the test binary's path in next-page hints as `dn`.
fn transcript(url: &str, config: &[(&str, &str)], args: &[&str]) -> String {
    let dir = tempfile::tempdir().unwrap();
    for (name, contents) in config {
        fs::write(dir.path().join(name), contents).unwrap();
    }
    let out = Command::new(env!("CARGO_BIN_EXE_dn"))
        .args(args)
        .env("DN_CONFIG_DIR", dir.path())
        .env("DEFINED_API_URL", url)
        .env("DEFINED_API_KEY", "fake-test-key")
        .output()
        .unwrap();
    let mut shown = format!("$ dn {}\n", args.join(" "));
    shown.push_str(&String::from_utf8_lossy(&out.stdout));
    if !out.stderr.is_empty() {
        shown.push_str("--- stderr\n");
        shown.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    if !out.status.success() {
        shown.push_str(&format!("--- exit {}\n", out.status.code().unwrap_or(-1)));
    }
    shown
        .replace(url, "<API_URL>")
        .replace(env!("CARGO_BIN_EXE_dn"), "dn")
}

/// One `#[test]` and one snapshot per case, named after the case. Each
/// case runs alone: insta stops a test at its first mismatch, so a loop of
/// asserts would hide every snapshot after it from review.
macro_rules! human_output {
    ($($name:ident: $description:literal, $routes:expr, $config:expr, $args:expr;)*) => {$(
        #[test]
        fn $name() {
            let shown = transcript(&serve($routes), $config, $args);
            insta::with_settings!({ description => $description, omit_expression => true }, {
                insta::assert_snapshot!(shown);
            });
        }
    )*};
}

const OK: &str = "200 OK";
const DELETED: &str = r#"{"data":{},"metadata":{}}"#;
const EMPTY_PAGE: &str = r#"{"data":[],"metadata":{"hasNextPage":false}}"#;

const HOSTS: &str = r#"{"data":[
    {"id":"host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI","name":"Build Server",
     "ipAddresses":["100.100.0.12","fd00:c0:c0:2966:d3bf:a55d:49a0:6f18"]},
    {"id":"host-M6TLA3VZQ2NXKC7EWJR5PBYHFO","name":"Pixel Phone",
     "ipAddresses":["100.100.0.39"]}
  ],"metadata":{"hasNextPage":true,"nextCursor":"page-2"}}"#;

const HOST: &str = r#"{"data":{"id":"host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI",
    "networkID":"network-EXAMPLE","roleID":"role-WEB","name":"Build Server",
    "ipAddresses":["100.100.0.12","fd00:c0:c0:2966:d3bf:a55d:49a0:6f18"],
    "staticAddresses":["203.0.113.5:4242"],"listenPort":4242,"isLighthouse":false,
    "isRelay":false,"isBlocked":false,"createdAt":"2026-01-25T18:15:27Z",
    "tags":["env:prod","site:hou"],"configOverrides":[],
    "metadata":{"lastSeenAt":"2026-10-09T18:27:45Z","platform":"dnclient-desktop",
    "updateAvailable":true,"version":"0.9.9","os":"windows"}},"metadata":{}}"#;

const HOST_EDITED: &str = r#"{"data":{"id":"host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI",
    "networkID":"network-EXAMPLE","roleID":"role-WEB","name":"Build Server",
    "ipAddresses":["100.100.0.12","fd00:c0:c0:2966:d3bf:a55d:49a0:6f18"],
    "tags":["env:prod","site:hou","team:infra"]},"metadata":{}}"#;

const HOST_CREATED: &str = r#"{"data":{"host":{"id":"host-Z3HWQ5ATVK2MRXE7NC4YLBPJDG",
    "name":"web-2","ipAddresses":["100.100.0.40"],"isLighthouse":false,"isRelay":false},
    "enrollmentCode":{"code":"EXAMPLE-ENROLLMENT-CODE","lifetimeSeconds":86400}},
    "metadata":{}}"#;

const ROLE: &str = r#"{"data":{"id":"role-WEB","name":"Web servers",
    "description":"Public HTTP","hostCount":3,"firewallRulesCount":2,
    "firewallRules":[
      {"protocol":"TCP","portRange":{"from":443,"to":443},"allowedRoleID":null,
       "allowedTags":null,"description":"https from anywhere"},
      {"protocol":"TCP","portRange":{"from":22,"to":22},"allowedRoleID":"role-ADM",
       "allowedTags":null,"description":"ssh from admins"}]},"metadata":{}}"#;

const ROLES: &str = r#"{"data":[
    {"id":"role-WEB","name":"Web servers","description":"Public HTTP",
     "hostCount":3,"firewallRulesCount":2},
    {"id":"role-ADM","name":"Admins","description":"",
     "hostCount":1,"firewallRulesCount":0}
  ],"metadata":{"hasNextPage":false}}"#;

const TAG: &str = r#"{"data":{"name":"env:prod","description":"Production",
    "hostCount":2,"priority":10,"firewallRulesCount":1,
    "firewallRules":[{"protocol":"UDP","portRange":{"from":53,"to":53},
    "allowedRoleID":null,"allowedTags":["site:hou"],"description":"dns"}]},
    "metadata":{}}"#;

const TAGS: &str = r#"{"data":[
    {"name":"env:prod","description":"Production","hostCount":2,
     "firewallRulesCount":1,"priority":10},
    {"name":"site:hou","description":"","hostCount":5,
     "firewallRulesCount":0,"priority":null}
  ],"metadata":{"hasNextPage":false}}"#;

const NETWORK: &str = r#"{"data":{"id":"network-EXAMPLE","name":"office",
    "cidrs":["100.100.0.0/22","fd00:c0:c0::/80"],"hostCount":3,"certVersion":2,
    "lighthousesAsRelays":false,"disableManagedLighthouses":true,"curve":"25519",
    "signingCAID":"ca-EXAMPLE","createdAt":"2025-11-02T09:00:00Z",
    "description":"Head office"},"metadata":{}}"#;

const NETWORKS: &str = r#"{"data":[
    {"id":"network-EXAMPLE","name":"office","cidrs":["100.100.0.0/22","fd00:c0:c0::/80"],
     "hostCount":3,"certVersion":2,"curve":"25519","description":"Head office",
     "lighthousesAsRelays":true,"disableManagedLighthouses":false},
    {"id":"network-LAB","name":"lab","cidrs":["100.101.0.0/24"],
     "hostCount":0,"certVersion":1,"curve":"P256","description":"",
     "lighthousesAsRelays":false,"disableManagedLighthouses":true}
  ],"metadata":{"hasNextPage":false}}"#;

const AUDIT_LOGS: &str = r#"{"data":[
    {"id":"log-3","timestamp":"2026-01-03T00:00:00.5Z",
     "actor":{"type":"user","id":"user-1","email":"alex@example.com"},
     "target":{"type":"host","id":"host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI"},
     "event":{"type":"UPDATED"}},
    {"id":"log-2","timestamp":"2026-01-02T00:00:00Z",
     "actor":{"type":"apiKey","id":"dnkey-1","name":"ci"},
     "target":{"type":"role","id":"role-WEB"},"event":{"type":"CREATED"}},
    {"id":"log-1","timestamp":"2026-01-01T00:00:00Z","actor":{"type":"system"},
     "target":{"type":"ca","id":"ca-EXAMPLE"},"event":{"type":"CREATED"}}
  ],"metadata":{"hasNextPage":true,"nextCursor":"page-2"}}"#;

const HOST_ID: &str = "host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI";

const HOST_ROUTES: &[Route] = &[
    ("GET", "/v2/hosts", OK, HOSTS),
    ("GET", "/v2/hosts/host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI", OK, HOST),
    ("GET", "/v1/roles/role-WEB", OK, ROLE),
    (
        "PUT",
        "/v3/hosts/host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI",
        OK,
        HOST_EDITED,
    ),
    (
        "DELETE",
        "/v1/hosts/host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI",
        OK,
        DELETED,
    ),
    ("GET", "/v2/networks/network-EXAMPLE", OK, NETWORK),
    ("POST", "/v2/host-and-enrollment-code", OK, HOST_CREATED),
];

const NETWORK_ROUTES: &[Route] = &[
    ("GET", "/v2/networks", OK, NETWORKS),
    ("GET", "/v2/networks/network-EXAMPLE", OK, NETWORK),
    ("DELETE", "/v1/networks/network-EXAMPLE", OK, DELETED),
];

const ROLE_ROUTES: &[Route] = &[
    ("GET", "/v1/roles", OK, ROLES),
    ("GET", "/v1/roles/role-WEB", OK, ROLE),
    ("DELETE", "/v1/roles/role-WEB", OK, DELETED),
];

const TAG_ROUTES: &[Route] = &[
    ("GET", "/v2/tags", OK, TAGS),
    ("GET", "/v1/tags/env:prod", OK, TAG),
    ("DELETE", "/v1/tags/env:prod", OK, DELETED),
];

const AUDIT_LOG_ROUTES: &[Route] = &[("GET", "/v1/audit-logs", OK, AUDIT_LOGS)];

const EMPTY_ROUTES: &[Route] = &[
    ("GET", "/v2/hosts", OK, EMPTY_PAGE),
    ("GET", "/v2/networks", OK, EMPTY_PAGE),
    ("GET", "/v1/roles", OK, EMPTY_PAGE),
    ("GET", "/v2/tags", OK, EMPTY_PAGE),
    ("GET", "/v1/audit-logs", OK, EMPTY_PAGE),
];

const ERROR_ROUTES: &[Route] = &[
    (
        "GET",
        "/v2/hosts/host-MISSING",
        "404 Not Found",
        r#"{"errors":[{"code":"ERR_NOT_FOUND","message":"host not found"}]}"#,
    ),
    (
        "GET",
        "/v2/networks",
        "403 Forbidden",
        r#"{"errors":[{"code":"ERR_FORBIDDEN","message":"missing scope networks:list"}]}"#,
    ),
];

const AUTH_FILE: &[(&str, &str)] = &[(
    "auth.json",
    r#"{"version":2,"default_profile":"prod",
    "profiles":{"prod":{"key":"op://Example/dn/credential"},
    "staging":{"api_url":"https://api.staging.example.com","key":"keyring"}}}"#,
)];

human_output! {
    host_list: "Host table, with a next-page hint on stderr.",
        HOST_ROUTES, &[], &["host", "list"];
    host_search: "Host search shares the host list table.",
        HOST_ROUTES, &[], &["host", "search", "build"];
    host_get: "Host detail view, with the role named and an available client update flagged.",
        HOST_ROUTES, &[], &["host", "get", HOST_ID];
    host_create: "Created host, its enrollment command, and the default-role firewall note.",
        HOST_ROUTES, &[], &["host", "create", "web-2", "--network", "network-EXAMPLE"];
    host_edit: "Edited host with its final tags, warning about a removed tag it never had.",
        HOST_ROUTES, &[], &["host", "edit", HOST_ID, "--add-tag", "team:infra", "--remove-tag", "gone:1"];
    host_edit_unchanged: "An edit that changes nothing skips the update and says so.",
        HOST_ROUTES, &[], &["host", "edit", HOST_ID, "--add-tag", "env:prod"];
    host_delete: "Host delete with --yes.",
        HOST_ROUTES, &[], &["host", "delete", HOST_ID, "--yes"];
    host_delete_needs_yes: "Without --yes and without a terminal to prompt on, delete refuses.",
        HOST_ROUTES, &[], &["host", "delete", HOST_ID];

    network_list: "Network table.",
        NETWORK_ROUTES, &[], &["network", "list"];
    network_get: "Network detail view.",
        NETWORK_ROUTES, &[], &["network", "get", "network-EXAMPLE"];
    network_delete: "Network delete with --yes.",
        NETWORK_ROUTES, &[], &["network", "delete", "network-EXAMPLE", "--yes"];

    role_list: "Role table.",
        ROLE_ROUTES, &[], &["role", "list"];
    role_get: "Role with its firewall rules; a rule allowing another role shows it by name.",
        ROLE_ROUTES, &[], &["role", "get", "role-WEB"];
    role_delete: "Role delete with --yes.",
        ROLE_ROUTES, &[], &["role", "delete", "role-WEB", "--yes"];

    tag_list: "Tag table.",
        TAG_ROUTES, &[], &["tag", "list"];
    tag_get: "Tag with its priority and a rule allowing hosts by tag.",
        TAG_ROUTES, &[], &["tag", "get", "env:prod"];
    tag_delete: "Tag delete with --yes.",
        TAG_ROUTES, &[], &["tag", "delete", "env:prod", "--yes"];

    audit_log_list: "Audit log table with each actor kind (user email, API key name, system) and a next-page hint.",
        AUDIT_LOG_ROUTES, &[], &["audit-log", "list"];

    host_list_empty: "Host list with no rows.",
        EMPTY_ROUTES, &[], &["host", "list"];
    host_search_empty: "Host search with no matches names the query.",
        EMPTY_ROUTES, &[], &["host", "search", "nothing"];
    network_list_empty: "Network list with no rows.",
        EMPTY_ROUTES, &[], &["network", "list"];
    role_list_empty: "Role list with no rows.",
        EMPTY_ROUTES, &[], &["role", "list"];
    tag_list_empty: "Tag list with no rows.",
        EMPTY_ROUTES, &[], &["tag", "list"];
    audit_log_list_empty: "Audit log list with no rows.",
        EMPTY_ROUTES, &[], &["audit-log", "list"];

    error_not_found: "A 404 reaches stderr as status, code and message, and exits 1.",
        ERROR_ROUTES, &[], &["host", "get", "host-MISSING"];
    error_forbidden: "A 403 on a list, naming the missing scope.",
        ERROR_ROUTES, &[], &["network", "list"];

    auth_status: "Auth status with the key taken from DEFINED_API_KEY.",
        &[], &[], &["auth", "status"];
    auth_list_empty: "Auth list before any login.",
        &[], &[], &["auth", "list"];
    auth_list: "Auth list with two profiles, the default marked *.",
        &[], AUTH_FILE, &["auth", "list"];
}
