//! What `role create` / `role edit` / `tag create` / `tag edit` put on the
//! wire: method, path, and JSON body, against a mock that answers every
//! request with one canned role or tag.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{Value, json};

/// One recorded request: method, target, and the parsed JSON body (`Null`
/// when there was none).
type Request = (String, String, Value);

fn serve(body: &'static str) -> (String, Arc<Mutex<Vec<Request>>>) {
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

fn requests(seen: &Arc<Mutex<Vec<Request>>>) -> Vec<Request> {
    seen.lock().unwrap().clone()
}

const ROLE: &str = r#"{"data":{"id":"role-WEB","name":"Web servers","description":"Public HTTP",
  "hostCount":3,"firewallRulesCount":2,"firewallRules":[
    {"protocol":"TCP","portRange":{"from":443,"to":443},"allowedRoleID":null,
     "allowedTags":null,"description":"https from anywhere"},
    {"protocol":"TCP","portRange":{"from":22,"to":22},"allowedRoleID":"role-ADM",
     "allowedTags":null,"description":"ssh from admins"}]},"metadata":{}}"#;

const TAG: &str = r#"{"data":{"name":"env:prod","description":"Production","hostCount":2,
  "priority":10,"firewallRulesCount":1,"routeSubscriptions":["route-A"],
  "configOverrides":[{"key":"tun.mtu","value":1300}],
  "firewallRules":[{"protocol":"UDP","portRange":{"from":53,"to":53},
    "allowedRoleID":null,"allowedTags":["site:hou"],"description":"dns"}]},"metadata":{}}"#;

fn rule(
    protocol: &str,
    ports: Option<(u16, u16)>,
    role: Option<&str>,
    tags: Option<&[&str]>,
    desc: &str,
) -> Value {
    json!({
        "protocol": protocol,
        "portRange": ports.map(|(from, to)| json!({"from": from, "to": to})),
        "allowedRoleID": role,
        "allowedTags": tags,
        "description": desc,
    })
}

#[test]
fn role_create_posts_name_description_and_parsed_rules() {
    let (url, seen) = serve(ROLE);
    let out = dn(
        &url,
        &[
            "--json",
            "role",
            "create",
            "Web servers",
            "--description",
            "Public HTTP",
            "--rule",
            "tcp/443,desc=https from anywhere",
            "--rule",
            "tcp/22,from=role-ADM,tag=team:ops,tag=env:prod,desc=ssh, admins only",
            "--rule",
            "icmp",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let want = json!({
        "name": "Web servers",
        "description": "Public HTTP",
        "firewallRules": [
            rule("TCP", Some((443, 443)), None, None, "https from anywhere"),
            rule("TCP", Some((22, 22)), Some("role-ADM"), Some(&["team:ops", "env:prod"]), "ssh, admins only"),
            rule("ICMP", None, None, None, ""),
        ],
    });
    assert_eq!(
        requests(&seen),
        [("POST".to_string(), "/v1/roles".to_string(), want)]
    );
}

#[test]
fn role_edit_reads_the_role_then_puts_the_whole_thing_back() {
    let (url, seen) = serve(ROLE);
    let out = dn(
        &url,
        &[
            "--json",
            "role",
            "edit",
            "role-WEB",
            "--remove-rule",
            "tcp/22,from=role-ADM",
            "--add-rule",
            "udp/53,desc=dns",
            "--add-rule",
            "tcp/443,desc=https (renamed)",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let seen = requests(&seen);
    assert_eq!(
        (seen[0].0.as_str(), seen[0].1.as_str()),
        ("GET", "/v1/roles/role-WEB")
    );
    assert_eq!(
        (seen[1].0.as_str(), seen[1].1.as_str()),
        ("PUT", "/v1/roles/role-WEB")
    );
    assert_eq!(
        seen[1].2,
        json!({
            "description": "Public HTTP",
            "firewallRules": [
                rule("TCP", Some((443, 443)), None, None, "https (renamed)"),
                rule("UDP", Some((53, 53)), None, None, "dns"),
            ],
        })
    );
    assert_eq!(seen.len(), 2);
}

#[test]
fn role_edit_that_changes_nothing_only_reads() {
    let (url, seen) = serve(ROLE);
    let out = dn(
        &url,
        &["role", "edit", "role-WEB", "--description", "Public HTTP"],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(requests(&seen).len(), 1);
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing changed"));
}

#[test]
fn role_edit_clear_rules_sends_an_empty_list() {
    let (url, seen) = serve(ROLE);
    let out = dn(
        &url,
        &[
            "--json",
            "role",
            "edit",
            "role-WEB",
            "--clear-rules",
            "--description",
            "",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        requests(&seen)[1].2,
        json!({"description": "", "firewallRules": []})
    );
}

#[test]
fn tag_create_posts_only_what_was_given() {
    let (url, seen) = serve(TAG);
    let out = dn(
        &url,
        &[
            "--json",
            "tag",
            "create",
            "env:prod",
            "--route",
            "route-A",
            "--after",
            "env:staging",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        requests(&seen),
        [(
            "POST".to_string(),
            "/v1/tags".to_string(),
            json!({"name": "env:prod", "routeSubscriptions": ["route-A"], "after": "env:staging"}),
        )]
    );
}

#[test]
fn tag_edit_patches_only_the_fields_that_change() {
    let (url, seen) = serve(TAG);
    let out = dn(
        &url,
        &[
            "--json",
            "tag",
            "edit",
            "env:prod",
            "--description",
            "Production", // unchanged: left out of the PATCH
            "--add-rule",
            "tcp/443",
            "--add-route",
            "route-A", // already subscribed: no change
            "--add-route",
            "route-B",
            "--before",
            "env:dev",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let seen = requests(&seen);
    assert_eq!(
        (seen[0].0.as_str(), seen[0].1.as_str()),
        ("GET", "/v1/tags/env:prod")
    );
    assert_eq!(
        (seen[1].0.as_str(), seen[1].1.as_str()),
        ("PATCH", "/v1/tags/env:prod")
    );
    assert_eq!(
        seen[1].2,
        json!({
            "firewallRules": [
                rule("UDP", Some((53, 53)), None, Some(&["site:hou"]), "dns"),
                rule("TCP", Some((443, 443)), None, None, ""),
            ],
            "routeSubscriptions": ["route-A", "route-B"],
            "before": "env:dev",
        })
    );
    // Config overrides are never part of the body.
    assert!(seen[1].2.get("configOverrides").is_none());
}

#[test]
fn tag_edit_that_changes_nothing_only_reads() {
    let (url, seen) = serve(TAG);
    let out = dn(
        &url,
        &["tag", "edit", "env:prod", "--remove-route", "route-Z"],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(requests(&seen).len(), 1);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not subscribed to route \"route-Z\""),
        "{stderr}"
    );
    assert!(stderr.contains("nothing changed"), "{stderr}");
}

const ROLE_ZERO_PORTS: &str = r#"{"data":{"id":"role-OPEN","name":"Open","description":"",
  "hostCount":0,"firewallRulesCount":1,"firewallRules":[
    {"protocol":"ANY","portRange":{"from":0,"to":0},"allowedRoleID":null,
     "allowedTags":["b:1","a:1"],"description":"open"}]},"metadata":{}}"#;

#[test]
fn re_adding_a_rule_the_api_encoded_differently_writes_nothing() {
    let (url, seen) = serve(ROLE_ZERO_PORTS);
    let out = dn(
        &url,
        &[
            "role",
            "edit",
            "role-OPEN",
            "--add-rule",
            "any,tag=a:1,tag=b:1,desc=open",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(requests(&seen).len(), 1, "only the read");
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing changed"));
}

#[test]
fn changing_only_a_description_keeps_the_stored_rule_encoding() {
    let (url, seen) = serve(ROLE_ZERO_PORTS);
    let out = dn(
        &url,
        &[
            "--json",
            "role",
            "edit",
            "role-OPEN",
            "--add-rule",
            "any,tag=a:1,tag=b:1,desc=wide open",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let seen = requests(&seen);
    assert_eq!(seen[1].0, "PUT");
    assert_eq!(
        seen[1].2["firewallRules"],
        json!([{"protocol":"ANY","portRange":{"from":0,"to":0},"allowedRoleID":null,
                "allowedTags":["b:1","a:1"],"description":"wide open"}])
    );
}

const ROLE_ODD_TAGS: &str = r#"{"data":{"id":"role-ODD","name":"Odd","description":"",
  "hostCount":0,"firewallRulesCount":1,"firewallRules":[
    {"protocol":"TCP","portRange":{"from":22,"to":22},"allowedRoleID":null,
     "allowedTags":"env:prod","description":"ssh"}]},"metadata":{}}"#;

const TAG_ODD_ROUTES: &str = r#"{"data":{"name":"env:prod","description":"Production","hostCount":2,
  "priority":10,"routeSubscriptions":["route-A",7],"firewallRules":[]},"metadata":{}}"#;

#[test]
fn an_edit_refuses_to_write_over_a_response_it_cannot_read() {
    // A tag restriction stored in a shape this code doesn't understand must
    // not be matched as "no tags" and removed.
    let (url, seen) = serve(ROLE_ODD_TAGS);
    let out = dn(
        &url,
        &["role", "edit", "role-ODD", "--remove-rule", "tcp/22"],
    );
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(requests(&seen).len(), 1, "read only, no PUT");
    assert!(String::from_utf8_lossy(&out.stderr).contains("firewall rule 0"));

    // Likewise a route list with an entry that isn't a string.
    let (url, seen) = serve(TAG_ODD_ROUTES);
    let out = dn(&url, &["tag", "edit", "env:prod", "--add-route", "route-B"]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(requests(&seen).len(), 1, "read only, no PATCH");
    assert!(String::from_utf8_lossy(&out.stderr).contains("routeSubscriptions"));
}

#[test]
fn a_bad_rule_spec_fails_before_any_request() {
    let (url, seen) = serve(ROLE);
    for args in [
        vec!["role", "create", "x", "--rule", "sctp/22"],
        vec!["role", "edit", "role-WEB", "--add-rule", "tcp/0"],
        vec!["tag", "create", "env:prod", "--rule", "tcp,port=22"],
        vec!["tag", "edit", "env:prod", "--remove-rule", "icmp/8"],
        vec!["tag", "edit", "env:prod", "--before", "nocolon"],
        vec!["role", "edit", "role-WEB"],
    ] {
        let out = dn(&url, &args);
        assert!(!out.status.success(), "{args:?}: {out:?}");
    }
    assert!(requests(&seen).is_empty());
}
