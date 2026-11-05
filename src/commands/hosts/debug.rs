//! `dn host debug …`: the debug commands of `POST /v1/hosts/{hostID}/command`.
//!
//! Everything here comes back from the dnclient on the host, not from
//! Defined's database, so every string is sanitized before it reaches a
//! terminal.

use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::time::Duration;

use serde_json::{Value, json};

use crate::api::Client;
use crate::cli::HostDebugCommand;
use crate::output::{
    OutputMode, joined_field, render_details, render_table, sanitize_for_display, str_field,
};

/// Extra time the stream gets past `--duration`, for the request to reach
/// the host and the last lines to come back.
const STREAM_SLACK: Duration = Duration::from_secs(30);

impl HostDebugCommand {
    /// The host whose dnclient runs the command.
    pub fn host_id(&self) -> &str {
        match self {
            Self::Cert(a) | Self::Tunnel(a) | Self::CreateTunnel(a) => &a.host_id,
            Self::Lighthouse(a) => &a.host_id,
            Self::Stack(a) => &a.host_id,
            Self::Logs(a) => &a.host_id,
        }
    }
}

/// The request body for one debug command, as the API's `oneOf` spells it.
/// DebugStack takes no arguments, but the schema still requires `args`.
pub(crate) fn command_body(command: &HostDebugCommand) -> Value {
    let target = |ip: &IpAddr| json!({ "target": ip.to_string() });
    let (name, args) = match command {
        HostDebugCommand::Cert(a) => ("PrintCert", target(&a.target)),
        HostDebugCommand::Tunnel(a) => ("PrintTunnel", target(&a.target)),
        HostDebugCommand::CreateTunnel(a) => ("CreateTunnel", target(&a.target)),
        HostDebugCommand::Lighthouse(a) => ("QueryLighthouse", target(&a.target)),
        HostDebugCommand::Stack(_) => ("DebugStack", json!({})),
        HostDebugCommand::Logs(a) => (
            "StreamLogs",
            json!({
                "durationSeconds": a.duration.as_secs(),
                "level": a.level.as_api(),
            }),
        ),
    };
    json!({ "command": name, "args": args })
}

pub fn hosts_debug(
    client: &Client,
    command: &HostDebugCommand,
    output: OutputMode,
) -> anyhow::Result<()> {
    let host = command.host_id();
    let body = command_body(command);
    if let HostDebugCommand::Logs(args) = command {
        let res = client.host_command_stream(host, &body, args.duration + STREAM_SLACK)?;
        let reader = BufReader::new(res.into_body().into_reader());
        return stream_logs(reader, &mut std::io::stdout().lock(), output);
    }
    let res = client.host_command(host, &body)?;
    output.emit(&res, |res| {
        let data = res.get("data").unwrap_or(&Value::Null);
        print!("{}", render(command, data));
        Ok(())
    })
}

/// The human view of one answer. A shape the renderer doesn't know falls back
/// to the JSON, so a newer dnclient never makes the command useless.
fn render(command: &HostDebugCommand, data: &Value) -> String {
    let rendered = match command {
        HostDebugCommand::Cert(_) => data.is_object().then(|| render_cert(data)),
        HostDebugCommand::Tunnel(_) => data.is_object().then(|| render_tunnel(data)),
        // A lighthouse with nothing cached answers `null`, not `{}`.
        HostDebugCommand::Lighthouse(_) => match data {
            Value::Null | Value::Object(_) => Some(render_lighthouse(data)),
            _ => None,
        },
        HostDebugCommand::CreateTunnel(a) => data.as_str().map(|s| {
            format!(
                "Asked {} to open a tunnel to {}; dnclient said \"{}\".\n",
                a.host_id,
                a.target,
                sanitize_for_display(s)
            )
        }),
        HostDebugCommand::Stack(_) => data.as_str().map(sanitize_lines),
        HostDebugCommand::Logs(_) => None,
    };
    rendered.unwrap_or_else(|| {
        let mut s = serde_json::to_string_pretty(data).unwrap_or_default();
        s.push('\n');
        s
    })
}

/// A Nebula certificate as dnclient prints it. Version 1 lists `ips` and
/// `subnets`; version 2 (dnclient 0.9.10 and later) calls them `networks` and
/// `unsafeNetworks`, so either spelling is read.
fn render_cert(cert: &Value) -> String {
    let d = cert.get("details").unwrap_or(&Value::Null);
    let either = |v1: &str, v2: &str| {
        let shown = joined_field(d, v1);
        if shown.is_empty() {
            joined_field(d, v2)
        } else {
            shown
        }
    };
    render_details(&[
        ("Name", str_field(d, "name").to_string()),
        ("Networks", either("ips", "networks")),
        ("Unsafe networks", either("subnets", "unsafeNetworks")),
        ("Groups", joined_field(d, "groups")),
        (
            "Valid",
            format!(
                "{} to {}",
                str_field(d, "notBefore"),
                str_field(d, "notAfter")
            ),
        ),
        ("Fingerprint", str_field(cert, "fingerprint").to_string()),
        ("Issuer", str_field(d, "issuer").to_string()),
    ])
}

fn render_tunnel(t: &Value) -> String {
    let cert = t.get("cert").unwrap_or(&Value::Null);
    let peer = str_field(cert.get("details").unwrap_or(&Value::Null), "name");
    render_details(&[
        ("Peer", peer.to_string()),
        ("Nebula IP", str_field(t, "vpnIp").to_string()),
        ("Using", addr(t.get("currentRemote"))),
        ("Known addresses", addrs(t.get("remoteAddrs"))),
        ("Relays to me", addrs(t.get("currentRelaysToMe"))),
        ("Relays through me", addrs(t.get("currentRelaysThroughMe"))),
        ("Messages", count(t, "messageCounter")),
        ("Cached packets", count(t, "cachedPackets")),
        ("Fingerprint", str_field(cert, "fingerprint").to_string()),
    ])
}

/// One row per VPN IP in the lighthouse's map, with where its addresses came
/// from: `reported` by the host itself, or `learned` by the lighthouse.
fn render_lighthouse(map: &Value) -> String {
    let entries = map.as_object().filter(|e| !e.is_empty());
    let Some(entries) = entries else {
        return "The lighthouse knows no hosts yet. Run it again: each call also asks for an update.\n"
            .to_string();
    };
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|(ip, e)| {
            let (source, list) = if e.get("reported").is_some() {
                ("reported", e.get("reported"))
            } else {
                ("learned", e.get("learned"))
            };
            vec![
                ip.clone(),
                source.to_string(),
                addrs(list),
                none_as_dash(addrs(e.get("relay"))),
            ]
        })
        .collect();
    render_table(&["NEBULA IP", "SOURCE", "ADDRESSES", "RELAYS"], &rows)
}

fn addr(v: Option<&Value>) -> String {
    match v {
        Some(Value::Object(o)) => match (o.get("ip"), o.get("port")) {
            (Some(Value::String(ip)), Some(port)) if ip.contains(':') => format!("[{ip}]:{port}"),
            (Some(Value::String(ip)), Some(port)) => format!("{ip}:{port}"),
            _ => String::new(),
        },
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn addrs(v: Option<&Value>) -> String {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| addr(Some(x)))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn none_as_dash(s: String) -> String {
    if s.is_empty() { "-".to_string() } else { s }
}

fn count(v: &Value, key: &str) -> String {
    v.get(key).map(Value::to_string).unwrap_or_default()
}

/// Sanitize text that is meant to span lines (a stack trace) one line at a
/// time, so the newlines survive and nothing else that moves the cursor does.
fn sanitize_lines(s: &str) -> String {
    let mut out = String::new();
    for line in s.lines() {
        out.push_str(&sanitize_for_display(line));
        out.push('\n');
    }
    out
}

/// Copy StreamLogs to `out` as it arrives. The docs promise NDJSON, but their
/// example is one `{"data": "<ndjson>"}` document, so both are taken: a line
/// that is a lone `data` string is opened up into the lines it carries.
pub(crate) fn stream_logs(
    reader: impl BufRead,
    out: &mut impl Write,
    output: OutputMode,
) -> anyhow::Result<()> {
    for line in reader.lines() {
        let line = line?;
        match serde_json::from_str::<Value>(&line) {
            Ok(Value::Object(o)) if o.len() == 1 && o.get("data").is_some_and(Value::is_string) => {
                for inner in o["data"].as_str().unwrap_or_default().lines() {
                    emit_log_line(inner, out, output)?;
                }
            }
            _ => emit_log_line(&line, out, output)?,
        }
        out.flush()?;
    }
    Ok(())
}

fn emit_log_line(line: &str, out: &mut impl Write, output: OutputMode) -> anyhow::Result<()> {
    if line.trim().is_empty() {
        return Ok(());
    }
    let entry = serde_json::from_str::<Value>(line)
        .ok()
        .filter(Value::is_object);
    match (output, entry) {
        // Re-serialize rather than echo, so `--json` stays one object per
        // line even if the host sent something odd.
        (OutputMode::Json, Some(entry)) => writeln!(out, "{}", serde_json::to_string(&entry)?)?,
        (OutputMode::Json, None) => writeln!(out, "{}", json!({ "raw": line }))?,
        (OutputMode::Human, Some(entry)) => writeln!(out, "{}", render_log(&entry))?,
        (OutputMode::Human, None) => writeln!(out, "{}", sanitize_for_display(line))?,
    }
    Ok(())
}

/// `time level msg key=value…`, the way logfmt reads.
fn render_log(entry: &Value) -> String {
    let mut parts = vec![
        str_field(entry, "time").to_string(),
        str_field(entry, "level").to_uppercase(),
        str_field(entry, "msg").to_string(),
    ];
    if let Some(o) = entry.as_object() {
        for (k, v) in o {
            if matches!(k.as_str(), "time" | "level" | "msg") {
                continue;
            }
            let v = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            parts.push(format!("{k}={v}"));
        }
    }
    sanitize_for_display(&parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{
        HostDebugLighthouseArgs, HostDebugLogsArgs, HostDebugTargetArgs, HostGetArgs, LogLevel,
    };
    use proptest::prelude::*;

    const HOST: &str = "host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI";

    fn target(ip: &str) -> HostDebugTargetArgs {
        HostDebugTargetArgs {
            host_id: HOST.to_string(),
            target: ip.parse().unwrap(),
        }
    }

    #[test]
    fn each_subcommand_sends_the_body_the_spec_names() {
        let cases = [
            (
                HostDebugCommand::Cert(target("10.0.0.2")),
                json!({"command": "PrintCert", "args": {"target": "10.0.0.2"}}),
            ),
            (
                HostDebugCommand::Tunnel(target("10.0.0.2")),
                json!({"command": "PrintTunnel", "args": {"target": "10.0.0.2"}}),
            ),
            (
                HostDebugCommand::CreateTunnel(target("10.0.0.2")),
                json!({"command": "CreateTunnel", "args": {"target": "10.0.0.2"}}),
            ),
            (
                HostDebugCommand::Lighthouse(HostDebugLighthouseArgs {
                    host_id: HOST.into(),
                    target: "10.0.0.1".parse().unwrap(),
                }),
                json!({"command": "QueryLighthouse", "args": {"target": "10.0.0.1"}}),
            ),
            (
                HostDebugCommand::Stack(HostGetArgs {
                    host_id: HOST.into(),
                }),
                json!({"command": "DebugStack", "args": {}}),
            ),
            (
                HostDebugCommand::Logs(HostDebugLogsArgs {
                    host_id: HOST.into(),
                    duration: Duration::from_secs(300),
                    level: LogLevel::Warning,
                }),
                json!({"command": "StreamLogs", "args": {"durationSeconds": 300, "level": "warning"}}),
            ),
        ];
        for (command, want) in cases {
            assert_eq!(command_body(&command), want);
            assert_eq!(command.host_id(), HOST);
        }
    }

    #[test]
    fn wrapped_and_bare_ndjson_print_the_same_lines() {
        let a = r#"{"level":"info","msg":"started","time":"t1"}"#;
        let b = r#"{"level":"info","msg":"Handshake message sent","time":"t2","vpnIp":"10.0.0.2"}"#;
        let bare = format!("{a}\n{b}\n");
        let wrapped = format!("{}\n", json!({ "data": format!("{a}\n{b}") }));
        let mut x = Vec::new();
        let mut y = Vec::new();
        stream_logs(bare.as_bytes(), &mut x, OutputMode::Json).unwrap();
        stream_logs(wrapped.as_bytes(), &mut y, OutputMode::Json).unwrap();
        assert_eq!(x, y);
        assert_eq!(String::from_utf8(x).unwrap().lines().count(), 2);
    }

    #[test]
    fn the_spec_examples_render() {
        let lighthouse = json!({
            "10.128.42.11": {"reported": [{"ip": "162.194.213.135", "port": 52148}], "relay": []},
            "10.255.89.11": {"learned": [{"ip": "162.194.213.8", "port": 52148}], "relay": []}
        });
        let out = render_lighthouse(&lighthouse);
        assert!(
            out.contains("10.128.42.11  reported  162.194.213.135:52148"),
            "{out}"
        );
        assert!(
            out.contains("10.255.89.11  learned   162.194.213.8:52148"),
            "{out}"
        );
    }

    proptest! {
        /// Whatever a host sends, a log line in human mode is one terminal
        /// line with no control characters, and `--json` is one object.
        #[test]
        fn any_log_line_stays_one_safe_line(line in "\\PC*|[\\x00-\\x1f\\x7f\\u{80}-\\u{9f}a-z{}\":,]*") {
            let mut human = Vec::new();
            emit_log_line(&line, &mut human, OutputMode::Human).unwrap();
            let human = String::from_utf8(human).unwrap();
            prop_assert!(human.is_empty() || human.ends_with('\n'));
            prop_assert!(human.trim_end_matches('\n').chars().all(|c| !c.is_control()));

            let mut json = Vec::new();
            emit_log_line(&line, &mut json, OutputMode::Json).unwrap();
            for l in String::from_utf8(json).unwrap().lines() {
                prop_assert!(serde_json::from_str::<Value>(l).unwrap().is_object());
            }
        }

        /// However the host's lines arrive (bare NDJSON or folded into one
        /// `{"data": "..."}` document), the same lines come out.
        #[test]
        fn wrapped_and_bare_agree(entries in prop::collection::vec(
            prop::collection::btree_map("[a-z]{1,8}", "\\PC{0,12}", 0..4), 0..6)
        ) {
            let lines: Vec<String> = entries.iter().map(|e| serde_json::to_string(e).unwrap()).collect();
            let bare = lines.iter().map(|l| format!("{l}\n")).collect::<String>();
            let wrapped = format!("{}\n", json!({ "data": lines.join("\n") }));
            for mode in [OutputMode::Json, OutputMode::Human] {
                let (mut x, mut y) = (Vec::new(), Vec::new());
                stream_logs(bare.as_bytes(), &mut x, mode).unwrap();
                stream_logs(wrapped.as_bytes(), &mut y, mode).unwrap();
                prop_assert_eq!(&x, &y);
            }
        }

        /// The target goes on the wire as the address clap parsed, in its
        /// canonical spelling, so the API never sees `010.0.0.1` or `::FFFF:…`.
        #[test]
        fn targets_round_trip(ip in any::<IpAddr>()) {
            let body = command_body(&HostDebugCommand::Cert(HostDebugTargetArgs { host_id: HOST.into(), target: ip }));
            let sent: IpAddr = body["args"]["target"].as_str().unwrap().parse().unwrap();
            prop_assert_eq!(sent, ip);
        }
    }
}
