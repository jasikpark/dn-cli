//! `dn host debug …`: the debug commands of `POST /v1/hosts/{hostID}/command`.
//!
//! Everything here comes back from the dnclient on the host, not from
//! Defined's database, so every string is sanitized before it reaches a
//! terminal.

use std::net::IpAddr;

use serde_json::{Value, json};

use crate::api::Client;
use crate::cli::HostDebugCommand;
use crate::output::{
    OutputMode, joined_field, render_details, render_table, sanitize_for_display, str_field,
};

impl HostDebugCommand {
    /// The host whose dnclient runs the command.
    pub fn host_id(&self) -> &str {
        match self {
            Self::Cert(a) | Self::Tunnel(a) | Self::CreateTunnel(a) => &a.host_id,
            Self::Lighthouse(a) => &a.host_id,
            Self::Stack(a) => &a.host_id,
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
        HostDebugCommand::Lighthouse(_) => data.as_object().map(|_| render_lighthouse(data)),
        HostDebugCommand::CreateTunnel(a) => data.as_str().map(|s| {
            format!(
                "Asked {} to open a tunnel to {}; dnclient said \"{}\".\n",
                a.host_id,
                a.target,
                sanitize_for_display(s)
            )
        }),
        HostDebugCommand::Stack(_) => data.as_str().map(sanitize_lines),
    };
    rendered.unwrap_or_else(|| {
        let mut s = serde_json::to_string_pretty(data).unwrap_or_default();
        s.push('\n');
        s
    })
}

fn render_cert(cert: &Value) -> String {
    let d = cert.get("details").unwrap_or(&Value::Null);
    render_details(&[
        ("Name", str_field(d, "name").to_string()),
        ("IPs", joined_field(d, "ips")),
        ("Subnets", joined_field(d, "subnets")),
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
    let Some(entries) = map.as_object() else {
        return String::new();
    };
    if entries.is_empty() {
        return "The lighthouse knows no hosts yet. Run it again: each call also asks for an update.\n"
            .to_string();
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{HostDebugLighthouseArgs, HostDebugTargetArgs, HostGetArgs};
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
        ];
        for (command, want) in cases {
            assert_eq!(command_body(&command), want);
            assert_eq!(command.host_id(), HOST);
        }
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
