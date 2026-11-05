//! `dn host debug …`: the debug commands of `POST /v1/hosts/{hostID}/command`.
//!
//! Everything here comes back from the dnclient on the host, not from
//! Defined's database, so every string is sanitized before it reaches a
//! terminal.

use std::net::IpAddr;

use serde_json::{Value, json};

use crate::api::{ApiError, Client};
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
    let res = client
        .host_command(host, &command_body(command))
        .map_err(explain_unreachable)?;
    output.emit(&res, |res| {
        let data = res.get("data").unwrap_or(&Value::Null);
        print!("{}", render(command, data));
        Ok(())
    })
}

/// The API waits about 30 seconds for the host's dnclient, then answers 408
/// `ERR_DNCLIENT_NOT_REACHABLE`. Say what to check.
fn explain_unreachable(err: anyhow::Error) -> anyhow::Error {
    let unreachable = err.downcast_ref::<ApiError>().is_some_and(|api| {
        api.errors
            .iter()
            .any(|e| e.code == "ERR_DNCLIENT_NOT_REACHABLE")
    });
    if unreachable {
        err.context(
            "the host's dnclient did not answer; `dn host get` shows when it last checked in \
             (metadata.lastSeenAt)",
        )
    } else {
        err
    }
}

/// dnclient 0.9.10 puts each answer under a key of its own (`{"cert": …}`,
/// `{"host": …}`, `{"cache": …}`, `{"stackTrace": …}`), where the spec's
/// examples have the answer bare. Either is read.
fn answer<'a>(data: &'a Value, key: &str) -> &'a Value {
    data.get(key).unwrap_or(data)
}

/// The human view of one answer. A shape the renderer doesn't know falls back
/// to the JSON, so a newer dnclient never makes the command useless.
fn render(command: &HostDebugCommand, data: &Value) -> String {
    let rendered = match command {
        // A host answers `null` for a peer it has no tunnel to.
        HostDebugCommand::Cert(a) => match answer(data, "cert") {
            Value::Null => Some(format!(
                "{} has no tunnel to {}, so it holds no certificate for it.\n",
                a.host_id, a.target
            )),
            cert @ Value::Object(_) => Some(render_cert(cert)),
            _ => None,
        },
        HostDebugCommand::Tunnel(a) => match answer(data, "host") {
            Value::Null => Some(format!("{} has no tunnel to {}.\n", a.host_id, a.target)),
            tunnel @ Value::Object(_) => Some(render_tunnel(tunnel)),
            _ => None,
        },
        // A lighthouse with nothing cached answers `null`, not `{}`.
        HostDebugCommand::Lighthouse(_) => match answer(data, "cache") {
            map @ (Value::Null | Value::Object(_)) => Some(render_lighthouse(map)),
            _ => None,
        },
        // The spec's example answers "Created"; dnclient 0.9.10 answers `{}`.
        HostDebugCommand::CreateTunnel(a) => match data {
            Value::String(s) => Some(format!(
                "Asked {} to open a tunnel to {}; dnclient said \"{}\".\n",
                a.host_id,
                a.target,
                sanitize_for_display(s)
            )),
            Value::Object(o) if o.is_empty() => Some(format!(
                "Asked {} to open a tunnel to {}.\n",
                a.host_id, a.target
            )),
            _ => None,
        },
        HostDebugCommand::Stack(_) => answer(data, "stackTrace").as_str().map(sanitize_lines),
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
        ("Nebula IP", nebula_ips(t)),
        ("Using", addr(t.get("currentRemote"))),
        ("Known addresses", addrs(t.get("remoteAddrs"))),
        ("Relays to me", addrs(t.get("currentRelaysToMe"))),
        ("Relays through me", addrs(t.get("currentRelaysThroughMe"))),
        ("Messages", count(t, "messageCounter")),
        ("Cached packets", count(t, "cachedPackets")),
        ("Fingerprint", str_field(cert, "fingerprint").to_string()),
    ])
}

/// The peer's overlay addresses: `vpnAddrs` since dnclient 0.9.10, one
/// `vpnIp` before it.
fn nebula_ips(t: &Value) -> String {
    let addrs = joined_field(t, "vpnAddrs");
    if addrs.is_empty() {
        str_field(t, "vpnIp").to_string()
    } else {
        addrs
    }
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
