//! `dn host debug …`: the debug commands of `POST /v1/hosts/{hostID}/command`.
//!
//! Everything here comes back from the dnclient on the host, not from
//! Defined's database, so every string is sanitized before it reaches a
//! terminal.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::time::Duration;

use anyhow::Context;
use serde_json::{Map, Value, json};

use crate::api::Client;
use crate::cli::HostDebugCommand;
use crate::error::TimedOut;
use crate::output::{
    OutputMode, joined_field, render_details, render_table, sanitize_for_display, str_field,
};

/// Extra time the stream gets past `--duration`, for the request to reach
/// the host and the last lines to come back.
const STREAM_SLACK: Duration = Duration::from_secs(30);

/// The longest line the stream may send. A ten-minute session at `debug`
/// folded into one document fits; a body that never ends its line stops
/// here instead of filling memory until the timeout.
const MAX_LOG_LINE: u64 = 64 * 1024 * 1024;

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
        let logs = client.host_command_stream(host, &body, args.duration + STREAM_SLACK)?;
        return stream_logs(BufReader::new(logs), &mut io::stdout().lock(), output);
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
        // Never reached: `hosts_debug` streams the logs itself.
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

/// Copy StreamLogs to `out` as it arrives, a line at a time. A reader that
/// hangs up (`| head -1`) ends the stream without an error.
pub(crate) fn stream_logs(
    mut reader: impl BufRead,
    out: &mut impl Write,
    output: OutputMode,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    loop {
        match read_line(&mut reader, &mut buf, MAX_LOG_LINE) {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(e) if is_timeout(&e) => {
                return Err(TimedOut(format!(
                    "the log stream was still open after --duration and {}s more: {e}",
                    STREAM_SLACK.as_secs()
                ))
                .into());
            }
            Err(e) => return Err(e).context("the log stream broke off"),
        }
        // Lossy, so one bad byte costs a character and not the session.
        match write_line(&String::from_utf8_lossy(&buf), out, output) {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
            written => written.context("could not print a log line")?,
        }
    }
}

/// Read the next line into `buf`, newline included; `false` once the stream
/// has ended. A line longer than `max` bytes is an error.
fn read_line(reader: &mut impl BufRead, buf: &mut Vec<u8>, max: u64) -> io::Result<bool> {
    buf.clear();
    reader.take(max).read_until(b'\n', buf)?;
    if buf.len() as u64 == max && buf.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a log line is longer than {max} bytes"),
        ));
    }
    Ok(!buf.is_empty())
}

/// ureq reports its own timeout as an `Other` error wrapping `Error::Timeout`.
fn is_timeout(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::TimedOut
        || matches!(
            e.get_ref().and_then(|inner| inner.downcast_ref()),
            Some(ureq::Error::Timeout(_))
        )
}

/// Print what one line of the response carries. The docs promise NDJSON, a
/// log entry per line, but their example is one `{"data": "<entries>"}`
/// document, so both are taken.
fn write_line(line: &str, out: &mut impl Write, output: OutputMode) -> io::Result<()> {
    if line.trim().is_empty() {
        return Ok(());
    }
    match serde_json::from_str::<Value>(line) {
        Ok(Value::Object(o)) => match folded_entries(&o) {
            Some(data) => {
                for inner in data.lines() {
                    write_folded(inner, out, output)?;
                }
            }
            None => write_entry(&o, out, output)?,
        },
        _ => write_raw(line.trim_end_matches(['\r', '\n']), out, output)?,
    }
    out.flush()
}

/// The `data` string of a document that folds the entries into one answer.
/// dnclient's own entries always have a `msg` and a `level`; the API's
/// envelope has neither, whatever else (`metadata`) it carries.
fn folded_entries(o: &Map<String, Value>) -> Option<&str> {
    if o.contains_key("msg") || o.contains_key("level") {
        return None;
    }
    o.get("data")?.as_str()
}

/// Print the entries on one line of a folded `data` string. The docs' example
/// separates them with a backslash and an `n`, not a newline, so whatever
/// follows an entry on its line is read as the next one.
fn write_folded(mut rest: &str, out: &mut impl Write, output: OutputMode) -> io::Result<()> {
    loop {
        rest = rest.trim_start();
        while let Some(after) = rest.strip_prefix("\\n") {
            rest = after.trim_start();
        }
        if rest.is_empty() {
            return Ok(());
        }
        let mut values = serde_json::Deserializer::from_str(rest).into_iter::<Value>();
        match values.next() {
            Some(Ok(Value::Object(o))) => {
                write_entry(&o, out, output)?;
                rest = &rest[values.byte_offset()..];
            }
            _ => return write_raw(rest, out, output),
        }
    }
}

fn write_entry(
    entry: &Map<String, Value>,
    out: &mut impl Write,
    output: OutputMode,
) -> io::Result<()> {
    match output {
        // Re-serialized rather than echoed, so `--json` stays one object per
        // line however the host spaced it.
        OutputMode::Json => writeln!(out, "{}", serde_json::to_string(entry)?),
        OutputMode::Human => writeln!(out, "{}", render_log(entry)),
    }
}

/// A line that isn't a log object: `{"raw": …}` under `--json`, so the output
/// is still one object per line.
fn write_raw(text: &str, out: &mut impl Write, output: OutputMode) -> io::Result<()> {
    match output {
        OutputMode::Json => writeln!(out, "{}", json!({ "raw": text })),
        OutputMode::Human => writeln!(out, "{}", sanitize_for_display(text)),
    }
}

/// `time LEVEL msg key=value…`, the way logfmt reads. Whichever of the three
/// leading fields the entry lacks is left out.
fn render_log(entry: &Map<String, Value>) -> String {
    const LEADING: [&str; 3] = ["time", "level", "msg"];
    let mut parts = Vec::new();
    for key in LEADING {
        let text = match entry.get(key) {
            None => continue,
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
        };
        if key == "level" {
            parts.push(text.to_uppercase());
        } else {
            parts.push(text);
        }
    }
    for (k, v) in entry {
        if !LEADING.contains(&k.as_str()) {
            parts.push(format!("{k}={}", logfmt_value(v)));
        }
    }
    parts.retain(|part| !part.is_empty());
    if parts.is_empty() {
        return "{}".to_string();
    }
    sanitize_for_display(&parts.join(" "))
}

/// A string is quoted when it wouldn't read back as one value, so a host
/// can't pass `x vpnIp=10.0.0.9` off as a second field.
fn logfmt_value(v: &Value) -> String {
    match v {
        Value::String(s)
            if !s.is_empty()
                && !s.contains(|c: char| c.is_whitespace() || c == '"' || c == '=') =>
        {
            s.clone()
        }
        other => other.to_string(),
    }
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

    const STARTED: &str = r#"{"level":"info","msg":"started","time":"t1"}"#;
    const HANDSHAKE: &str =
        r#"{"level":"info","msg":"Handshake message sent","time":"t2","vpnIp":"10.0.0.2"}"#;

    fn streamed(input: &[u8], output: OutputMode) -> String {
        let mut out = Vec::new();
        stream_logs(input, &mut out, output).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn wrapped_and_bare_ndjson_print_the_same_lines() {
        let bare = streamed(
            format!("{STARTED}\n{HANDSHAKE}\n").as_bytes(),
            OutputMode::Json,
        );
        assert_eq!(bare.lines().count(), 2);
        let wrapped = json!({ "data": format!("{STARTED}\n{HANDSHAKE}") });
        assert_eq!(
            streamed(format!("{wrapped}\n").as_bytes(), OutputMode::Json),
            bare
        );
    }

    /// The docs' StreamLogs example: the entries in one `data` string, with a
    /// backslash and an `n` between them where a newline would be.
    #[test]
    fn the_docs_example_separates_entries_with_a_literal_backslash_n() {
        // An escaped newline inside a message is not a separator.
        let two_lines = r#"{"level":"error","msg":"first\nsecond","time":"t3"}"#;
        let bare = streamed(
            format!("{STARTED}\n{two_lines}\n{HANDSHAKE}\n").as_bytes(),
            OutputMode::Json,
        );
        assert_eq!(bare.lines().count(), 3);
        let wrapped = json!({ "data": format!("{STARTED}\\n{two_lines}\\n{HANDSHAKE}\\n") });
        assert_eq!(
            streamed(format!("{wrapped}\n").as_bytes(), OutputMode::Json),
            bare
        );
    }

    #[test]
    fn an_envelope_with_metadata_is_opened_too() {
        let wrapped = json!({ "data": format!("{STARTED}\n{HANDSHAKE}"), "metadata": {} });
        assert_eq!(
            streamed(format!("{wrapped}\n").as_bytes(), OutputMode::Json),
            format!("{STARTED}\n{HANDSHAKE}\n")
        );
    }

    #[test]
    fn an_entry_with_a_data_field_of_its_own_stays_an_entry() {
        let entry = r#"{"data":"payload","level":"info","msg":"sent","time":"t1"}"#;
        assert_eq!(
            streamed(format!("{entry}\n").as_bytes(), OutputMode::Json),
            format!("{entry}\n")
        );
    }

    #[test]
    fn a_bad_byte_costs_a_character_and_not_the_session() {
        let mut input = format!("{STARTED}\n").into_bytes();
        input.extend(b"{\"msg\":\"bad \xff byte\"}\n");
        input.extend(format!("{HANDSHAKE}\n").as_bytes());
        let out = streamed(&input, OutputMode::Human);
        assert_eq!(out.lines().count(), 3, "{out}");
        assert!(out.contains("bad \u{fffd} byte"), "{out}");
        assert!(out.ends_with("vpnIp=10.0.0.2\n"), "{out}");
    }

    /// A writer whose reader has gone away, as stdout is after `| head -1`.
    struct HungUp;

    impl Write for HungUp {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_reader_that_hangs_up_ends_the_stream_without_an_error() {
        let input = format!("{STARTED}\n{HANDSHAKE}\n");
        for mode in [OutputMode::Json, OutputMode::Human] {
            stream_logs(input.as_bytes(), &mut HungUp, mode).unwrap();
        }
    }

    /// A body that gives `sent`, then fails the way ureq does at its timeout.
    struct TimesOut(&'static [u8]);

    impl Read for TimesOut {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::Error::other(ureq::Error::Timeout(
                    ureq::Timeout::Global,
                )));
            }
            self.0.read(buf)
        }
    }

    #[test]
    fn a_stream_cut_off_by_the_timeout_keeps_its_lines_and_is_a_timeout() {
        let mut out = Vec::new();
        let body = BufReader::new(TimesOut(b"{\"msg\":\"started\"}\n"));
        let err = stream_logs(body, &mut out, OutputMode::Json).unwrap_err();
        assert!(err.downcast_ref::<TimedOut>().is_some(), "{err:#}");
        assert_eq!(out, b"{\"msg\":\"started\"}\n");
    }

    #[test]
    fn a_line_past_the_limit_is_an_error_and_a_shorter_one_is_not() {
        let mut buf = Vec::new();
        let mut short = &b"abc\ndefg\n"[..];
        assert!(read_line(&mut short, &mut buf, 5).unwrap());
        assert_eq!(buf, b"abc\n");
        assert!(read_line(&mut short, &mut buf, 5).unwrap());
        assert_eq!(buf, b"defg\n");
        assert!(!read_line(&mut short, &mut buf, 5).unwrap());

        let mut long = &b"abcdefgh\n"[..];
        let err = read_line(&mut long, &mut buf, 5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_log_line_shows_every_field_the_entry_has() {
        let line = |entry: Value| render_log(entry.as_object().unwrap());
        assert_eq!(
            line(json!({"level": "info", "msg": {"code": 7}, "time": 1730822400})),
            r#"1730822400 INFO {"code":7}"#
        );
        assert_eq!(
            line(json!({"msg": "no time", "error": "dial tcp: i/o timeout"})),
            r#"no time error="dial tcp: i/o timeout""#
        );
        assert_eq!(
            line(json!({"msg": "m", "peer": "x vpnIp=10.0.0.9", "empty": ""})),
            r#"m peer="x vpnIp=10.0.0.9" empty="""#
        );
        assert_eq!(line(json!({})), "{}");
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
            write_line(&line, &mut human, OutputMode::Human).unwrap();
            let human = String::from_utf8(human).unwrap();
            prop_assert!(human.is_empty() || human.ends_with('\n'));
            prop_assert!(human.split('\n').all(|l| l.chars().all(|c| !c.is_control())));

            let mut json = Vec::new();
            write_line(&line, &mut json, OutputMode::Json).unwrap();
            for l in String::from_utf8(json).unwrap().lines() {
                prop_assert!(serde_json::from_str::<Value>(l).unwrap().is_object());
            }
        }

        /// However the host's entries arrive (bare NDJSON, or folded into one
        /// `{"data": "..."}` document with a newline or the docs' literal
        /// `\n` between them), the same lines come out. Every entry has a
        /// `msg`, as dnclient's do.
        #[test]
        fn wrapped_and_bare_agree(
            entries in prop::collection::vec(
                (prop::collection::btree_map("[a-z]{1,8}", "\\PC{0,12}", 0..4), "\\PC{0,12}"), 0..6),
            separator in prop::sample::select(vec!["\n", "\\n"]),
        ) {
            let lines: Vec<String> = entries.iter().map(|(fields, msg)| {
                let mut entry = fields.clone();
                entry.insert("msg".to_string(), msg.clone());
                serde_json::to_string(&entry).unwrap()
            }).collect();
            let bare = lines.iter().map(|l| format!("{l}\n")).collect::<String>();
            let wrapped = format!("{}\n", json!({ "data": lines.join(separator) }));
            for mode in [OutputMode::Json, OutputMode::Human] {
                prop_assert_eq!(streamed(bare.as_bytes(), mode), streamed(wrapped.as_bytes(), mode));
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
