mod api;
mod config;

use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};
use unicode_width::UnicodeWidthStr;

use crate::api::{ApiError, Client};
use crate::config::{Config, FileConfig, KeySource, config_path, op_read, validate_op_ref};

#[derive(Parser)]
#[command(name = "dn", version, about = "CLI for the Defined Networking API")]
struct Cli {
    /// Output machine-readable JSON (including errors) instead of human tables
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Configure how `dn` finds your API key
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Inspect Nebula hosts
    Hosts {
        #[command(subcommand)]
        command: HostsCommand,
    },
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Store a 1Password secret reference to your API key. The key itself is
    /// never written to disk; every `dn` call resolves it with `op read`.
    Login(AuthLoginArgs),
    /// Show where the API key comes from (never prints the key)
    Status,
    /// Forget the stored secret reference
    Logout,
}

#[derive(Args)]
struct AuthLoginArgs {
    /// 1Password secret reference to the API key. Prompted for when omitted
    /// (interactive terminals only).
    #[arg(long = "ref", value_name = "op://vault/item/field")]
    reference: Option<String>,
    /// Skip resolving the reference and calling the API before saving
    #[arg(long)]
    no_verify: bool,
}

#[derive(Subcommand)]
enum HostsCommand {
    /// List hosts
    List,
}

/// Generic JSON error envelope for non-API errors (config, network, parse).
/// API errors serialize via [`ApiError`]'s own richer shape instead.
#[derive(Serialize)]
struct GenericError<'a> {
    error: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    causes: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            report_error(&err, cli.json);
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        Command::Auth { command } => match command {
            AuthCommand::Login(args) => auth_login(args, cli.json)?,
            AuthCommand::Status => auth_status(cli.json)?,
            AuthCommand::Logout => auth_logout(cli.json)?,
        },
        Command::Hosts { command } => {
            let client = Client::new(Config::load()?);
            match command {
                HostsCommand::List => hosts_list(&client, cli.json)?,
            }
        }
    }

    Ok(())
}

const API_KEYS_URL: &str = "https://admin.defined.net/settings/api-keys/add";

fn auth_login(args: &AuthLoginArgs, json: bool) -> anyhow::Result<()> {
    let reference = match &args.reference {
        Some(r) => r.trim().to_string(),
        None => prompt_for_reference(json)?,
    };
    validate_op_ref(&reference)?;

    let mut file = FileConfig::load()?;
    if !args.no_verify {
        let key = op_read(&reference)?;
        Client::new(Config::with_key(key, &file))
            .get("/v2/networks?pageSize=1")
            .context("the key resolved but the API rejected it")?;
    }
    file.api_key_ref = Some(reference.clone());
    let path = file.save()?;

    if json {
        println!(
            "{}",
            json!({ "ok": true, "config_path": path, "api_key_ref": reference })
        );
    } else {
        println!(
            "Saved reference to {}. `dn` will resolve it with `op read` on every call.",
            path.display()
        );
    }
    Ok(())
}

/// Interactive-only: explain where to mint a key, then read the reference from
/// stdin. Agents pass `--ref` instead — no prompt ever blocks a `--json` run.
fn prompt_for_reference(json: bool) -> anyhow::Result<String> {
    if json || !std::io::stdin().is_terminal() {
        bail!("pass --ref when running non-interactively");
    }
    let mut err = std::io::stderr();
    writeln!(
        err,
        "Create an API key at {API_KEYS_URL} (pick only the permissions you need),\n\
         save it in 1Password, then right-click the field \u{2192} Copy Secret Reference."
    )?;
    write!(err, "Secret reference (op://vault/item/field): ")?;
    err.flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let line = line.trim();
    if line.is_empty() {
        bail!("no reference entered");
    }
    Ok(line.to_string())
}

fn auth_status(json: bool) -> anyhow::Result<()> {
    let source = KeySource::detect()?;
    let file = FileConfig::load()?;
    let path = config_path()?;
    let api_url = Config::with_key(String::new(), &file).api_url;
    let label = source.as_ref().map_or("none", KeySource::label);
    let reference = source.as_ref().and_then(KeySource::reference);

    if json {
        println!(
            "{}",
            json!({
                "source": label,
                "api_key_ref": reference,
                "config_path": path,
                "api_url": api_url,
            })
        );
        return Ok(());
    }

    match &source {
        None => println!("No API key configured. Run `dn auth login` or set DEFINED_API_KEY."),
        Some(KeySource::Env(_)) => println!("API key: DEFINED_API_KEY (raw value in environment)"),
        Some(KeySource::EnvRef(r)) => {
            println!("API key: DEFINED_API_KEY -> {r} (resolved via op read)")
        }
        Some(KeySource::FileRef(r)) => println!(
            "API key: {r} (from {}, resolved via op read)",
            path.display()
        ),
    }
    println!("API URL: {api_url}");
    Ok(())
}

fn auth_logout(json: bool) -> anyhow::Result<()> {
    let mut file = FileConfig::load()?;
    let removed = file.api_key_ref.take();
    let path = file.save()?;

    if json {
        println!(
            "{}",
            json!({ "ok": true, "removed": removed.is_some(), "config_path": path })
        );
    } else if removed.is_some() {
        println!(
            "Removed the stored secret reference from {}.",
            path.display()
        );
    } else {
        println!("No stored secret reference to remove.");
    }
    Ok(())
}

/// Render an error per dn-cli's two-faces design (the axocli envelope-split
/// pattern, reimplemented on anyhow): in `--json` mode emit a machine-readable
/// envelope to stdout AND a human hint to stderr; otherwise just the human
/// hint to stderr. Typed [`ApiError`]s get the rich structured shape; anything
/// else gets the generic `{error, causes}` envelope.
fn report_error(err: &anyhow::Error, json: bool) {
    if json {
        let payload = match err.downcast_ref::<ApiError>() {
            Some(api) => serde_json::to_string(api),
            None => serde_json::to_string(&GenericError {
                error: &err.to_string(),
                causes: err.chain().skip(1).map(|c| c.to_string()).collect(),
            }),
        };
        if let Ok(payload) = payload {
            println!("{payload}");
        }
    }

    eprintln!("error: {err:#}");
}

fn hosts_list(client: &Client, json: bool) -> anyhow::Result<()> {
    let res = client.list_hosts()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&res)?);
        return Ok(());
    }

    let empty: Vec<Value> = Vec::new();
    let rows = res.get("data").and_then(Value::as_array).unwrap_or(&empty);
    if rows.is_empty() {
        println!("No hosts found.");
        return Ok(());
    }

    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let (id, name, ip) = host_fields(row);
            vec![id.to_string(), name.to_string(), ip]
        })
        .collect();
    print!(
        "{}",
        render_table(&["ID", "NAME", "IP ADDRESSES"], &table_rows)
    );

    if let Some(total) = res
        .get("metadata")
        .and_then(|m| m.get("totalCount"))
        .and_then(Value::as_u64)
    {
        println!("\n{} shown / {total} total", rows.len());
    }

    Ok(())
}

/// Render rows as a left-aligned column table with a header row, padding each
/// column to its widest cell. Columns are separated by two spaces; the final
/// column is never padded (no trailing whitespace).
///
/// Widths are measured in terminal display columns via `unicode-width`, so
/// wide glyphs (emoji, CJK) and combining marks align correctly — a host named
/// `caleb-macbook-pro 💻` lines up with its plain-ASCII neighbours. Generic
/// over column count so future list commands (networks, roles, …) can reuse it.
fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.width()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.as_str().width());
            }
        }
    }

    let mut out = String::new();
    push_row(&mut out, headers, &widths);
    for row in rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        push_row(&mut out, &cells, &widths);
    }
    out
}

/// Append one padded row (newline-terminated) to `out`. The last cell is
/// emitted without trailing padding.
fn push_row(out: &mut String, cells: &[&str], widths: &[usize]) {
    let last = cells.len().saturating_sub(1);
    for (i, &cell) in cells.iter().enumerate() {
        out.push_str(cell);
        if i != last {
            let pad = widths
                .get(i)
                .copied()
                .unwrap_or(0)
                .saturating_sub(cell.width());
            out.push_str(&" ".repeat(pad));
            out.push_str("  ");
        }
    }
    out.push('\n');
}

/// The three columns the human host table renders. `id` and `name` fall back
/// to an empty string when absent or non-string; the IP column joins the v2
/// `ipAddresses` array (dual-stack: IPv4 and/or IPv6) with ", ".
fn host_fields(row: &Value) -> (&str, &str, String) {
    let field = |key| row.get(key).and_then(Value::as_str).unwrap_or_default();
    let ips = row
        .get("ipAddresses")
        .and_then(Value::as_array)
        .map(|addrs| {
            addrs
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    (field("id"), field("name"), ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn host_fields_extracts_present_columns() {
        // Dual-stack: v2 returns an ipAddresses array (IPv4 + IPv6).
        let row = json!({"id": "host-1", "name": "web", "ipAddresses": ["10.0.0.1", "fd00::1"]});
        assert_eq!(
            host_fields(&row),
            ("host-1", "web", "10.0.0.1, fd00::1".to_string())
        );
    }

    #[test]
    fn host_fields_defaults_missing_or_wrong_type() {
        // Missing name, and ipAddresses that isn't an array of strings.
        let row = json!({"id": "host-2", "ipAddresses": 42});
        assert_eq!(host_fields(&row), ("host-2", "", String::new()));
    }

    #[test]
    fn host_fields_skips_non_string_ip_entries() {
        let row = json!({"id": "host-3", "name": "db", "ipAddresses": ["10.0.0.2", 7, "fd00::2"]});
        assert_eq!(
            host_fields(&row),
            ("host-3", "db", "10.0.0.2, fd00::2".to_string())
        );
    }

    #[test]
    fn render_table_aligns_columns_no_trailing_space() {
        let rows = vec![
            vec![
                "host-1".to_string(),
                "web".to_string(),
                "10.0.0.1".to_string(),
            ],
            vec![
                "h2".to_string(),
                "longer-name".to_string(),
                "10.0.0.2".to_string(),
            ],
        ];
        let out = render_table(&["ID", "NAME", "IP"], &rows);
        assert_eq!(
            out,
            "ID      NAME         IP\n\
             host-1  web          10.0.0.1\n\
             h2      longer-name  10.0.0.2\n"
        );
        // Last column is never padded.
        assert!(out.lines().all(|l| !l.ends_with(' ')));
    }

    #[test]
    fn render_table_aligns_wide_glyphs_by_display_width() {
        // 💻 is one char but two display columns; a naive char/byte count would
        // misalign the row after it. The final column must start at the same
        // *display* offset on every line.
        let rows = vec![
            vec!["a".to_string(), "laptop 💻".to_string(), "x".to_string()],
            vec!["b".to_string(), "pc".to_string(), "y".to_string()],
        ];
        let out = render_table(&["ID", "NAME", "C"], &rows);
        let last_col_offsets: Vec<usize> = out
            .lines()
            .map(|line| line.width() - 1) // every last cell here is 1 column wide
            .collect();
        assert!(
            last_col_offsets.windows(2).all(|w| w[0] == w[1]),
            "last column misaligned across rows: {last_col_offsets:?}"
        );
    }
}
