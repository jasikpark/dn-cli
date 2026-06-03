mod api;
mod config;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use unicode_width::UnicodeWidthStr;

use crate::api::{ApiError, Client};
use crate::config::Config;

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
    /// Inspect Nebula hosts
    Hosts {
        #[command(subcommand)]
        command: HostsCommand,
    },
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
    let client = Client::new(Config::from_env()?);

    match &cli.command {
        Command::Hosts { command } => match command {
            HostsCommand::List => hosts_list(&client, cli.json)?,
        },
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
    print!("{}", render_table(&["ID", "NAME", "IP ADDRESSES"], &table_rows));

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
            let pad = widths.get(i).copied().unwrap_or(0).saturating_sub(cell.width());
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
            vec!["host-1".to_string(), "web".to_string(), "10.0.0.1".to_string()],
            vec!["h2".to_string(), "longer-name".to_string(), "10.0.0.2".to_string()],
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
