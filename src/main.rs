mod api;
mod config;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;

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

    for row in rows {
        let (id, name, ip) = host_fields(row);
        println!("{id}\t{name}\t{ip}");
    }

    if let Some(total) = res
        .get("metadata")
        .and_then(|m| m.get("totalCount"))
        .and_then(Value::as_u64)
    {
        println!("\n{} shown / {total} total", rows.len());
    }

    Ok(())
}

/// The three columns the human host table renders, each falling back to an
/// empty string when the field is absent or not a string.
fn host_fields(row: &Value) -> (&str, &str, &str) {
    let field = |key| row.get(key).and_then(Value::as_str).unwrap_or_default();
    (field("id"), field("name"), field("ipAddress"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn host_fields_extracts_present_columns() {
        let row = json!({"id": "host-1", "name": "web", "ipAddress": "10.0.0.1"});
        assert_eq!(host_fields(&row), ("host-1", "web", "10.0.0.1"));
    }

    #[test]
    fn host_fields_defaults_missing_or_wrong_type() {
        // Missing name, and an ipAddress that isn't a string.
        let row = json!({"id": "host-2", "ipAddress": 42});
        assert_eq!(host_fields(&row), ("host-2", "", ""));
    }
}
