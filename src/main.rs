mod api;
mod config;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::Value;

use crate::api::Client;
use crate::config::Config;

#[derive(Parser)]
#[command(
    name = "dn",
    version,
    about = "Personal clean-room CLI for the Defined Networking API"
)]
struct Cli {
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
    List {
        /// Output raw JSON instead of a table
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new(Config::from_env()?);

    match cli.command {
        Command::Hosts { command } => match command {
            HostsCommand::List { json } => hosts_list(&client, json)?,
        },
    }

    Ok(())
}

fn hosts_list(client: &Client, json: bool) -> Result<()> {
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
        let id = row.get("id").and_then(Value::as_str).unwrap_or_default();
        let name = row.get("name").and_then(Value::as_str).unwrap_or_default();
        let ip = row
            .get("ipAddress")
            .and_then(Value::as_str)
            .unwrap_or_default();
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
