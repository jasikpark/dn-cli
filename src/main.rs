mod api;
mod cli;
mod commands;
mod config;
mod error;
mod ids;
mod keystore;
mod output;

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::bail;
use clap::Parser;

use crate::api::Client;
use crate::cli::{
    AuditLogCommand, AuthCommand, Cli, Command, HostCommand, NetworkCommand, RoleCommand,
    TagCommand,
};
use crate::commands::{
    audit_log::audit_log_list,
    auth::{
        KEY_STDIN_NEEDS_PIPE, LOGIN_NEEDS_KEY, auth_list, auth_login, auth_logout, auth_status,
        auth_switch, validate_api_url,
    },
    delete::{DELETE_NEEDS_YES, DeleteConfirmation, delete_confirmation},
    firewall::{roles_delete, roles_get, roles_list, tags_delete, tags_get, tags_list},
    hosts::{
        hosts_create, hosts_delete, hosts_edit, hosts_get, hosts_list, hosts_search, parse_tag,
        validate_create_preflight, validate_edit_preflight, validate_search_preflight,
    },
    networks::{networks_delete, networks_get, networks_list},
};
use crate::config::{
    Config, Migration, migrate_to_profiles, normalize_op_ref, validate_op_ref,
    validate_profile_name,
};
use crate::error::{InvalidArgument, json_requested, report_error, report_usage_error};
use crate::ids::validate_id;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => report_usage_error(err, json_requested(std::env::args_os())),
    };
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            report_error(&err, cli.json);
            ExitCode::FAILURE
        }
    }
}

/// Say once what [`migrate_to_profiles`] did, on stderr only so `--json`
/// output never changes. A failed rewrite is a warning, never an error.
fn report_migration(migration: Migration) {
    if !migration.notes.is_empty() {
        eprintln!("migrated credentials: {}", migration.notes.join("; "));
    }
    for warning in migration.warnings {
        eprintln!("warning: {warning}");
    }
}

fn preflight(cli: &Cli) -> anyhow::Result<()> {
    if let Some(profile) = &cli.profile {
        validate_profile_name(profile)?;
    }
    // Run all client-side validation before resolving credentials or touching
    // the network, so `dn host create --lighthouse` (missing required flags)
    // reports the actual problem instead of hiding behind a credentials error.
    match &cli.command {
        Command::Host { command } => match command {
            HostCommand::Create(args) => validate_create_preflight(args)?,
            HostCommand::Edit(args) => validate_edit_preflight(args)?,
            HostCommand::Search(args) => validate_search_preflight(args)?,
            HostCommand::Delete(args) => {
                validate_id("host", &args.host_id)?;
                preflight_delete(args.yes, cli.json)?;
            }
            HostCommand::Get(args) => validate_id("host", &args.host_id)?,
            HostCommand::List(_) => {}
        },
        Command::Role {
            command: RoleCommand::Get(args),
        } => validate_id("role", args.role_id.trim())?,
        Command::Role {
            command: RoleCommand::Delete(args),
        } => {
            validate_id("role", args.role_id.trim())?;
            preflight_delete(args.yes, cli.json)?;
        }
        Command::Network {
            command: NetworkCommand::Get(args),
        } => validate_id("network", args.network_id.trim())?,
        Command::Network {
            command: NetworkCommand::Delete(args),
        } => {
            validate_id("network", args.network_id.trim())?;
            preflight_delete(args.yes, cli.json)?;
        }
        Command::Tag {
            command: TagCommand::Get(args),
        } => {
            parse_tag(args.tag.trim())?;
        }
        Command::Tag {
            command: TagCommand::Delete(args),
        } => {
            parse_tag(args.tag.trim())?;
            preflight_delete(args.yes, cli.json)?;
        }
        Command::Auth {
            command: AuthCommand::Switch(args),
        } => validate_profile_name(&args.name)?,
        Command::Auth {
            command: AuthCommand::Login(args),
        } => {
            if let Some(url) = &args.api_url {
                validate_api_url(url)?;
            }
            match &args.reference {
                Some(reference) => validate_op_ref(&normalize_op_ref(reference))?,
                None if args.key_stdin && cli.json && std::io::stdin().is_terminal() => {
                    bail!(KEY_STDIN_NEEDS_PIPE)
                }
                None if args.key_stdin => {}
                None if cli.json || !std::io::stdin().is_terminal() => bail!(LOGIN_NEEDS_KEY),
                None => {}
            }
        }
        _ => {}
    }
    Ok(())
}

/// Refuse a delete that has nobody to confirm it and no `--yes`, before
/// credentials are resolved.
fn preflight_delete(yes: bool, json: bool) -> anyhow::Result<()> {
    if delete_confirmation(yes, json, std::io::stdin().is_terminal()) == DeleteConfirmation::Refuse
    {
        bail!(DELETE_NEEDS_YES);
    }
    Ok(())
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    report_migration(migrate_to_profiles());
    preflight(cli).map_err(InvalidArgument)?;

    match &cli.command {
        Command::Auth { command } => match command {
            AuthCommand::Login(args) => auth_login(args, cli.profile.as_deref(), cli.json)?,
            AuthCommand::Status => auth_status(cli.profile.as_deref(), cli.json)?,
            AuthCommand::List => auth_list(cli.json)?,
            AuthCommand::Switch(args) => auth_switch(args, cli.json)?,
            AuthCommand::Logout(args) => auth_logout(args, cli.profile.as_deref(), cli.json)?,
        },
        Command::Host { command } => {
            let client = api_client(cli)?;
            match command {
                HostCommand::List(page) => hosts_list(&client, page, cli.json)?,
                HostCommand::Get(args) => hosts_get(&client, args, cli.json)?,
                HostCommand::Search(args) => hosts_search(&client, args, cli.json)?,
                HostCommand::Create(args) => hosts_create(&client, args, cli.json)?,
                HostCommand::Edit(args) => hosts_edit(&client, args, cli.json)?,
                HostCommand::Delete(args) => hosts_delete(&client, args, cli.json)?,
            }
        }
        Command::Network { command } => match command {
            NetworkCommand::List(page) => networks_list(&api_client(cli)?, page, cli.json)?,
            NetworkCommand::Get(args) => networks_get(&api_client(cli)?, args, cli.json)?,
            NetworkCommand::Delete(args) => networks_delete(&api_client(cli)?, args, cli.json)?,
        },
        Command::Role { command } => match command {
            RoleCommand::List(page) => roles_list(&api_client(cli)?, page, cli.json)?,
            RoleCommand::Get(args) => roles_get(&api_client(cli)?, args, cli.json)?,
            RoleCommand::Delete(args) => roles_delete(&api_client(cli)?, args, cli.json)?,
        },
        Command::Tag { command } => match command {
            TagCommand::List(page) => tags_list(&api_client(cli)?, page, cli.json)?,
            TagCommand::Get(args) => tags_get(&api_client(cli)?, args, cli.json)?,
            TagCommand::Delete(args) => tags_delete(&api_client(cli)?, args, cli.json)?,
        },
        Command::AuditLog { command } => match command {
            AuditLogCommand::List(args) => audit_log_list(&api_client(cli)?, args, cli.json)?,
        },
    }

    Ok(())
}

/// The API client for this call. In human mode, a stderr note says when the
/// call isn't going to the production API, so staging or mock data is never
/// mistaken for the real thing.
fn api_client(cli: &Cli) -> anyhow::Result<Client> {
    let config = Config::load(cli.profile.as_deref())?;
    if !cli.json
        && let Some(note) = config.non_default_url_note()
    {
        eprintln!("{note}");
    }
    Ok(Client::new(config))
}
