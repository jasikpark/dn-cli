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
    RouteCommand, TagCommand,
};
use crate::commands::{
    audit_log::audit_log_list,
    auth::{
        KEY_STDIN_NEEDS_PIPE, LOGIN_NEEDS_KEY, auth_list, auth_login, auth_logout, auth_status,
        auth_switch, validate_api_url,
    },
    delete::{DELETE_NEEDS_YES, DeleteConfirmation, delete_confirmation},
    firewall::{roles_delete, roles_get, roles_list, tags_delete, tags_get, tags_list},
    firewall_edit::{
        roles_create, roles_edit, tags_create, tags_edit, validate_role_create_preflight,
        validate_role_edit_preflight, validate_tag_create_preflight, validate_tag_edit_preflight,
    },
    hosts::{
        hosts_block, hosts_create, hosts_delete, hosts_edit, hosts_enroll_code, hosts_get,
        hosts_list, hosts_search, hosts_unblock, parse_tag, validate_create_preflight,
        validate_edit_preflight, validate_list_preflight, validate_search_preflight,
    },
    networks::{networks_delete, networks_get, networks_list},
    routes::{routes_get, routes_list},
};
use crate::config::{
    Config, Migration, migrate_to_profiles, normalize_op_ref, validate_op_ref,
    validate_profile_name,
};
use crate::error::{InvalidArgument, json_requested, report_error, report_usage_error};
use crate::ids::validate_id;
use crate::output::OutputMode;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => report_usage_error(
            err,
            OutputMode::from_flag(json_requested(std::env::args_os())),
        ),
    };
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            report_error(&err, cli.output_mode());
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
    let output = cli.output_mode();
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
                preflight_delete(args.yes, output)?;
            }
            HostCommand::Get(args) | HostCommand::Block(args) | HostCommand::Unblock(args) => {
                validate_id("host", &args.host_id)?;
            }
            HostCommand::EnrollCode(args) => validate_id("host", &args.host_id)?,
            HostCommand::List(args) => validate_list_preflight(args)?,
        },
        Command::Role {
            command: RoleCommand::Get(args),
        } => validate_id("role", args.role_id.trim())?,
        Command::Role {
            command: RoleCommand::Delete(args),
        } => {
            validate_id("role", args.role_id.trim())?;
            preflight_delete(args.yes, output)?;
        }
        Command::Role {
            command: RoleCommand::Create(args),
        } => validate_role_create_preflight(args)?,
        Command::Role {
            command: RoleCommand::Edit(args),
        } => validate_role_edit_preflight(args)?,
        Command::Tag {
            command: TagCommand::Create(args),
        } => validate_tag_create_preflight(args)?,
        Command::Tag {
            command: TagCommand::Edit(args),
        } => validate_tag_edit_preflight(args)?,
        Command::Network {
            command: NetworkCommand::Get(args),
        } => validate_id("network", args.network_id.trim())?,
        Command::Route {
            command: RouteCommand::Get(args),
        } => validate_id("route", args.route_id.trim())?,
        Command::Network {
            command: NetworkCommand::Delete(args),
        } => {
            validate_id("network", args.network_id.trim())?;
            preflight_delete(args.yes, output)?;
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
            preflight_delete(args.yes, output)?;
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
            let stdin_is_tty = std::io::stdin().is_terminal();
            match (&args.reference, output, stdin_is_tty) {
                (Some(reference), _, _) => validate_op_ref(&normalize_op_ref(reference))?,
                // `--key-stdin` under `--json` is an agent run: a terminal on
                // stdin means nothing was piped in.
                (None, OutputMode::Json, true) if args.key_stdin => bail!(KEY_STDIN_NEEDS_PIPE),
                (None, _, _) if args.key_stdin => {}
                // Nobody to prompt for the key.
                (None, OutputMode::Json, _) | (None, OutputMode::Human, false) => {
                    bail!(LOGIN_NEEDS_KEY)
                }
                (None, OutputMode::Human, true) => {}
            }
        }
        _ => {}
    }
    Ok(())
}

/// Refuse a delete that has nobody to confirm it and no `--yes`, before
/// credentials are resolved.
fn preflight_delete(yes: bool, output: OutputMode) -> anyhow::Result<()> {
    if delete_confirmation(yes, output, std::io::stdin().is_terminal())
        == DeleteConfirmation::Refuse
    {
        bail!(DELETE_NEEDS_YES);
    }
    Ok(())
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    let output = cli.output_mode();
    report_migration(migrate_to_profiles());
    preflight(cli).map_err(InvalidArgument)?;

    match &cli.command {
        Command::Auth { command } => match command {
            AuthCommand::Login(args) => auth_login(args, cli.profile.as_deref(), output)?,
            AuthCommand::Status(args) => auth_status(args, cli.profile.as_deref(), output)?,
            AuthCommand::List => auth_list(output)?,
            AuthCommand::Switch(args) => auth_switch(args, output)?,
            AuthCommand::Logout(args) => auth_logout(args, cli.profile.as_deref(), output)?,
        },
        Command::Host { command } => {
            let client = api_client(cli)?;
            match command {
                HostCommand::List(args) => hosts_list(&client, args, output)?,
                HostCommand::Get(args) => hosts_get(&client, args, output)?,
                HostCommand::Search(args) => hosts_search(&client, args, output)?,
                HostCommand::Create(args) => hosts_create(&client, args, output)?,
                HostCommand::Edit(args) => hosts_edit(&client, args, output)?,
                HostCommand::Delete(args) => hosts_delete(&client, args, output)?,
                HostCommand::Block(args) => hosts_block(&client, args, output)?,
                HostCommand::Unblock(args) => hosts_unblock(&client, args, output)?,
                HostCommand::EnrollCode(args) => hosts_enroll_code(&client, args, output)?,
            }
        }
        Command::Network { command } => match command {
            NetworkCommand::List(page) => networks_list(&api_client(cli)?, page, output)?,
            NetworkCommand::Get(args) => networks_get(&api_client(cli)?, args, output)?,
            NetworkCommand::Delete(args) => networks_delete(&api_client(cli)?, args, output)?,
        },
        Command::Route { command } => match command {
            RouteCommand::List(page) => routes_list(&api_client(cli)?, page, output)?,
            RouteCommand::Get(args) => routes_get(&api_client(cli)?, args, output)?,
        },
        Command::Role { command } => match command {
            RoleCommand::List(page) => roles_list(&api_client(cli)?, page, output)?,
            RoleCommand::Get(args) => roles_get(&api_client(cli)?, args, output)?,
            RoleCommand::Create(args) => roles_create(&api_client(cli)?, args, output)?,
            RoleCommand::Edit(args) => roles_edit(&api_client(cli)?, args, output)?,
            RoleCommand::Delete(args) => roles_delete(&api_client(cli)?, args, output)?,
        },
        Command::Tag { command } => match command {
            TagCommand::List(page) => tags_list(&api_client(cli)?, page, output)?,
            TagCommand::Get(args) => tags_get(&api_client(cli)?, args, output)?,
            TagCommand::Create(args) => tags_create(&api_client(cli)?, args, output)?,
            TagCommand::Edit(args) => tags_edit(&api_client(cli)?, args, output)?,
            TagCommand::Delete(args) => tags_delete(&api_client(cli)?, args, output)?,
        },
        Command::AuditLog { command } => match command {
            AuditLogCommand::List(args) => audit_log_list(&api_client(cli)?, args, output)?,
        },
    }

    Ok(())
}

/// The API client for this call. In human mode, a stderr note says when the
/// call isn't going to the production API, so staging or mock data is never
/// mistaken for the real thing.
fn api_client(cli: &Cli) -> anyhow::Result<Client> {
    let config = Config::load(cli.profile.as_deref())?;
    if cli.output_mode() == OutputMode::Human
        && let Some(note) = config.non_default_url_note()
    {
        eprintln!("{note}");
    }
    Ok(Client::new(config))
}
