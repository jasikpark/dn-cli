use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "dn", version, about = "CLI for the Defined Networking API")]
pub struct Cli {
    /// Output machine-readable JSON (including errors) instead of human tables
    #[arg(long, global = true)]
    pub json: bool,
    /// Profile to run as (see `dn auth list`); defaults to `DN_PROFILE`, then
    /// the default profile
    #[arg(long, global = true, value_name = "NAME")]
    pub profile: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Configure how `dn` finds your API key
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Inspect and manage Nebula hosts
    #[command(alias = "hosts")]
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    /// Inspect networks
    #[command(alias = "networks")]
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Inspect and delete firewall roles
    #[command(alias = "roles")]
    Role {
        #[command(subcommand)]
        command: RoleCommand,
    },
    /// Inspect and delete tags
    #[command(alias = "tags")]
    Tag {
        #[command(subcommand)]
        command: TagCommand,
    },
}

#[derive(Subcommand)]
pub enum NetworkCommand {
    /// List networks
    List,
}

#[derive(Subcommand)]
pub enum RoleCommand {
    /// List firewall roles
    List,
    /// Show one role and its inbound firewall rules
    Get(RoleGetArgs),
    /// Delete a role. Asks for confirmation unless --yes is passed.
    Delete(RoleDeleteArgs),
}

#[derive(Args)]
pub struct RoleGetArgs {
    /// Role id (role-…). Find ids with `dn role list`.
    pub role_id: String,
}

#[derive(Subcommand)]
pub enum TagCommand {
    /// List tags
    List,
    /// Show one tag and the inbound firewall rules it adds to its hosts
    Get(TagGetArgs),
    /// Delete a tag. Asks for confirmation unless --yes is passed.
    Delete(TagDeleteArgs),
}

#[derive(Args)]
pub struct TagGetArgs {
    /// Tag name in `key:value` form, e.g. `env:prod`
    pub tag: String,
}

#[derive(Args)]
pub struct RoleDeleteArgs {
    /// Role id (role-…). Find ids with `dn role list`.
    pub role_id: String,
    /// Skip the confirmation prompt (required when stdin is not a terminal or
    /// with --json)
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct TagDeleteArgs {
    /// Tag name in `key:value` form, e.g. `env:prod`
    pub tag: String,
    /// Skip the confirmation prompt (required when stdin is not a terminal or
    /// with --json)
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Store an API key for a profile and make it the default. The key goes
    /// in the OS keyring, or pass `--ref` to store a 1Password secret
    /// reference instead.
    Login(AuthLoginArgs),
    /// Show which profile and API key source a call would use (never prints
    /// the key)
    Status,
    /// List stored profiles
    List,
    /// Make a profile the default for calls that don't name one
    Switch(AuthSwitchArgs),
    /// Forget a profile (the one `--profile` names, else the default). If it
    /// was the default, another profile becomes the default.
    Logout(AuthLogoutArgs),
}

#[derive(Args)]
pub struct AuthSwitchArgs {
    /// Profile to make the default
    pub name: String,
}

#[derive(Args)]
pub struct AuthLogoutArgs {
    /// Forget every profile and remove the credentials file
    #[arg(long)]
    pub all: bool,
}

#[derive(Args)]
pub struct AuthLoginArgs {
    /// Store a 1Password secret reference instead of the key; every call
    /// then resolves it with `op read`
    #[arg(
        long = "ref",
        value_name = "op://vault/item/field",
        conflicts_with = "key_stdin"
    )]
    pub reference: Option<String>,
    /// Read the API key from stdin instead of prompting for it. A terminal
    /// on stdin still gets the hidden prompt
    #[arg(long)]
    pub key_stdin: bool,
    /// API server for this account, for testing against a mock or
    /// non-production API. Kept when omitted; a new profile uses
    /// https://api.defined.net. Plain http:// only to localhost.
    #[arg(long, value_name = "URL")]
    pub api_url: Option<String>,
    /// Don't make this profile the default (the first profile always is)
    #[arg(long)]
    pub keep_default: bool,
    /// Skip checking the key against the API before saving
    #[arg(long)]
    pub no_verify: bool,
}

#[derive(Subcommand)]
pub enum HostCommand {
    /// List hosts
    List,
    /// Search hosts by name, IP, role name, or tag (server-side, whole
    /// account). The query must be at least two characters.
    Search(HostSearchArgs),
    /// Create a host (or lighthouse / relay) and an enrollment code in one
    /// transaction. Prints the OTP to give to `dnclient enroll`.
    Create(HostCreateArgs),
    /// Edit a host — rename it, assign a role, or add/remove tags.
    Edit(HostEditArgs),
    /// Delete a host. Asks for confirmation unless --yes is passed.
    Delete(HostDeleteArgs),
}

/// Arguments for `dn host search`. Wraps the `filter.search` query on
/// `GET /v2/hosts` — a server-side match across a host's name, IPs, role
/// name, and tags.
#[derive(Args)]
pub struct HostSearchArgs {
    /// Search term (case-insensitive substring). At least two characters —
    /// the API rejects a shorter query. Multiple words are joined with a
    /// space, so `dn host search web server` searches for "web server".
    #[arg(required = true, num_args = 1.., value_name = "QUERY")]
    pub query: Vec<String>,
}

/// Arguments for `dn host create`. Mirrors the
/// `POST /v2/host-and-enrollment-code` request body, plus a `--network`
/// override for the auto-pick fallback.
///
/// Validation that's cheap client-side (lighthouse needs static address +
/// non-zero listen port; relay needs listen port; lighthouse-xor-relay) is
/// enforced before the request — the API enforces the same rules, but
/// catching them locally gives a clearer error than `ERR_INVALID_VALUE` from
/// 1500km away.
#[derive(Args)]
pub struct HostCreateArgs {
    /// Host name (1–255 chars)
    pub name: String,
    /// Network ID (see `dn network list`). Omit if the account has exactly
    /// one network — it's auto-picked, which is the common case at signup.
    #[arg(long)]
    pub network: Option<String>,
    /// Role ID to assign. Omit to use the account's default role (deny-all
    /// firewall — see post-create output).
    #[arg(long)]
    pub role: Option<String>,
    /// Mark this host as a lighthouse. Requires `--static-address` and
    /// `--listen-port`. Mutually exclusive with `--relay`.
    #[arg(long, conflicts_with = "relay")]
    pub lighthouse: bool,
    /// Mark this host as a relay. Requires `--listen-port`. Mutually
    /// exclusive with `--lighthouse`.
    #[arg(long)]
    pub relay: bool,
    /// IPv4 address to assign, or the network's IPv4 CIDR to have the server
    /// pick one inside it. When omitted, hosts on networks with an IPv4
    /// prefix still get an auto-assigned IPv4: the CLI sends that prefix,
    /// because the API otherwise leaves dual-stack hosts v6-only. See
    /// `--no-ipv4`.
    #[arg(long, conflicts_with = "no_ipv4")]
    pub ipv4: Option<String>,
    /// Skip the IPv4 auto-assign on a dual-stack network, creating a v6-only
    /// host. IPv4-only networks always assign an IPv4.
    #[arg(long)]
    pub no_ipv4: bool,
    /// IPv6 address to assign. The server auto-assigns one when omitted.
    #[arg(long)]
    pub ipv6: Option<String>,
    /// Static `ip:port` (or `hostname:port`) for lighthouses / relays.
    /// Repeatable. Required for lighthouses.
    #[arg(long = "static-address")]
    pub static_addresses: Vec<String>,
    /// UDP listen port. Required (non-zero) for lighthouses and relays.
    #[arg(long)]
    pub listen_port: Option<u16>,
    /// Tags in `key:value` form (key ≤20 chars, value ≤50, no whitespace).
    /// Repeatable, or comma-separated.
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,
    /// Lifetime of the enrollment code in seconds. API default is 86400
    /// (24h).
    #[arg(long)]
    pub code_lifetime: Option<u64>,
}

#[derive(Args)]
pub struct HostEditArgs {
    /// Host id (host-…)
    pub host_id: String,
    /// Rename the host.
    #[arg(long)]
    pub name: Option<String>,
    /// Assign a firewall role (role-…). Find ids with `dn role list`.
    #[arg(long, value_name = "ROLE_ID", conflicts_with = "clear_role")]
    pub role: Option<String>,
    /// Unassign the host's role (sends `roleID: null`). Mutually exclusive
    /// with `--role`.
    #[arg(long)]
    pub clear_role: bool,
    /// Add a tag (key:value). Repeatable.
    #[arg(long, value_name = "TAG")]
    pub add_tag: Vec<String>,
    /// Remove a tag (exact key:value match). Repeatable.
    #[arg(long, value_name = "TAG")]
    pub remove_tag: Vec<String>,
}

#[derive(Args)]
pub struct HostDeleteArgs {
    /// Host id (host-…)
    pub host_id: String,
    /// Skip the confirmation prompt (required when stdin is not a terminal or
    /// with --json)
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::hosts::validate_edit_preflight;

    #[test]
    fn parses_hosts_delete_with_short_yes() {
        let cli = Cli::try_parse_from(["dn", "host", "delete", "host-1", "-y"]).unwrap();
        let Command::Host {
            command: HostCommand::Delete(args),
        } = cli.command
        else {
            panic!("expected `host delete` to parse into HostCommand::Delete");
        };
        assert_eq!(args.host_id, "host-1");
        assert!(args.yes);
    }

    #[test]
    fn parses_role_delete_with_long_yes() {
        let cli = Cli::try_parse_from(["dn", "roles", "delete", "role-1", "--yes"]).unwrap();
        let Command::Role {
            command: RoleCommand::Delete(args),
        } = cli.command
        else {
            panic!("expected `role delete` to parse into RoleCommand::Delete");
        };
        assert_eq!(args.role_id, "role-1");
        assert!(args.yes);
    }

    #[test]
    fn parses_tag_delete_without_yes() {
        let cli = Cli::try_parse_from(["dn", "tag", "delete", "env:prod"]).unwrap();
        let Command::Tag {
            command: TagCommand::Delete(args),
        } = cli.command
        else {
            panic!("expected `tag delete` to parse into TagCommand::Delete");
        };
        assert_eq!(args.tag, "env:prod");
        assert!(!args.yes);
    }

    #[test]
    fn parses_hosts_create_with_positional_name() {
        let cli = Cli::try_parse_from(["dn", "host", "create", "my-laptop"]).unwrap();
        let Command::Host {
            command: HostCommand::Create(args),
        } = cli.command
        else {
            panic!("expected `host create` to parse into HostCommand::Create");
        };
        assert_eq!(args.name, "my-laptop");
    }

    #[test]
    fn parses_hosts_search_with_a_single_word_query() {
        let cli = Cli::try_parse_from(["dn", "host", "search", "laptop"]).unwrap();
        let Command::Host {
            command: HostCommand::Search(args),
        } = cli.command
        else {
            panic!("expected `host search` to parse into HostCommand::Search");
        };
        assert_eq!(args.query, vec!["laptop".to_string()]);
    }

    #[test]
    fn hosts_search_requires_at_least_one_query_word() {
        // No positional at all is a parse error (the arg is `required`).
        assert!(Cli::try_parse_from(["dn", "host", "search"]).is_err());
    }

    #[test]
    fn parses_hosts_edit_with_add_and_remove_tags() {
        let cli = Cli::try_parse_from([
            "dn",
            "hosts",
            "edit",
            "host-1",
            "--add-tag",
            "dns:cloudflare",
            "--remove-tag",
            "old:stale",
        ])
        .unwrap();
        let Command::Host {
            command: HostCommand::Edit(args),
        } = cli.command
        else {
            panic!("expected `host edit` to parse into HostCommand::Edit");
        };
        assert_eq!(args.host_id, "host-1");
        assert_eq!(args.add_tag, vec!["dns:cloudflare"]);
        assert_eq!(args.remove_tag, vec!["old:stale"]);
    }

    #[test]
    fn parses_hosts_edit_repeated_tags() {
        let cli = Cli::try_parse_from([
            "dn",
            "hosts",
            "edit",
            "host-1",
            "--add-tag",
            "a:1",
            "--add-tag",
            "b:2",
        ])
        .unwrap();
        let Command::Host {
            command: HostCommand::Edit(args),
        } = cli.command
        else {
            panic!("expected repeated add-tag to collect");
        };
        assert_eq!(args.add_tag, vec!["a:1", "b:2"]);
    }

    #[test]
    fn parses_hosts_edit_with_role() {
        let cli =
            Cli::try_parse_from(["dn", "host", "edit", "host-1", "--role", "role-abc"]).unwrap();
        let Command::Host {
            command: HostCommand::Edit(args),
        } = cli.command
        else {
            panic!("expected `host edit --role` to parse into HostCommand::Edit");
        };
        assert_eq!(args.role.as_deref(), Some("role-abc"));
        assert!(validate_edit_preflight(&args).is_ok());
    }

    #[test]
    fn parses_hosts_edit_with_clear_role() {
        let cli = Cli::try_parse_from(["dn", "host", "edit", "host-1", "--clear-role"]).unwrap();
        let Command::Host {
            command: HostCommand::Edit(args),
        } = cli.command
        else {
            panic!("expected `host edit --clear-role` to parse into HostCommand::Edit");
        };
        assert!(args.clear_role);
        assert!(args.role.is_none());
        assert!(validate_edit_preflight(&args).is_ok());
    }

    #[test]
    fn role_and_clear_role_conflict() {
        let kind = Cli::try_parse_from([
            "dn",
            "hosts",
            "edit",
            "host-1",
            "--role",
            "role-a",
            "--clear-role",
        ])
        .err()
        .map(|e| e.kind());
        assert_eq!(kind, Some(clap::error::ErrorKind::ArgumentConflict));
    }

    #[test]
    fn parses_roles_get() {
        let cli = Cli::try_parse_from(["dn", "role", "get", "role-ABC"]).unwrap();
        let Command::Role {
            command: RoleCommand::Get(args),
        } = cli.command
        else {
            panic!("expected role get");
        };
        assert_eq!(args.role_id, "role-ABC");
    }

    #[test]
    fn parses_tags_get() {
        let cli = Cli::try_parse_from(["dn", "tag", "get", "env:prod"]).unwrap();
        let Command::Tag {
            command: TagCommand::Get(args),
        } = cli.command
        else {
            panic!("expected tag get");
        };
        assert_eq!(args.tag, "env:prod");
    }

    #[test]
    fn plural_command_names_still_parse() {
        // The old plural names stay as aliases so existing scripts keep working.
        let cli = Cli::try_parse_from(["dn", "hosts", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Host {
                command: HostCommand::List
            }
        ));
        let cli = Cli::try_parse_from(["dn", "networks", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Network {
                command: NetworkCommand::List
            }
        ));
        let cli = Cli::try_parse_from(["dn", "roles", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Role {
                command: RoleCommand::List
            }
        ));
        let cli = Cli::try_parse_from(["dn", "tags", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Tag {
                command: TagCommand::List
            }
        ));
        let cli = Cli::try_parse_from(["dn", "tags", "get", "env:prod"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Tag {
                command: TagCommand::Get(_)
            }
        ));
    }
}
