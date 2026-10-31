use clap::{Args, Parser, Subcommand};

use crate::api::MAX_PAGE_SIZE;
use crate::commands::rules::RULE_SPEC_HELP;
use crate::output::OutputMode;

/// Links shown at the end of `dn --help`: the API reference the commands wrap
/// and its OpenAPI spec, for anyone generating a client or checking a field.
const API_DOCS_HELP: &str = "\
API reference: https://www.defined.net/docs/api/
OpenAPI spec:  https://www.defined.net/docs/openapi.yaml";

#[derive(Parser)]
#[command(
    name = "dn",
    version,
    about = "CLI for the Defined Networking API",
    after_help = API_DOCS_HELP
)]
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

impl Cli {
    /// The output mode `--json` selected.
    pub fn output_mode(&self) -> OutputMode {
        OutputMode::from_flag(self.json)
    }
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
    /// Inspect and delete networks
    #[command(alias = "networks")]
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Inspect routes: the IPv4 ranges a router host forwards for
    #[command(alias = "routes")]
    Route {
        #[command(subcommand)]
        command: RouteCommand,
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
    /// Read the account's audit log: who changed what, and when
    #[command(alias = "audit-logs")]
    AuditLog {
        #[command(subcommand)]
        command: AuditLogCommand,
    },
}

#[derive(Subcommand)]
pub enum AuditLogCommand {
    /// List audit log entries, newest first
    List(AuditLogListArgs),
}

#[derive(Args)]
pub struct AuditLogListArgs {
    #[command(flatten)]
    pub page: PageArgs,
    /// Only entries about this resource, by id (e.g. host-…, role-…)
    #[arg(long, value_name = "ID", value_parser = non_blank)]
    pub target: Option<String>,
    /// Only entries about this kind of resource, e.g. host, role, network,
    /// apiKey, user, ca, oidcProvider
    #[arg(long, value_name = "TYPE", value_parser = non_blank)]
    pub target_type: Option<String>,
}

/// Which page of a list to fetch. Lists return one page at a time; the
/// human view prints the next and previous cursors on stderr, `--json`
/// carries them in `metadata`.
#[derive(Args, Clone, Debug, Default)]
pub struct PageArgs {
    /// Fetch the page this cursor points at (a `nextCursor` or `prevCursor`
    /// from an earlier call with the same filters)
    #[arg(
        long,
        value_parser = non_blank,
        allow_hyphen_values = true,
        overrides_with = "cursor"
    )]
    pub cursor: Option<String>,
    /// How many items to fetch, at most 500 per call; `--cursor` continues
    /// past them
    #[arg(
        long,
        visible_alias = "page-size",
        default_value_t = MAX_PAGE_SIZE,
        value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_PAGE_SIZE))
    )]
    pub limit: u32,
}

/// A flag value trimmed of surrounding whitespace, refusing one with nothing
/// left: an empty filter or cursor would quietly widen the request instead of
/// narrowing it.
fn non_blank(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("must not be blank".to_string());
    }
    Ok(s.to_string())
}

#[derive(Subcommand)]
pub enum NetworkCommand {
    /// List networks
    List(PageArgs),
    /// Show one network: its address ranges, host count, and lighthouse
    /// settings
    Get(NetworkGetArgs),
    /// Delete a network. It must have no hosts left. Asks for confirmation
    /// unless --yes is passed.
    Delete(NetworkDeleteArgs),
}

#[derive(Args)]
pub struct NetworkGetArgs {
    /// Network id (network-…). Find ids with `dn network list`.
    pub network_id: String,
}

#[derive(Args)]
pub struct NetworkDeleteArgs {
    /// Network id (network-…). Find ids with `dn network list`.
    pub network_id: String,
    /// Skip the confirmation prompt (required when stdin is not a terminal or
    /// with --json)
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Subcommand)]
pub enum RouteCommand {
    /// List routes
    List(PageArgs),
    /// Show one route: its router host, routable ranges, and the inbound
    /// rules the router accepts for them
    Get(RouteGetArgs),
}

#[derive(Args)]
pub struct RouteGetArgs {
    /// Route id (route-…). Find ids with `dn route list`.
    pub route_id: String,
}

#[derive(Subcommand)]
pub enum RoleCommand {
    /// List firewall roles
    List(PageArgs),
    /// Show one role and its inbound firewall rules
    Get(RoleGetArgs),
    /// Create a role with a description and inbound firewall rules
    Create(RoleCreateArgs),
    /// Edit a role's description or firewall rules. Roles can't be renamed.
    Edit(RoleEditArgs),
    /// Delete a role. Asks for confirmation unless --yes is passed.
    Delete(RoleDeleteArgs),
}

#[derive(Args)]
pub struct RoleGetArgs {
    /// Role id (role-…). Find ids with `dn role list`.
    pub role_id: String,
}

/// Arguments for `dn role create`: the `POST /v1/roles` body.
#[derive(Args)]
pub struct RoleCreateArgs {
    /// Role name (1–50 characters)
    pub name: String,
    /// Description (up to 255 characters)
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
    /// An inbound firewall rule. Repeatable. With none, the role allows no
    /// inbound traffic.
    #[arg(long = "rule", value_name = "RULE", long_help = RULE_SPEC_HELP)]
    pub rules: Vec<String>,
}

/// Arguments for `dn role edit`. The API's role update replaces the whole
/// role, so `dn` reads it first and writes back the current values with
/// these changes applied.
#[derive(Args)]
pub struct RoleEditArgs {
    /// Role id (role-…). Find ids with `dn role list`.
    pub role_id: String,
    /// Replace the description (`--description ""` clears it)
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
    #[command(flatten)]
    pub rules: RuleEditArgs,
}

/// Firewall rule edits shared by `role edit` and `tag edit`. Removes run
/// before adds, and `--clear-rules --add-rule …` replaces the whole list.
#[derive(Args, Clone, Debug, Default)]
pub struct RuleEditArgs {
    /// Add an inbound firewall rule, or update the description of one that
    /// already allows the same traffic. Repeatable.
    #[arg(long, value_name = "RULE", long_help = RULE_SPEC_HELP)]
    pub add_rule: Vec<String>,
    /// Remove every rule allowing the same traffic as this spec (its
    /// description doesn't matter). Repeatable.
    #[arg(long, value_name = "RULE", conflicts_with = "clear_rules")]
    pub remove_rule: Vec<String>,
    /// Remove every rule, before any --add-rule is applied
    #[arg(long)]
    pub clear_rules: bool,
}

#[derive(Subcommand)]
pub enum TagCommand {
    /// List tags
    List(PageArgs),
    /// Show one tag and the inbound firewall rules it adds to its hosts
    Get(TagGetArgs),
    /// Create a tag, with optional firewall rules, route subscriptions, and
    /// a position in the priority order
    Create(TagCreateArgs),
    /// Edit a tag's description, firewall rules, route subscriptions, or
    /// priority. Config overrides are left as they are.
    Edit(TagEditArgs),
    /// Delete a tag. Asks for confirmation unless --yes is passed.
    Delete(TagDeleteArgs),
}

#[derive(Args)]
pub struct TagGetArgs {
    /// Tag name in `key:value` form, e.g. `env:prod`
    pub tag: String,
}

/// Arguments for `dn tag create`: the `POST /v1/tags` body.
#[derive(Args)]
pub struct TagCreateArgs {
    /// Tag name in `key:value` form (key ≤20 chars, value ≤50, no
    /// whitespace around either)
    pub tag: String,
    /// Description (up to 255 characters)
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
    /// An inbound firewall rule added to every host carrying the tag.
    /// Repeatable.
    #[arg(long = "rule", value_name = "RULE", long_help = RULE_SPEC_HELP)]
    pub rules: Vec<String>,
    /// A route (route-…) every host carrying the tag subscribes to.
    /// Repeatable.
    #[arg(long = "route", value_name = "ROUTE_ID")]
    pub routes: Vec<String>,
    /// Place the tag just before this one in the priority order (lower
    /// precedence than it). Mutually exclusive with --after.
    #[arg(long, value_name = "TAG", conflicts_with = "after")]
    pub before: Option<String>,
    /// Place the tag just after this one in the priority order (higher
    /// precedence than it)
    #[arg(long, value_name = "TAG")]
    pub after: Option<String>,
}

/// Arguments for `dn tag edit`. Tags have a partial update, so only the
/// fields that change are sent; config overrides are never touched.
#[derive(Args)]
pub struct TagEditArgs {
    /// Tag name in `key:value` form, e.g. `env:prod`
    pub tag: String,
    /// Replace the description (`--description ""` clears it)
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
    #[command(flatten)]
    pub rules: RuleEditArgs,
    /// Subscribe the tag's hosts to a route (route-…). Repeatable.
    #[arg(long, value_name = "ROUTE_ID")]
    pub add_route: Vec<String>,
    /// Unsubscribe from a route. Repeatable.
    #[arg(long, value_name = "ROUTE_ID", conflicts_with = "clear_routes")]
    pub remove_route: Vec<String>,
    /// Unsubscribe from every route, before any --add-route is applied
    #[arg(long)]
    pub clear_routes: bool,
    /// Move the tag just before this one in the priority order. Mutually
    /// exclusive with --after.
    #[arg(long, value_name = "TAG", conflicts_with = "after")]
    pub before: Option<String>,
    /// Move the tag just after this one in the priority order
    #[arg(long, value_name = "TAG")]
    pub after: Option<String>,
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
    /// Show which profile and API key source a call would use, and the
    /// organization and key the API says it belongs to (never prints the key)
    Status(AuthStatusArgs),
    /// List stored profiles
    List,
    /// Make a profile the default for calls that don't name one
    Switch(AuthSwitchArgs),
    /// Forget a profile (the one `--profile` names, else the default). If it
    /// was the default, another profile becomes the default.
    Logout(AuthLogoutArgs),
}

#[derive(Args)]
pub struct AuthStatusArgs {
    /// Report only the local configuration, without asking the API who the
    /// key belongs to. Never resolves a 1Password reference.
    #[arg(long)]
    pub offline: bool,
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
    /// List hosts, optionally narrowed by role, network, tag, kind, or
    /// client state. Every filter is applied server-side.
    List(HostListArgs),
    /// Show one host: its addresses, role, tags, and when it was last seen
    Get(HostGetArgs),
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
    /// Block a host: it stays in the account but can't reach, or be reached
    /// by, other hosts until it is unblocked.
    Block(HostGetArgs),
    /// Unblock a host so it can rejoin the network.
    Unblock(HostGetArgs),
    /// Issue a new enrollment code for an existing host, e.g. to re-enroll
    /// it after a reinstall. Prints the code to give to `dnclient enroll`.
    EnrollCode(HostEnrollCodeArgs),
}

#[derive(Args)]
pub struct HostEnrollCodeArgs {
    /// Host id (host-…). Find ids with `dn host list` or `dn host search`.
    pub host_id: String,
    /// How long the code stays valid, in seconds: 60 to 604800 (7 days).
    /// The API default is 86400 (24h).
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(60..=604_800))]
    pub code_lifetime: Option<u64>,
}

/// Arguments for `dn host list`: the `filter.*` query parameters of
/// `GET /v2/hosts` plus paging.
#[derive(Args, Default)]
pub struct HostListArgs {
    #[command(flatten)]
    pub filters: HostFilterArgs,
    #[command(flatten)]
    pub page: PageArgs,
}

/// The server-side filters `GET /v2/hosts` accepts, shared by `host list`
/// and `host search` so a search can be narrowed the same way. Each flag maps
/// to one `filter.*` query parameter; combining flags ANDs them.
///
/// The boolean flags take an optional value, so `--lighthouse` keeps only
/// lighthouses and `--lighthouse=false` keeps only non-lighthouses; leaving a
/// flag off means "don't filter on it".
#[derive(Args, Clone, Debug, Default)]
pub struct HostFilterArgs {
    /// Only hosts assigned this role (role-…). `any` keeps hosts that have
    /// a role, `null` hosts that have none.
    #[arg(long, value_name = "ROLE_ID|any|null", value_parser = non_blank)]
    pub role: Option<String>,
    /// Only hosts on this network (network-…)
    #[arg(long, value_name = "NETWORK_ID", value_parser = non_blank)]
    pub network: Option<String>,
    /// Only hosts carrying this tag (key:value). Repeatable; a host must
    /// have every tag given.
    #[arg(long, value_name = "TAG", value_parser = non_blank)]
    pub tag: Vec<String>,
    /// Only lighthouses; `--lighthouse=false` for everything but
    #[arg(long, value_name = "BOOL", num_args = 0..=1, default_missing_value = "true")]
    pub lighthouse: Option<bool>,
    /// Only relays; `--relay=false` for everything but
    #[arg(long, value_name = "BOOL", num_args = 0..=1, default_missing_value = "true")]
    pub relay: Option<bool>,
    /// Only blocked hosts; `--blocked=false` for unblocked ones
    #[arg(long, value_name = "BOOL", num_args = 0..=1, default_missing_value = "true")]
    pub blocked: Option<bool>,
    /// Only hosts with a client update available;
    /// `--update-available=false` for up-to-date ones
    #[arg(long, value_name = "BOOL", num_args = 0..=1, default_missing_value = "true")]
    pub update_available: Option<bool>,
    /// Only hosts whose client reports this platform, named as the API
    /// reports it in `metadata.platform` (for example mobile, dnclient,
    /// dnclient-desktop). `null` keeps hosts that have never reported one.
    #[arg(long, value_name = "PLATFORM", value_parser = non_blank)]
    pub platform: Option<String>,
    /// Only hosts that have never connected to Defined Networking
    #[arg(long)]
    pub never_seen: bool,
    /// Only hosts enrolled by this endpoint OIDC user (eoidcuser-…).
    /// `any` keeps hosts that have one, `null` hosts that have none.
    #[arg(long, value_name = "USER_ID|any|null", value_parser = non_blank)]
    pub oidc_user: Option<String>,
}

/// Arguments for `dn host search`. Wraps the `filter.search` query on
/// `GET /v2/hosts` — a server-side match across a host's name, IPs, role
/// name, and tags — plus the same filters as `host list`.
#[derive(Args)]
pub struct HostSearchArgs {
    /// Search term (case-insensitive substring). At least two characters —
    /// the API rejects a shorter query. Multiple words are joined with a
    /// space, so `dn host search web server` searches for "web server".
    #[arg(required = true, num_args = 1.., value_name = "QUERY")]
    pub query: Vec<String>,
    #[command(flatten)]
    pub filters: HostFilterArgs,
    #[command(flatten)]
    pub page: PageArgs,
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
pub struct HostGetArgs {
    /// Host id (host-…). Find ids with `dn host list` or `dn host search`.
    pub host_id: String,
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
    use clap::CommandFactory;

    #[test]
    fn parses_hosts_delete_with_short_yes() {
        let cli = Cli::try_parse_from([
            "dn",
            "host",
            "delete",
            "host-FBNRAHQYQLWXWMCY7L4XP46ZXI",
            "-y",
        ])
        .unwrap();
        let Command::Host {
            command: HostCommand::Delete(args),
        } = cli.command
        else {
            panic!("expected `host delete` to parse into HostCommand::Delete");
        };
        assert_eq!(args.host_id, "host-FBNRAHQYQLWXWMCY7L4XP46ZXI");
        assert!(args.yes);
    }

    #[test]
    fn parses_role_delete_with_long_yes() {
        let cli = Cli::try_parse_from([
            "dn",
            "roles",
            "delete",
            "role-4A2TRFEEBUMSGYTBSZRNVWJUQE",
            "--yes",
        ])
        .unwrap();
        let Command::Role {
            command: RoleCommand::Delete(args),
        } = cli.command
        else {
            panic!("expected `role delete` to parse into RoleCommand::Delete");
        };
        assert_eq!(args.role_id, "role-4A2TRFEEBUMSGYTBSZRNVWJUQE");
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
    fn parses_network_delete_with_short_yes() {
        let cli = Cli::try_parse_from([
            "dn",
            "networks",
            "delete",
            "network-PP4ZXJCLB4VVUNOUYC67UW3UAE",
            "-y",
        ])
        .unwrap();
        let Command::Network {
            command: NetworkCommand::Delete(args),
        } = cli.command
        else {
            panic!("expected `network delete` to parse into NetworkCommand::Delete");
        };
        assert_eq!(args.network_id, "network-PP4ZXJCLB4VVUNOUYC67UW3UAE");
        assert!(args.yes);
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
            "host-FBNRAHQYQLWXWMCY7L4XP46ZXI",
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
        assert_eq!(args.host_id, "host-FBNRAHQYQLWXWMCY7L4XP46ZXI");
        assert_eq!(args.add_tag, vec!["dns:cloudflare"]);
        assert_eq!(args.remove_tag, vec!["old:stale"]);
    }

    #[test]
    fn parses_hosts_edit_repeated_tags() {
        let cli = Cli::try_parse_from([
            "dn",
            "hosts",
            "edit",
            "host-FBNRAHQYQLWXWMCY7L4XP46ZXI",
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
        let cli = Cli::try_parse_from([
            "dn",
            "host",
            "edit",
            "host-FBNRAHQYQLWXWMCY7L4XP46ZXI",
            "--role",
            "role-Y5LAD6TPG7QXASCOCUCBF632NI",
        ])
        .unwrap();
        let Command::Host {
            command: HostCommand::Edit(args),
        } = cli.command
        else {
            panic!("expected `host edit --role` to parse into HostCommand::Edit");
        };
        assert_eq!(
            args.role.as_deref(),
            Some("role-Y5LAD6TPG7QXASCOCUCBF632NI")
        );
        assert!(validate_edit_preflight(&args).is_ok());
    }

    #[test]
    fn parses_hosts_edit_with_clear_role() {
        let cli = Cli::try_parse_from([
            "dn",
            "host",
            "edit",
            "host-FBNRAHQYQLWXWMCY7L4XP46ZXI",
            "--clear-role",
        ])
        .unwrap();
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
            "host-FBNRAHQYQLWXWMCY7L4XP46ZXI",
            "--role",
            "role-H55C26ACPLURXFO4C3MWND4HHA",
            "--clear-role",
        ])
        .err()
        .map(|e| e.kind());
        assert_eq!(kind, Some(clap::error::ErrorKind::ArgumentConflict));
    }

    #[test]
    fn parses_roles_get() {
        let cli =
            Cli::try_parse_from(["dn", "role", "get", "role-B2RPGZ2TEPSZO5EGJJAX5LNN7M"]).unwrap();
        let Command::Role {
            command: RoleCommand::Get(args),
        } = cli.command
        else {
            panic!("expected role get");
        };
        assert_eq!(args.role_id, "role-B2RPGZ2TEPSZO5EGJJAX5LNN7M");
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
    fn parses_audit_log_list_with_filters() {
        let cli = Cli::try_parse_from([
            "dn",
            "audit-logs",
            "list",
            "--limit",
            "5",
            "--cursor",
            "c1",
            "--target",
            "host-FBNRAHQYQLWXWMCY7L4XP46ZXI",
            "--target-type",
            "host",
        ])
        .unwrap();
        let Command::AuditLog {
            command: AuditLogCommand::List(args),
        } = cli.command
        else {
            panic!("expected `audit-log list`");
        };
        assert_eq!(args.page.limit, 5);
        assert_eq!(args.page.cursor.as_deref(), Some("c1"));
        assert_eq!(
            args.target.as_deref(),
            Some("host-FBNRAHQYQLWXWMCY7L4XP46ZXI")
        );
        assert_eq!(args.target_type.as_deref(), Some("host"));
    }

    #[test]
    fn limit_defaults_to_the_api_maximum_and_stays_in_range() {
        let cli = Cli::try_parse_from(["dn", "audit-log", "list"]).unwrap();
        let Command::AuditLog {
            command: AuditLogCommand::List(args),
        } = cli.command
        else {
            panic!("expected `audit-log list`");
        };
        assert_eq!(args.page.limit, 500);
        assert!(args.page.cursor.is_none());
        for flag in ["--limit", "--page-size"] {
            for bad in ["0", "501"] {
                assert!(Cli::try_parse_from(["dn", "host", "list", flag, bad]).is_err());
            }
        }
    }

    #[test]
    fn the_last_cursor_wins_and_may_start_with_a_hyphen() {
        // Paging appends the hinted cursor to a command that may already
        // carry one; cursors are opaque and can begin with `-`.
        let cli = Cli::try_parse_from(["dn", "host", "list", "--cursor", "p2", "--cursor", "-p3"])
            .unwrap();
        let Command::Host {
            command: HostCommand::List(args),
        } = cli.command
        else {
            panic!("expected `host list`");
        };
        assert_eq!(args.page.cursor.as_deref(), Some("-p3"));
    }

    #[test]
    fn blank_cursor_and_filters_are_rejected() {
        for args in [
            ["dn", "host", "list", "--cursor", "  "],
            ["dn", "audit-log", "list", "--target", ""],
            ["dn", "audit-log", "list", "--target-type", " "],
        ] {
            assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn plural_command_names_still_parse() {
        // The old plural names stay as aliases so existing scripts keep working.
        let cli = Cli::try_parse_from(["dn", "hosts", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Host {
                command: HostCommand::List(_)
            }
        ));
        let cli = Cli::try_parse_from(["dn", "networks", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Network {
                command: NetworkCommand::List(_)
            }
        ));
        let cli = Cli::try_parse_from(["dn", "roles", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Role {
                command: RoleCommand::List(_)
            }
        ));
        let cli = Cli::try_parse_from(["dn", "tags", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Tag {
                command: TagCommand::List(_)
            }
        ));
        let cli = Cli::try_parse_from(["dn", "tags", "get", "env:prod"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Tag {
                command: TagCommand::Get(_)
            }
        ));
        let cli =
            Cli::try_parse_from(["dn", "hosts", "get", "host-FBNRAHQYQLWXWMCY7L4XP46ZXI"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Host {
                command: HostCommand::Get(_)
            }
        ));
        let cli = Cli::try_parse_from([
            "dn",
            "networks",
            "get",
            "network-PP4ZXJCLB4VVUNOUYC67UW3UAE",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Network {
                command: NetworkCommand::Get(_)
            }
        ));
    }

    #[test]
    fn help_links_to_api_reference_and_openapi_spec() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("https://www.defined.net/docs/api/"), "{help}");
        assert!(
            help.contains("https://www.defined.net/docs/openapi.yaml"),
            "{help}"
        );
    }
}
