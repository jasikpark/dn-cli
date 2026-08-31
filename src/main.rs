mod api;
mod config;

use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};
use unicode_width::UnicodeWidthStr;

use crate::api::{ApiError, Client};
use crate::config::{
    Config, FileConfig, KeySource, api_key_env_is_set, api_url, config_path, normalize_op_ref,
    op_read, validate_op_ref,
};

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
    /// Inspect and manage Nebula hosts
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
    /// Create a host (or lighthouse / relay) and an enrollment code in one
    /// transaction. Prints the OTP to give to `dnclient enroll`.
    Create(HostCreateArgs),
    /// Edit a host — update tags, and (in future) other mutable fields.
    Edit(HostEditArgs),
    /// Delete a host. Asks for confirmation unless --yes is passed.
    Delete(HostDeleteArgs),
}

/// Arguments for `dn hosts create`. Mirrors the
/// `POST /v2/host-and-enrollment-code` request body, plus a `--network`
/// override for the auto-pick fallback.
///
/// Validation that's cheap client-side (lighthouse needs static address +
/// non-zero listen port; relay needs listen port; lighthouse-xor-relay) is
/// enforced before the request — the API enforces the same rules, but
/// catching them locally gives a clearer error than `ERR_INVALID_VALUE` from
/// 1500km away.
#[derive(Args)]
struct HostCreateArgs {
    /// Host name (1–255 chars)
    name: String,
    /// Network ID. Omit if the account has exactly one network — it's
    /// auto-picked, which is the common case at signup.
    #[arg(long)]
    network: Option<String>,
    /// Role ID to assign. Omit to use the account's default role (deny-all
    /// firewall — see post-create output).
    #[arg(long)]
    role: Option<String>,
    /// Mark this host as a lighthouse. Requires `--static-address` and
    /// `--listen-port`. Mutually exclusive with `--relay`.
    #[arg(long, conflicts_with = "relay")]
    lighthouse: bool,
    /// Mark this host as a relay. Requires `--listen-port`. Mutually
    /// exclusive with `--lighthouse`.
    #[arg(long)]
    relay: bool,
    /// IPv4 address to assign, or the network's IPv4 CIDR to have the server
    /// pick one inside it. When omitted, hosts on networks with an IPv4
    /// prefix still get an auto-assigned IPv4: the CLI sends that prefix,
    /// because the API otherwise leaves dual-stack hosts v6-only. See
    /// `--no-ipv4`.
    #[arg(long, conflicts_with = "no_ipv4")]
    ipv4: Option<String>,
    /// Skip the IPv4 auto-assign on a dual-stack network, creating a v6-only
    /// host. IPv4-only networks always assign an IPv4.
    #[arg(long)]
    no_ipv4: bool,
    /// IPv6 address to assign. The server auto-assigns one when omitted.
    #[arg(long)]
    ipv6: Option<String>,
    /// Static `ip:port` (or `hostname:port`) for lighthouses / relays.
    /// Repeatable. Required for lighthouses.
    #[arg(long = "static-address")]
    static_addresses: Vec<String>,
    /// UDP listen port. Required (non-zero) for lighthouses and relays.
    #[arg(long)]
    listen_port: Option<u16>,
    /// Tags in `key:value` form (key ≤20 chars, value ≤50, no whitespace).
    /// Repeatable, or comma-separated.
    #[arg(long, value_delimiter = ',')]
    tags: Vec<String>,
    /// Lifetime of the enrollment code in seconds. API default is 86400
    /// (24h).
    #[arg(long)]
    code_lifetime: Option<u64>,
}

#[derive(Args)]
struct HostEditArgs {
    /// Host id (host-…)
    host_id: String,
    /// Rename the host.
    #[arg(long)]
    name: Option<String>,
    /// Add a tag in key:value form. Repeatable, or comma-separated.
    #[arg(long, value_name = "KEY:VALUE", value_delimiter = ',')]
    add_tag: Vec<String>,
    /// Remove a tag by its key. Repeatable, or comma-separated.
    #[arg(long, value_name = "KEY", value_delimiter = ',')]
    remove_tag: Vec<String>,
}

#[derive(Args)]
struct HostDeleteArgs {
    /// Host id (host-…)
    host_id: String,
    /// Skip the confirmation prompt (required when stdin is not a terminal or
    /// with --json)
    #[arg(short = 'y', long)]
    yes: bool,
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
    // Run all client-side validation before resolving credentials or touching
    // the network, so `dn hosts create --lighthouse` (missing required flags)
    // reports the actual problem instead of hiding behind a credentials error.
    if let Command::Hosts {
        command: HostsCommand::Create(args),
    } = &cli.command
    {
        validate_create_preflight(args)?;
    }

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
                HostsCommand::Create(args) => hosts_create(&client, args, cli.json)?,
                HostsCommand::Edit(args) => hosts_edit(&client, args, cli.json)?,
                HostsCommand::Delete(args) => hosts_delete(&client, args, cli.json)?,
            }
        }
    }

    Ok(())
}

const API_KEYS_URL: &str = "https://admin.defined.net/settings/api-keys/add";

fn auth_login(args: &AuthLoginArgs, json: bool) -> anyhow::Result<()> {
    let reference = match &args.reference {
        Some(r) => normalize_op_ref(r),
        None => prompt_for_reference(json)?,
    };
    validate_op_ref(&reference)?;

    let (mut file, corrupt) = FileConfig::load_or_reset()?;
    if let Some(err) = corrupt {
        eprintln!("warning: replacing unreadable config ({err:#})");
    }
    if !args.no_verify {
        let key = op_read(&reference)?;
        Client::new(Config::with_key(key, &file))
            .verify_key()
            .map_err(label_verify_error)?;
    }
    file.api_key_ref = Some(reference.clone());
    let path = file.save()?;
    let env_override = warn_env_override();

    if json {
        print_json(&json!({
            "ok": true,
            "config_path": path,
            "api_key_ref": reference,
            "env_override": env_override,
        }))?;
    } else {
        println!(
            "Saved reference to {}. `dn` will resolve it with `op read` on every call.",
            path.display()
        );
    }
    Ok(())
}

/// Only an API response is evidence the key itself was rejected; anything
/// else (offline, bad `DEFINED_API_URL`) is a reachability problem.
fn label_verify_error(err: anyhow::Error) -> anyhow::Error {
    if err.downcast_ref::<ApiError>().is_some() {
        err.context("the key resolved but the API rejected it")
    } else {
        err.context("could not reach the API to verify the key")
    }
}

/// The environment shadows the file, so a login/logout under an exported
/// `DEFINED_API_KEY` changes nothing for the next call. Say so.
fn warn_env_override() -> bool {
    let set = api_key_env_is_set();
    if set {
        eprintln!(
            "warning: DEFINED_API_KEY is set in this environment and takes precedence over the stored reference."
        );
    }
    set
}

fn print_json(value: &Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
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
    let line = normalize_op_ref(&line);
    if line.is_empty() {
        bail!("no reference entered");
    }
    Ok(line)
}

/// Read-only introspection: never resolves a secret and never fails on a
/// misconfigured key — a bad reference or blank env var is reported as
/// `source: "invalid"` so callers can branch on it.
fn auth_status(json: bool) -> anyhow::Result<()> {
    let file = FileConfig::load()?;
    let path = config_path()?;
    let api_url = api_url(&file);
    let source = KeySource::detect(&file);
    let (label, reference, message) = match &source {
        Ok(Some(s)) => (s.label(), s.reference(), None),
        Ok(None) => ("none", None, None),
        Err(e) => ("invalid", None, Some(format!("{e:#}"))),
    };

    if json {
        return print_json(&json!({
            "source": label,
            "api_key_ref": reference,
            "message": message,
            "config_path": path,
            "api_url": api_url,
        }));
    }

    match &source {
        Ok(None) => {
            println!("No API key configured. Run `dn auth login` or set DEFINED_API_KEY.")
        }
        Ok(Some(KeySource::Env(_))) => {
            println!("API key: DEFINED_API_KEY (raw value in environment)")
        }
        Ok(Some(KeySource::EnvRef(r))) => {
            println!("API key: DEFINED_API_KEY -> {r} (resolved via op read)")
        }
        Ok(Some(KeySource::FileRef(r))) => println!(
            "API key: {r} (from {}, resolved via op read)",
            path.display()
        ),
        Err(e) => println!("API key: invalid — {e:#}"),
    }
    println!("API URL: {api_url}");
    Ok(())
}

fn auth_logout(json: bool) -> anyhow::Result<()> {
    let (mut file, corrupt) = FileConfig::load_or_reset()?;
    let path = config_path()?;
    if let Some(err) = corrupt {
        eprintln!("warning: removing unreadable config ({err:#})");
    }
    let removed = file.api_key_ref.take().is_some();
    let file_deleted = if file.is_empty() {
        match std::fs::remove_file(&path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                return Err(e).with_context(|| format!("failed to remove {}", path.display()));
            }
        }
    } else {
        file.save()?;
        false
    };
    let env_override = warn_env_override();

    if json {
        return print_json(&json!({
            "ok": true,
            "removed": removed,
            "file_deleted": file_deleted,
            "config_path": path,
            "env_override": env_override,
        }));
    }
    match (removed, file_deleted) {
        (true, true) => println!("Removed {}.", path.display()),
        (true, false) => println!(
            "Removed the stored secret reference from {}.",
            path.display()
        ),
        (false, true) => println!("Removed unreadable config {}.", path.display()),
        (false, false) => println!("No stored secret reference to remove."),
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

fn hosts_create(client: &Client, args: &HostCreateArgs, json: bool) -> anyhow::Result<()> {
    // Auto-assigning an IPv4 means sending the network's own IPv4 prefix, so
    // the network is fetched only while IPv4 is still undecided.
    let auto_ipv4 = wants_auto_ipv4(args);
    let (network_id, ipv4_cidr) = match &args.network {
        Some(id) => {
            let cidr = if auto_ipv4 {
                let network = client.get_network(id).with_context(|| {
                    format!(
                        "could not read network {id} to auto-assign an IPv4 (the API key needs \
                         networks:read; pass --ipv4 <ADDR|CIDR> or --no-ipv4 to skip the lookup)"
                    )
                })?;
                network_ipv4_cidr(&network["data"])
            } else {
                None
            };
            (id.clone(), cidr)
        }
        None => {
            let networks = client.list_networks()?;
            let network = pick_network(&networks)?;
            let id = network
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("network list response missing 'id' on the only entry"))?;
            let cidr = if auto_ipv4 {
                network_ipv4_cidr(network)
            } else {
                None
            };
            (id.to_owned(), cidr)
        }
    };

    let body = build_host_create_body(args, &network_id, ipv4_cidr.as_deref());
    let res = client.create_host_with_enrollment(&body)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&res)?);
        return Ok(());
    }

    print!("{}", render_host_create_human(&res));
    Ok(())
}

/// Edit a host's tags via read-modify-write: GET the current host, apply
/// the `--add-tag` / `--remove-tag` deltas, PUT the full object back.
fn hosts_edit(client: &Client, args: &HostEditArgs, json: bool) -> anyhow::Result<()> {
    if args.name.is_none() && args.add_tag.is_empty() && args.remove_tag.is_empty() {
        bail!("nothing to edit — pass --name, --add-tag, or --remove-tag");
    }

    let id = args.host_id.as_str();
    let res = client.get_host(id)?;
    let data = res
        .get("data")
        .ok_or_else(|| anyhow!("host response missing 'data'"))?;

    let mut tags = extract_tags(data);

    for raw in &args.add_tag {
        let tag = raw.trim().to_string();
        parse_tag(&tag)?;
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    for raw in &args.remove_tag {
        let tag = raw.trim();
        let before = tags.len();
        tags.retain(|t| t != tag);
        if tags.len() == before && !json {
            eprintln!("warning: tag \"{tag}\" was not present on the host");
        }
    }

    let mut body = data.clone();
    let obj = body
        .as_object_mut()
        .ok_or_else(|| anyhow!("host data is not an object"))?;
    obj.insert("tags".into(), json!(tags));
    if let Some(new_name) = &args.name {
        obj.insert("name".into(), json!(new_name));
    }

    let updated = client.update_host(id, &body)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&updated)?);
        return Ok(());
    }

    let (_, name, ips) = host_fields(updated.get("data").unwrap_or(&Value::Null));
    let final_tags = extract_tags(updated.get("data").unwrap_or(&Value::Null));
    if name.is_empty() {
        print!("Updated host {id}");
    } else {
        print!("Updated host \"{name}\" ({id})");
    }
    if !ips.is_empty() {
        print!(" [{ips}]");
    }
    println!();
    if final_tags.is_empty() {
        println!("  Tags: (none)");
    } else {
        for tag in &final_tags {
            println!("  {tag}");
        }
    }
    Ok(())
}

/// Parse a `key:value` tag, splitting on the first `:`.
fn parse_tag(s: &str) -> anyhow::Result<(String, String)> {
    let s = s.trim();
    match s.split_once(':') {
        Some((k, v)) if !k.is_empty() && !v.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => Err(anyhow!("invalid tag \"{s}\" — expected key:value")),
    }
}

/// Pull the tags out of a host object as a list of `key:value` strings.
/// The full string is the identity — multiple tags can share a prefix.
fn extract_tags(host: &Value) -> Vec<String> {
    host.get("tags")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Delete one host, confirming interactively unless `--yes` says not to.
/// The confirmation lookup is what makes the human path safe (you see the
/// name and IPs of the host you typed an id for), so it runs before the
/// prompt and its failure is fatal.
fn hosts_delete(client: &Client, args: &HostDeleteArgs, json: bool) -> anyhow::Result<()> {
    let id = args.host_id.as_str();
    let mut name = String::new();

    match delete_confirmation(args.yes, json, std::io::stdin().is_terminal()) {
        DeleteConfirmation::Skip => {}
        DeleteConfirmation::Refuse => bail!(
            "pass --yes to delete without a confirmation prompt when running non-interactively"
        ),
        DeleteConfirmation::Prompt => {
            let res = client.get_host(id).with_context(|| {
                format!(
                    "could not read host {id} to confirm the deletion (the API key needs \
                     hosts:read; pass --yes to skip the lookup)"
                )
            })?;
            let (_, found, ips) = host_fields(&res["data"]);
            name = found.to_owned();

            let mut err = std::io::stderr();
            write!(err, "{}", delete_prompt(id, &name, &ips))?;
            err.flush()?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            if !confirmation_accepted(&line) {
                bail!("aborted, host not deleted");
            }
        }
    }

    client.delete_host(id)?;

    if json {
        return print_json(&delete_json_payload(id));
    }
    if name.is_empty() {
        println!("Deleted host {id}.");
    } else {
        println!("Deleted host \"{name}\" ({id}).");
    }
    Ok(())
}

/// How `dn hosts delete` should confirm a deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeleteConfirmation {
    /// Delete straight away: no lookup, no prompt. Only `hosts:delete` is
    /// needed.
    Skip,
    /// Look the host up, then ask on stderr.
    Prompt,
    /// Nowhere to ask — the run has to opt in with `--yes` instead.
    Refuse,
}

/// `--yes` is the only way a non-interactive run reaches the DELETE: a prompt
/// with no terminal behind it would hang a `--json` caller or a script, so it
/// is refused rather than skipped.
fn delete_confirmation(yes: bool, json: bool, stdin_is_tty: bool) -> DeleteConfirmation {
    if yes {
        DeleteConfirmation::Skip
    } else if json || !stdin_is_tty {
        DeleteConfirmation::Refuse
    } else {
        DeleteConfirmation::Prompt
    }
}

/// `y` / `yes`, case- and whitespace-insensitive. Everything else — a bare
/// newline included — declines, so the default is the non-destructive one.
fn confirmation_accepted(input: &str) -> bool {
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// The confirmation line, naming the host by everything the lookup returned so
/// a mistyped id is visible before it costs a device its access. The id is
/// always shown; name and IPs are dropped when the response lacks them.
fn delete_prompt(id: &str, name: &str, ips: &str) -> String {
    if name.is_empty() {
        format!("Delete host {id}? [y/N] ")
    } else if ips.is_empty() {
        format!("Delete host \"{name}\" ({id})? [y/N] ")
    } else {
        format!("Delete host \"{name}\" ({id}; {ips})? [y/N] ")
    }
}

/// The `--json` success payload. The API answers a delete with an empty
/// envelope, so the id and the outcome are echoed for the caller to key on.
fn delete_json_payload(id: &str) -> Value {
    json!({"id": id, "deleted": true})
}

/// Reject lighthouse/relay configurations the API would also reject, but with
/// a clearer message than `ERR_INVALID_VALUE` from a round-trip away. The
/// pairing rules (lighthouse needs static address + non-zero port; relay
/// needs non-zero port) come straight from the v2 host-create error examples.
fn validate_create_preflight(args: &HostCreateArgs) -> anyhow::Result<()> {
    if args.lighthouse {
        if args.static_addresses.is_empty() {
            return Err(anyhow!(
                "--lighthouse requires at least one --static-address <ip:port>"
            ));
        }
        if args.listen_port.unwrap_or(0) == 0 {
            return Err(anyhow!(
                "--lighthouse requires --listen-port <port> (non-zero)"
            ));
        }
    }
    if args.relay && args.listen_port.unwrap_or(0) == 0 {
        return Err(anyhow!("--relay requires --listen-port <port> (non-zero)"));
    }
    Ok(())
}

/// Pick the account's only network from a `GET /v2/networks` page. Returns a
/// usefully-typed error when auto-pick is ambiguous (0 networks → tell user
/// to create one; ≥2, or more pages → tell user to pass --network), so the
/// caller doesn't have to know the shape of the response to recover.
fn pick_network(networks: &Value) -> anyhow::Result<&Value> {
    let rows = networks
        .get("data")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let has_more = networks
        .get("metadata")
        .and_then(|m| m.get("hasNextPage"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match (rows.len(), has_more) {
        (0, _) => Err(anyhow!(
            "no networks found in this account — create one in the web client first"
        )),
        (1, false) => Ok(&rows[0]),
        _ => Err(anyhow!(
            "multiple networks found — pass --network <id> to disambiguate"
        )),
    }
}

/// Whether `hosts create` should have the server pick an IPv4: neither an
/// explicit `--ipv4` nor `--no-ipv4` has settled it.
fn wants_auto_ipv4(args: &HostCreateArgs) -> bool {
    args.ipv4.is_none() && !args.no_ipv4
}

/// The network's IPv4 prefix from its `cidrs` list, or `None` on a v6-only
/// network. Sent as an `ipAddresses` entry it makes the server auto-assign an
/// IPv4 inside that prefix; the API honours only the network's exact prefix
/// (sub-prefixes are rejected), so this is the one CIDR worth sending.
fn network_ipv4_cidr(network: &Value) -> Option<String> {
    network
        .get("cidrs")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find(|cidr| {
            cidr.split_once('/')
                .is_some_and(|(addr, _)| addr.parse::<std::net::Ipv4Addr>().is_ok())
        })
        .map(str::to_owned)
}

/// Assemble the JSON body for `POST /v2/host-and-enrollment-code` from parsed
/// CLI args. Pure (no I/O) so the body construction is unit-testable without
/// hitting the wire. Optional fields are omitted entirely when unset rather
/// than sent as null — the API treats absent and null the same, but a tighter
/// payload makes API logs easier to diff later.
///
/// `ipv4_auto_cidr` is the network's IPv4 prefix, sent in place of an explicit
/// `--ipv4` so the server picks an address inside it. Without either, the
/// server creates a v6-only host on every network but a legacy v4-only one.
fn build_host_create_body(
    args: &HostCreateArgs,
    network_id: &str,
    ipv4_auto_cidr: Option<&str>,
) -> Value {
    let mut body = json!({
        "name": args.name,
        "networkID": network_id,
    });
    let obj = body.as_object_mut().expect("freshly built object");

    if let Some(role) = &args.role {
        obj.insert("roleID".into(), json!(role));
    }
    let mut ips: Vec<&str> = Vec::new();
    if !args.no_ipv4
        && let Some(v4) = args.ipv4.as_deref().or(ipv4_auto_cidr)
    {
        ips.push(v4);
    }
    if let Some(v6) = &args.ipv6 {
        ips.push(v6);
    }
    if !ips.is_empty() {
        obj.insert("ipAddresses".into(), json!(ips));
    }
    if !args.static_addresses.is_empty() {
        obj.insert("staticAddresses".into(), json!(args.static_addresses));
    }
    if let Some(p) = args.listen_port {
        obj.insert("listenPort".into(), json!(p));
    }
    if args.lighthouse {
        obj.insert("isLighthouse".into(), json!(true));
    }
    if args.relay {
        obj.insert("isRelay".into(), json!(true));
    }
    if !args.tags.is_empty() {
        obj.insert("tags".into(), json!(args.tags));
    }
    if let Some(c) = args.code_lifetime {
        obj.insert("codeLifetimeSeconds".into(), json!(c));
    }
    body
}

/// Human-readable post-create summary. Surfaces what the user needs to act on
/// next: the OTP to feed `dnclient enroll`, and the deny-all-default warning
/// so a fresh user doesn't wonder why the hosts can't reach each other yet.
///
/// Treated as the user-facing UX surface — strings, ordering, and emphasis
/// are deliberately open to revision; the structure (extract → format → emit)
/// is what's load-bearing.
fn render_host_create_human(res: &Value) -> String {
    let data = res.get("data");
    let host = data.and_then(|d| d.get("host"));
    let enrollment = data.and_then(|d| d.get("enrollmentCode"));

    let str_field = |v: Option<&Value>, key: &str| -> String {
        v.and_then(|h| h.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let name = str_field(host, "name");
    let id = str_field(host, "id");
    let ips = host
        .and_then(|h| h.get("ipAddresses"))
        .and_then(Value::as_array)
        .map(|addrs| {
            addrs
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let is_lighthouse = host
        .and_then(|h| h.get("isLighthouse"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let is_relay = host
        .and_then(|h| h.get("isRelay"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let kind = if is_lighthouse {
        "lighthouse"
    } else if is_relay {
        "relay"
    } else {
        "host"
    };
    let code = str_field(enrollment, "code");

    let mut out = String::new();
    out.push_str(&format!("Created {kind} \"{name}\" ({id})\n"));
    if !ips.is_empty() {
        out.push_str(&format!("  IP addresses: {ips}\n"));
    }
    if !code.is_empty() {
        out.push('\n');
        out.push_str("To enroll the device, install dnclient and run:\n");
        out.push_str(&format!("  dnclient enroll {code}\n"));
    }
    out.push('\n');
    out.push_str("Note: the default role denies all traffic. New hosts will be on the\n");
    out.push_str("network but unable to reach each other until a role with firewall rules\n");
    out.push_str("is created and assigned (see `dn roles --help`).\n");
    out
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

    fn args(
        name: &str,
        network: Option<&str>,
        lighthouse: bool,
        relay: bool,
        static_addresses: Vec<&str>,
        listen_port: Option<u16>,
    ) -> HostCreateArgs {
        HostCreateArgs {
            name: name.into(),
            network: network.map(str::to_owned),
            role: None,
            lighthouse,
            relay,
            ipv4: None,
            no_ipv4: false,
            ipv6: None,
            static_addresses: static_addresses.into_iter().map(str::to_owned).collect(),
            listen_port,
            tags: Vec::new(),
            code_lifetime: None,
        }
    }

    #[test]
    fn pick_network_returns_sole_network_when_one() {
        let networks = json!({
            "data": [{"id": "network-only", "cidrs": ["100.100.0.0/22"]}],
            "metadata": {"hasNextPage": false},
        });
        let network = pick_network(&networks).unwrap();
        assert_eq!(network["id"], json!("network-only"));
        assert_eq!(network["cidrs"], json!(["100.100.0.0/22"]));
    }

    #[test]
    fn pick_network_errors_on_zero_networks() {
        let networks = json!({"data": [], "metadata": {"hasNextPage": false}});
        let err = pick_network(&networks).unwrap_err().to_string();
        assert!(err.contains("no networks"));
    }

    #[test]
    fn pick_network_errors_on_multiple_in_data() {
        let networks = json!({
            "data": [{"id": "a"}, {"id": "b"}],
            "metadata": {"hasNextPage": false},
        });
        let err = pick_network(&networks).unwrap_err().to_string();
        assert!(err.contains("--network"));
    }

    #[test]
    fn pick_network_errors_when_more_pages_exist() {
        // Single row but a second page → can't safely auto-pick.
        let networks = json!({
            "data": [{"id": "a"}],
            "metadata": {"hasNextPage": true},
        });
        assert!(pick_network(&networks).is_err());
    }

    #[test]
    fn wants_auto_ipv4_only_when_neither_flag_settles_it() {
        let mut a = args("h", None, false, false, vec![], None);
        assert!(wants_auto_ipv4(&a));
        a.no_ipv4 = true;
        assert!(!wants_auto_ipv4(&a));
        a.no_ipv4 = false;
        a.ipv4 = Some("100.100.0.0/22".into());
        assert!(!wants_auto_ipv4(&a));
    }

    #[test]
    fn network_ipv4_cidr_picks_v4_among_mixed_cidrs() {
        let network = json!({"cidrs": ["fdef:c0:c0::/48", "100.100.0.0/22"]});
        assert_eq!(
            network_ipv4_cidr(&network).as_deref(),
            Some("100.100.0.0/22")
        );
    }

    #[test]
    fn network_ipv4_cidr_is_none_without_a_v4_prefix() {
        assert_eq!(
            network_ipv4_cidr(&json!({"cidrs": ["fdef:c0:c0::/48"]})),
            None
        );
        assert_eq!(network_ipv4_cidr(&json!({})), None);
    }

    #[test]
    fn build_body_minimal_omits_all_optionals() {
        let a = args("server", None, false, false, vec![], None);
        let body = build_host_create_body(&a, "network-1", None);
        assert_eq!(
            body,
            json!({"name": "server", "networkID": "network-1"}),
            "optional fields must be absent (not null) when unset"
        );
    }

    #[test]
    fn build_body_lighthouse_payload() {
        let mut a = args("lh", None, true, false, vec!["1.2.3.4:4242"], Some(4242));
        a.ipv4 = Some("100.100.0.5".into());
        let body = build_host_create_body(&a, "network-1", None);
        assert_eq!(body["isLighthouse"], json!(true));
        assert_eq!(body["staticAddresses"], json!(["1.2.3.4:4242"]));
        assert_eq!(body["listenPort"], json!(4242));
        assert_eq!(body["ipAddresses"], json!(["100.100.0.5"]));
        assert!(body.get("isRelay").is_none());
    }

    #[test]
    fn build_body_dual_stack_ips_preserve_v4_then_v6_order() {
        let mut a = args("h", None, false, false, vec![], None);
        a.ipv4 = Some("100.100.0.5".into());
        a.ipv6 = Some("fdef::42".into());
        let body = build_host_create_body(&a, "n", None);
        assert_eq!(body["ipAddresses"], json!(["100.100.0.5", "fdef::42"]));
    }

    #[test]
    fn build_body_sends_network_cidr_to_auto_assign_ipv4() {
        let a = args("h", None, false, false, vec![], None);
        let body = build_host_create_body(&a, "n", Some("100.100.0.0/22"));
        assert_eq!(body["ipAddresses"], json!(["100.100.0.0/22"]));
    }

    #[test]
    fn build_body_explicit_ipv4_wins_over_network_cidr() {
        let mut a = args("h", None, false, false, vec![], None);
        a.ipv4 = Some("100.100.0.5".into());
        let body = build_host_create_body(&a, "n", Some("100.100.0.0/22"));
        assert_eq!(body["ipAddresses"], json!(["100.100.0.5"]));
    }

    #[test]
    fn build_body_no_ipv4_yields_v6_only_host() {
        let mut a = args("h", None, false, false, vec![], None);
        a.no_ipv4 = true;
        let body = build_host_create_body(&a, "n", Some("100.100.0.0/22"));
        assert!(body.get("ipAddresses").is_none());
        a.ipv6 = Some("fdef::42".into());
        let body = build_host_create_body(&a, "n", Some("100.100.0.0/22"));
        assert_eq!(body["ipAddresses"], json!(["fdef::42"]));
    }

    #[test]
    fn build_body_includes_tags_and_code_lifetime() {
        let mut a = args("h", None, false, false, vec![], None);
        a.tags = vec!["env:prod".into(), "team:gaming".into()];
        a.code_lifetime = Some(3600);
        let body = build_host_create_body(&a, "n", None);
        assert_eq!(body["tags"], json!(["env:prod", "team:gaming"]));
        assert_eq!(body["codeLifetimeSeconds"], json!(3600));
    }

    #[test]
    fn preflight_lighthouse_needs_static_address() {
        let a = args("lh", None, true, false, vec![], Some(4242));
        let err = validate_create_preflight(&a).unwrap_err().to_string();
        assert!(err.contains("--static-address"));
    }

    #[test]
    fn preflight_lighthouse_needs_nonzero_listen_port() {
        let a = args("lh", None, true, false, vec!["1.2.3.4:4242"], None);
        assert!(validate_create_preflight(&a).is_err());
        let a = args("lh", None, true, false, vec!["1.2.3.4:4242"], Some(0));
        assert!(validate_create_preflight(&a).is_err());
    }

    #[test]
    fn preflight_relay_needs_listen_port() {
        let a = args("r", None, false, true, vec![], None);
        let err = validate_create_preflight(&a).unwrap_err().to_string();
        assert!(err.contains("--listen-port"));
    }

    #[test]
    fn preflight_ok_for_regular_host_with_no_flags() {
        let a = args("plain", None, false, false, vec![], None);
        assert!(validate_create_preflight(&a).is_ok());
    }

    #[test]
    fn render_human_includes_otp_and_deny_warning() {
        let res = json!({
            "data": {
                "host": {
                    "id": "host-1",
                    "name": "mc-server",
                    "ipAddresses": ["100.100.0.5"],
                    "isLighthouse": false,
                    "isRelay": false,
                },
                "enrollmentCode": {"code": "ABC123XYZ", "lifetimeSeconds": 86400},
            }
        });
        let out = render_host_create_human(&res);
        assert!(out.contains("host"));
        assert!(out.contains("mc-server"));
        assert!(out.contains("ABC123XYZ"));
        assert!(out.contains("dnclient enroll"));
        assert!(out.to_lowercase().contains("default role"));
    }

    #[test]
    fn render_human_labels_lighthouse_when_set() {
        let res = json!({
            "data": {
                "host": {"id": "host-lh", "name": "lh-1", "isLighthouse": true},
                "enrollmentCode": {"code": "OTP"},
            }
        });
        assert!(render_host_create_human(&res).contains("lighthouse"));
    }

    #[test]
    fn delete_confirmation_skips_the_prompt_whenever_yes_is_passed() {
        for json in [false, true] {
            for tty in [false, true] {
                assert_eq!(
                    delete_confirmation(true, json, tty),
                    DeleteConfirmation::Skip,
                    "--yes must win over json={json} tty={tty}"
                );
            }
        }
    }

    #[test]
    fn delete_confirmation_refuses_without_yes_when_nothing_can_answer() {
        // --json is an agent run: a prompt there would hang the caller.
        assert_eq!(
            delete_confirmation(false, true, true),
            DeleteConfirmation::Refuse
        );
        // Piped stdin, human output: still nobody to ask.
        assert_eq!(
            delete_confirmation(false, false, false),
            DeleteConfirmation::Refuse
        );
    }

    #[test]
    fn delete_confirmation_prompts_an_interactive_human() {
        assert_eq!(
            delete_confirmation(false, false, true),
            DeleteConfirmation::Prompt
        );
    }

    #[test]
    fn confirmation_accepted_takes_only_y_and_yes() {
        assert!(confirmation_accepted("y"));
        assert!(confirmation_accepted("Y"));
        assert!(confirmation_accepted("yes"));
        assert!(confirmation_accepted("YES \n"));
        // Enter alone is a decline: the [y/N] default is the safe one.
        assert!(!confirmation_accepted(""));
        assert!(!confirmation_accepted("n"));
        assert!(!confirmation_accepted("no"));
    }

    #[test]
    fn delete_prompt_names_the_host_and_its_ips() {
        assert_eq!(
            delete_prompt("host-1", "web", "10.0.0.1, fd00::1"),
            "Delete host \"web\" (host-1; 10.0.0.1, fd00::1)? [y/N] "
        );
    }

    #[test]
    fn delete_prompt_falls_back_to_the_id_alone_without_a_name() {
        assert_eq!(
            delete_prompt("host-2", "", "10.0.0.2"),
            "Delete host host-2? [y/N] "
        );
    }

    #[test]
    fn delete_prompt_omits_the_ip_clause_when_there_are_none() {
        assert_eq!(
            delete_prompt("host-3", "db", ""),
            "Delete host \"db\" (host-3)? [y/N] "
        );
    }

    #[test]
    fn delete_json_payload_echoes_the_id_and_outcome() {
        assert_eq!(
            delete_json_payload("host-1"),
            json!({"id": "host-1", "deleted": true})
        );
    }

    #[test]
    fn parses_hosts_delete_with_short_yes() {
        let cli = Cli::try_parse_from(["dn", "hosts", "delete", "host-1", "-y"]).unwrap();
        let Command::Hosts {
            command: HostsCommand::Delete(args),
        } = cli.command
        else {
            panic!("expected `hosts delete` to parse into HostsCommand::Delete");
        };
        assert_eq!(args.host_id, "host-1");
        assert!(args.yes);
    }

    #[test]
    fn parses_hosts_create_with_positional_name() {
        let cli = Cli::try_parse_from(["dn", "hosts", "create", "my-laptop"]).unwrap();
        let Command::Hosts {
            command: HostsCommand::Create(args),
        } = cli.command
        else {
            panic!("expected `hosts create` to parse into HostsCommand::Create");
        };
        assert_eq!(args.name, "my-laptop");
    }

    #[test]
    fn parse_tag_splits_on_first_colon() {
        let (k, v) = parse_tag("dns:cloudflare").unwrap();
        assert_eq!(k, "dns");
        assert_eq!(v, "cloudflare");
    }

    #[test]
    fn parse_tag_preserves_colons_in_value() {
        let (k, v) = parse_tag("url:https://example.com").unwrap();
        assert_eq!(k, "url");
        assert_eq!(v, "https://example.com");
    }

    #[test]
    fn parse_tag_rejects_missing_colon() {
        assert!(parse_tag("novalue").is_err());
    }

    #[test]
    fn parse_tag_rejects_empty_key_or_value() {
        assert!(parse_tag(":val").is_err());
        assert!(parse_tag("key:").is_err());
    }

    #[test]
    fn extract_tags_returns_empty_when_absent() {
        assert!(extract_tags(&json!({})).is_empty());
        assert!(extract_tags(&json!({"tags": null})).is_empty());
    }

    #[test]
    fn extract_tags_preserves_full_strings() {
        let host = json!({"tags": ["dns:cloudflare", "dns:synced", "env:prod"]});
        let tags = extract_tags(&host);
        assert_eq!(tags, vec!["dns:cloudflare", "dns:synced", "env:prod"]);
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
            "old",
        ])
        .unwrap();
        let Command::Hosts {
            command: HostsCommand::Edit(args),
        } = cli.command
        else {
            panic!("expected `hosts edit` to parse into HostsCommand::Edit");
        };
        assert_eq!(args.host_id, "host-1");
        assert_eq!(args.add_tag, vec!["dns:cloudflare"]);
        assert_eq!(args.remove_tag, vec!["old"]);
    }

    #[test]
    fn parses_hosts_edit_comma_delimited_tags() {
        let cli = Cli::try_parse_from([
            "dn",
            "hosts",
            "edit",
            "host-1",
            "--add-tag",
            "a:1,b:2",
        ])
        .unwrap();
        let Command::Hosts {
            command: HostsCommand::Edit(args),
        } = cli.command
        else {
            panic!("expected comma-delimited add-tag to split");
        };
        assert_eq!(args.add_tag, vec!["a:1", "b:2"]);
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
