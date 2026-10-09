mod create;
mod delete;
mod edit;
mod get;

pub use create::{hosts_create, validate_create_preflight};
pub use delete::hosts_delete;
pub use edit::{hosts_edit, validate_edit_preflight};
pub use get::hosts_get;

use anyhow::{anyhow, bail};
use serde_json::Value;

use crate::api::Client;
use crate::cli::{HostSearchArgs, PageArgs};
use crate::output::{joined_field, print_list, sanitize_for_display, str_field};

pub fn hosts_list(client: &Client, page: &PageArgs, json: bool) -> anyhow::Result<()> {
    let res = client.list_hosts(page)?;
    render_hosts(&res, json, "No hosts found.")
}

/// The `filter.search` term for `dn host search`, joined from the argv words
/// and trimmed. The join means `dn host search web server` searches for the
/// single phrase "web server" rather than erroring on an extra positional.
fn search_query(args: &HostSearchArgs) -> String {
    args.query.join(" ").trim().to_string()
}

/// Reject a query the API would reject anyway (fewer than two characters →
/// 400 `ERR_TOO_SHORT`), before credentials are resolved or the wire is
/// touched — the same preflight contract as create/edit. Two chars is counted
/// in `char`s, not bytes, so a two-emoji query passes.
pub fn validate_search_preflight(args: &HostSearchArgs) -> anyhow::Result<()> {
    let query = search_query(args);
    if query.chars().count() < 2 {
        bail!("search query must be at least 2 characters");
    }
    Ok(())
}

pub fn hosts_search(client: &Client, args: &HostSearchArgs, json: bool) -> anyhow::Result<()> {
    let query = search_query(args);
    let res = client.search_hosts(&query, &args.page)?;
    render_hosts(
        &res,
        json,
        &format!("No hosts match \"{}\".", sanitize_for_display(&query)),
    )
}

/// Render a hosts envelope. Shared by `host list` and `host search` so the
/// two can't drift on columns.
fn render_hosts(res: &Value, json: bool, empty_msg: &str) -> anyhow::Result<()> {
    print_list(res, json, empty_msg, &HOST_HEADERS, host_rows)
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
            page: PageArgs::default(),
        }
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
    fn render_hosts_json_passes_the_envelope_through() {
        let res = json!({"data": [{"id": "host-1"}], "metadata": {"hasNextPage": false}});
        // Just assert it doesn't error on the JSON path; the payload is the
        // client's, rendered verbatim.
        assert!(render_hosts(&res, true, "unused").is_ok());
    }

    #[test]
    fn render_hosts_human_empty_uses_the_supplied_message() {
        let res = json!({"data": [], "metadata": {}});
        assert!(render_hosts(&res, false, "No hosts match \"x\".").is_ok());
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
