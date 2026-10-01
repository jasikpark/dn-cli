use anyhow::{anyhow, bail};
use serde_json::{Value, json};

use super::{host_fields, parse_tag, validate_host_id, validate_role_id};
use crate::api::Client;
use crate::cli::HostEditArgs;
use crate::output::{print_json, sanitize_for_display, str_field};

/// Catch user errors (empty flags, bad tag format) before credentials are
/// resolved, matching `validate_create_preflight`'s contract.
pub fn validate_edit_preflight(args: &HostEditArgs) -> anyhow::Result<()> {
    validate_host_id(&args.host_id)?;
    if args.name.is_none()
        && args.role.is_none()
        && !args.clear_role
        && args.add_tag.is_empty()
        && args.remove_tag.is_empty()
    {
        bail!("nothing to edit — pass --name, --role, --clear-role, --add-tag, or --remove-tag");
    }
    if let Some(n) = &args.name
        && n.trim().is_empty()
    {
        bail!("--name must not be empty");
    }
    if let Some(r) = &args.role {
        validate_role_id(r.trim()).map_err(|e| anyhow!("--role: {e}"))?;
    }
    for raw in &args.add_tag {
        parse_tag(raw.trim())?;
    }
    for raw in &args.remove_tag {
        if raw.trim().is_empty() {
            bail!("--remove-tag value must not be empty");
        }
    }
    Ok(())
}

/// Apply the edit deltas to a fetched host object and return the full body
/// to PUT back, plus any `--remove-tag` values that were not on the host
/// (the caller decides whether to warn). Removes run before adds so
/// `--remove-tag old:x --add-tag old:y` replaces in one call.
fn build_edit_body(data: &Value, args: &HostEditArgs) -> anyhow::Result<(Value, Vec<String>)> {
    let mut tags = extract_tags(data);
    let mut missing = Vec::new();

    for raw in &args.remove_tag {
        let tag = raw.trim();
        let before = tags.len();
        tags.retain(|t| t != tag);
        if tags.len() == before {
            missing.push(tag.to_string());
        }
    }
    for raw in &args.add_tag {
        let tag = raw.trim().to_string();
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }

    let mut body = data.clone();
    let obj = body
        .as_object_mut()
        .ok_or_else(|| anyhow!("host data is not an object"))?;
    obj.insert("tags".into(), json!(tags));
    if let Some(new_name) = &args.name {
        obj.insert("name".into(), json!(new_name.trim()));
    }
    if let Some(role) = &args.role {
        obj.insert("roleID".into(), json!(role.trim()));
    } else if args.clear_role {
        obj.insert("roleID".into(), Value::Null);
    }
    Ok((body, missing))
}

/// Edit a host via read-modify-write: GET the current host, apply deltas,
/// PUT the full object back (the v3 PUT is whole-object, not partial).
pub fn hosts_edit(client: &Client, args: &HostEditArgs, json: bool) -> anyhow::Result<()> {
    let id = args.host_id.as_str();
    let res = client.get_host(id)?;
    let data = res
        .get("data")
        .ok_or_else(|| anyhow!("host response missing 'data'"))?;

    let (body, missing_tags) = build_edit_body(data, args)?;
    if !json {
        for tag in &missing_tags {
            eprintln!(
                "warning: tag \"{}\" was not present on the host",
                sanitize_for_display(tag)
            );
        }
    }

    let updated = if body == *data {
        if !json {
            eprintln!("nothing changed — skipping update");
            return Ok(());
        }
        res
    } else {
        client.update_host(id, &body)?
    };
    if json {
        return print_json(&updated);
    }

    let data = &updated["data"];
    let (_, name, ips) = host_fields(data);
    let name = sanitize_for_display(name);
    let ips = sanitize_for_display(&ips);
    if name.is_empty() {
        print!("Updated host {id}");
    } else {
        print!("Updated host \"{name}\" ({id})");
    }
    if !ips.is_empty() {
        print!(" [{ips}]");
    }
    println!();
    match str_field(data, "roleID") {
        "" => println!("  Role: (none)"),
        role => println!("  Role: {}", sanitize_for_display(role)),
    }
    let final_tags = extract_tags(data);
    if final_tags.is_empty() {
        println!("  Tags: (none)");
    }
    for tag in &final_tags {
        println!("  {}", sanitize_for_display(tag));
    }
    Ok(())
}

/// Pull the tags out of a host object as a list of `key:value` strings.
/// The full string is the identity — multiple tags can share a prefix.
fn extract_tags(host: &Value) -> Vec<String> {
    host.get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, Command, HostCommand};

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

    fn edit_args(role: Option<&str>, name: Option<&str>) -> HostEditArgs {
        HostEditArgs {
            host_id: "host-1".to_string(),
            name: name.map(str::to_string),
            role: role.map(str::to_string),
            clear_role: false,
            add_tag: Vec::new(),
            remove_tag: Vec::new(),
        }
    }

    #[test]
    fn build_edit_body_clear_role_sends_null() {
        let mut args = edit_args(None, None);
        args.clear_role = true;
        let data = json!({"id": "host-1", "roleID": "role-old", "tags": ["a:1"]});
        let (body, _) = build_edit_body(&data, &args).unwrap();
        assert!(body["roleID"].is_null());
        assert!(body.as_object().unwrap().contains_key("roleID"));
        assert_eq!(body["tags"], json!(["a:1"]));
    }

    #[test]
    fn build_edit_body_clear_role_on_unassigned_host_is_a_noop() {
        let mut args = edit_args(None, None);
        args.clear_role = true;
        let data = json!({"id": "host-1", "roleID": null, "tags": []});
        let (body, _) = build_edit_body(&data, &args).unwrap();
        assert_eq!(body, data);
    }

    #[test]
    fn edit_preflight_rejects_no_edits_and_names_role_flag() {
        let err = validate_edit_preflight(&edit_args(None, None))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--role"), "{err}");
    }

    #[test]
    fn edit_preflight_names_role_flag_on_bad_role() {
        let err = validate_edit_preflight(&edit_args(Some("role/x"), None))
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("--role:"), "{err}");
    }

    #[test]
    fn edit_preflight_rejects_bad_role_ids() {
        for bad in ["", "  ", "role/abc", "role?x", "role abc"] {
            assert!(
                validate_edit_preflight(&edit_args(Some(bad), None)).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
        assert!(validate_edit_preflight(&edit_args(Some(" role-abc "), None)).is_ok());
    }

    #[test]
    fn build_edit_body_sets_role_and_keeps_other_fields() {
        let data = json!({
            "id": "host-1",
            "name": "web",
            "roleID": "role-old",
            "tags": ["env:prod"],
            "listenPort": 0
        });
        let (body, missing) = build_edit_body(&data, &edit_args(Some(" role-new "), None)).unwrap();
        assert!(missing.is_empty());
        assert_eq!(body["roleID"], "role-new");
        assert_eq!(body["name"], "web");
        assert_eq!(body["tags"], json!(["env:prod"]));
        assert_eq!(body["listenPort"], 0);
    }

    #[test]
    fn build_edit_body_without_role_flag_leaves_role_untouched() {
        let data = json!({"id": "host-1", "roleID": "role-old", "tags": []});
        let (body, _) = build_edit_body(&data, &edit_args(None, Some("renamed"))).unwrap();
        assert_eq!(body["roleID"], "role-old");
        assert_eq!(body["name"], "renamed");
    }

    #[test]
    fn build_edit_body_same_role_is_a_noop() {
        let data = json!({"id": "host-1", "roleID": "role-a", "tags": ["a:1"]});
        let (body, _) = build_edit_body(&data, &edit_args(Some("role-a"), None)).unwrap();
        assert_eq!(body, data);
    }

    #[test]
    fn build_edit_body_reports_missing_removed_tags() {
        let mut args = edit_args(None, None);
        args.remove_tag = vec!["gone:1".to_string(), "a:1".to_string()];
        args.add_tag = vec!["a:2".to_string()];
        let data = json!({"id": "host-1", "tags": ["a:1"]});
        let (body, missing) = build_edit_body(&data, &args).unwrap();
        assert_eq!(missing, vec!["gone:1"]);
        assert_eq!(body["tags"], json!(["a:2"]));
    }

    #[test]
    fn commas_in_tag_values_are_preserved() {
        let cli = Cli::try_parse_from(["dn", "host", "edit", "host-1", "--add-tag", "list:a,b,c"])
            .unwrap();
        let Command::Host {
            command: HostCommand::Edit(args),
        } = cli.command
        else {
            panic!("expected comma in value to survive");
        };
        assert_eq!(args.add_tag, vec!["list:a,b,c"]);
    }
}
