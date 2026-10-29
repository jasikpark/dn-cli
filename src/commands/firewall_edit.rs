//! `role create` / `role edit` and `tag create` / `tag edit`.
//!
//! A role is edited by read-modify-write: `PUT /v1/roles/{id}` replaces
//! the whole role (a field left out is reset), so the current role is read
//! first and sent back with the changes applied. A tag has a partial
//! `PATCH /v1/tags/{tag}`, so only the fields that actually change are
//! sent, and config overrides are never touched.

use anyhow::{anyhow, bail};
use serde_json::{Map, Value, json};

use super::firewall::{render_role, render_tag, rule_role_names};
use super::hosts::parse_tag;
use super::rules::{RuleEdits, apply_rule_edits, parse_rule_spec};
use crate::api::Client;
use crate::cli::{RoleCreateArgs, RoleEditArgs, RuleEditArgs, TagCreateArgs, TagEditArgs};
use crate::ids::validate_id;
use crate::output::{OutputMode, data_object, sanitize_for_display, str_field};

const MAX_DESCRIPTION_CHARS: usize = 255;
const MAX_ROLE_NAME_CHARS: usize = 50;

pub fn validate_role_create_preflight(args: &RoleCreateArgs) -> anyhow::Result<()> {
    let name = args.name.trim();
    if name.is_empty() || name.chars().count() > MAX_ROLE_NAME_CHARS {
        bail!("role name must be 1 to {MAX_ROLE_NAME_CHARS} characters");
    }
    check_description(args.description.as_deref())?;
    parse_specs("--rule", &args.rules)?;
    Ok(())
}

pub fn validate_role_edit_preflight(args: &RoleEditArgs) -> anyhow::Result<()> {
    validate_id("role", args.role_id.trim())?;
    if args.description.is_none() && !has_rule_edits(&args.rules) {
        bail!("nothing to edit — pass --description, --add-rule, --remove-rule, or --clear-rules");
    }
    check_description(args.description.as_deref())?;
    rule_edits(&args.rules)?;
    Ok(())
}

pub fn validate_tag_create_preflight(args: &TagCreateArgs) -> anyhow::Result<()> {
    parse_tag(args.tag.trim())?;
    check_description(args.description.as_deref())?;
    parse_specs("--rule", &args.rules)?;
    check_routes("--route", &args.routes)?;
    check_neighbour("--before", args.before.as_deref())?;
    check_neighbour("--after", args.after.as_deref())?;
    Ok(())
}

pub fn validate_tag_edit_preflight(args: &TagEditArgs) -> anyhow::Result<()> {
    parse_tag(args.tag.trim())?;
    if args.description.is_none()
        && !has_rule_edits(&args.rules)
        && !has_route_edits(args)
        && args.before.is_none()
        && args.after.is_none()
    {
        bail!(
            "nothing to edit — pass --description, --add-rule, --remove-rule, --clear-rules, \
             --add-route, --remove-route, --clear-routes, --before, or --after"
        );
    }
    check_description(args.description.as_deref())?;
    rule_edits(&args.rules)?;
    check_routes("--add-route", &args.add_route)?;
    check_routes("--remove-route", &args.remove_route)?;
    check_neighbour("--before", args.before.as_deref())?;
    check_neighbour("--after", args.after.as_deref())?;
    Ok(())
}

fn check_description(description: Option<&str>) -> anyhow::Result<()> {
    if let Some(d) = description
        && d.chars().count() > MAX_DESCRIPTION_CHARS
    {
        bail!("--description must be at most {MAX_DESCRIPTION_CHARS} characters");
    }
    Ok(())
}

fn check_routes(flag: &str, routes: &[String]) -> anyhow::Result<()> {
    for route in routes {
        validate_id("route", route.trim()).map_err(|e| anyhow!("{flag}: {e}"))?;
    }
    Ok(())
}

fn check_neighbour(flag: &str, tag: Option<&str>) -> anyhow::Result<()> {
    if let Some(tag) = tag {
        parse_tag(tag.trim()).map_err(|e| anyhow!("{flag}: {e}"))?;
    }
    Ok(())
}

fn parse_specs(flag: &str, specs: &[String]) -> anyhow::Result<Vec<Value>> {
    specs
        .iter()
        .map(|spec| parse_rule_spec(spec).map_err(|e| anyhow!("{flag} {spec:?}: {e}")))
        .collect()
}

fn has_rule_edits(args: &RuleEditArgs) -> bool {
    args.clear_rules || !args.add_rule.is_empty() || !args.remove_rule.is_empty()
}

fn has_route_edits(args: &TagEditArgs) -> bool {
    args.clear_routes || !args.add_route.is_empty() || !args.remove_route.is_empty()
}

fn rule_edits(args: &RuleEditArgs) -> anyhow::Result<RuleEdits> {
    Ok(RuleEdits {
        clear: args.clear_rules,
        remove: parse_specs("--remove-rule", &args.remove_rule)?,
        add: parse_specs("--add-rule", &args.add_rule)?,
    })
}

/// The current `firewallRules`, failing on a response without a list: a
/// write built on a guess would silently drop every rule the API holds.
fn current_rules(data: &Value) -> anyhow::Result<&Vec<Value>> {
    data.get("firewallRules")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("unexpected response: firewallRules missing or not a list"))
}

/// Say which `--remove-rule` specs matched nothing, in human mode only.
fn warn_unmatched(output: OutputMode, flag: &str, specs: &[String], unmatched: &[usize]) {
    if output == OutputMode::Human {
        for i in unmatched {
            eprintln!(
                "warning: no rule matched {flag} \"{}\"",
                sanitize_for_display(&specs[*i])
            );
        }
    }
}

pub fn roles_create(
    client: &Client,
    args: &RoleCreateArgs,
    output: OutputMode,
) -> anyhow::Result<()> {
    let body = json!({
        "name": args.name.trim(),
        "description": args.description.as_deref().unwrap_or("").trim(),
        "firewallRules": parse_specs("--rule", &args.rules)?,
    });
    let res = client.create_role(&body)?;
    output.emit(&res, |res| {
        let data = data_object(res, "role")?;
        println!("Created role");
        print!("{}", render_role(data, &rule_role_names(client, data))?);
        Ok(())
    })
}

pub fn roles_edit(client: &Client, args: &RoleEditArgs, output: OutputMode) -> anyhow::Result<()> {
    let id = args.role_id.trim();
    let res = client.get_role(id)?;
    let data = data_object(&res, "role")?;
    let current = current_rules(data)?;

    let (rules, unmatched) = apply_rule_edits(current, &rule_edits(&args.rules)?);
    warn_unmatched(output, "--remove-rule", &args.rules.remove_rule, &unmatched);
    let description = args
        .description
        .as_deref()
        .map_or_else(|| str_field(data, "description"), str::trim);
    let unchanged = description == str_field(data, "description") && rules == *current;
    let body = json!({ "description": description, "firewallRules": rules });

    // A no-op edit still echoes the role under `--json`, so a script sees
    // the same shape either way; a human just hears nothing happened.
    let updated = match (unchanged, output) {
        (true, OutputMode::Human) => {
            eprintln!("nothing changed — skipping update");
            return Ok(());
        }
        (true, OutputMode::Json) => res,
        (false, _) => client.update_role(id, &body)?,
    };
    output.emit(&updated, |updated| {
        let data = data_object(updated, "role")?;
        println!("Updated role");
        print!("{}", render_role(data, &rule_role_names(client, data))?);
        Ok(())
    })
}

pub fn tags_create(
    client: &Client,
    args: &TagCreateArgs,
    output: OutputMode,
) -> anyhow::Result<()> {
    let name = args.tag.trim();
    let mut body = Map::new();
    body.insert("name".into(), json!(name));
    if let Some(d) = &args.description {
        body.insert("description".into(), json!(d.trim()));
    }
    let rules = parse_specs("--rule", &args.rules)?;
    if !rules.is_empty() {
        body.insert("firewallRules".into(), json!(rules));
    }
    if !args.routes.is_empty() {
        body.insert("routeSubscriptions".into(), json!(trimmed(&args.routes)));
    }
    if let Some(before) = &args.before {
        body.insert("before".into(), json!(before.trim()));
    }
    if let Some(after) = &args.after {
        body.insert("after".into(), json!(after.trim()));
    }
    let res = client.create_tag(&Value::Object(body))?;
    output.emit(&res, |res| {
        let data = data_object(res, "tag")?;
        println!("Created tag");
        print!(
            "{}",
            render_tag(data, name, &rule_role_names(client, data))?
        );
        Ok(())
    })
}

pub fn tags_edit(client: &Client, args: &TagEditArgs, output: OutputMode) -> anyhow::Result<()> {
    let name = args.tag.trim();
    let res = client.get_tag(name)?;
    let data = data_object(&res, "tag")?;
    let mut body = Map::new();

    if let Some(d) = &args.description
        && d.trim() != str_field(data, "description")
    {
        body.insert("description".into(), json!(d.trim()));
    }
    if has_rule_edits(&args.rules) {
        let current = current_rules(data)?;
        let (rules, unmatched) = apply_rule_edits(current, &rule_edits(&args.rules)?);
        warn_unmatched(output, "--remove-rule", &args.rules.remove_rule, &unmatched);
        if rules != *current {
            body.insert("firewallRules".into(), json!(rules));
        }
    }
    if has_route_edits(args) {
        let current: Vec<String> = data["routeSubscriptions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        let mut routes = if args.clear_routes {
            Vec::new()
        } else {
            current.clone()
        };
        for gone in trimmed(&args.remove_route) {
            let before = routes.len();
            routes.retain(|r| r != gone);
            if routes.len() == before && output == OutputMode::Human {
                eprintln!("warning: the tag was not subscribed to route \"{gone}\"");
            }
        }
        for new in trimmed(&args.add_route) {
            if !routes.iter().any(|r| r == new) {
                routes.push(new.to_string());
            }
        }
        if routes != current {
            body.insert("routeSubscriptions".into(), json!(routes));
        }
    }
    if let Some(before) = &args.before {
        body.insert("before".into(), json!(before.trim()));
    }
    if let Some(after) = &args.after {
        body.insert("after".into(), json!(after.trim()));
    }

    let updated = match (body.is_empty(), output) {
        (true, OutputMode::Human) => {
            eprintln!("nothing changed — skipping update");
            return Ok(());
        }
        (true, OutputMode::Json) => res,
        (false, _) => client.patch_tag(name, &Value::Object(body))?,
    };
    output.emit(&updated, |updated| {
        let data = data_object(updated, "tag")?;
        println!("Updated tag");
        print!(
            "{}",
            render_tag(data, name, &rule_role_names(client, data))?
        );
        Ok(())
    })
}

fn trimmed(values: &[String]) -> Vec<&str> {
    values.iter().map(|v| v.trim()).collect()
}
