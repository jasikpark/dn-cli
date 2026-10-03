use std::cmp::Reverse;
use std::collections::HashMap;

use anyhow::{anyhow, bail};
use serde_json::Value;

use crate::api::Client;
use crate::cli::{RoleDeleteArgs, RoleGetArgs, TagDeleteArgs, TagGetArgs};
use crate::commands::delete::{DeleteTarget, Described, confirm_and_delete, host_count_detail};
use crate::commands::hosts::validate_role_id;
use crate::output::{
    count_field, print_json, print_list, render_table, sanitize_for_display, str_field,
};

pub fn roles_list(client: &Client, json: bool) -> anyhow::Result<()> {
    let headers = ["ID", "NAME", "RULES", "HOSTS", "DESCRIPTION"];
    print_list(
        &client.list_roles()?,
        json,
        "No roles found.",
        &headers,
        |rows| {
            rows.iter()
                .map(|row| {
                    vec![
                        str_field(row, "id").to_string(),
                        str_field(row, "name").to_string(),
                        count_field(row, "firewallRulesCount"),
                        count_field(row, "hostCount"),
                        str_field(row, "description").to_string(),
                    ]
                })
                .collect()
        },
    )
}

pub fn tags_list(client: &Client, json: bool) -> anyhow::Result<()> {
    let headers = ["NAME", "RULES", "HOSTS", "DESCRIPTION", "PRIORITY"];
    print_list(
        &client.list_tags()?,
        json,
        "No tags found.",
        &headers,
        |rows| {
            // Highest priority first, matching the admin panel's tag list.
            let priority = |row: &Value| row.get("priority").and_then(Value::as_i64);
            let mut rows: Vec<&Value> = rows.iter().collect();
            rows.sort_by_key(|row| Reverse(priority(row)));
            rows.into_iter()
                .map(|row| {
                    vec![
                        str_field(row, "name").to_string(),
                        // The API omits `firewallRulesCount` on tags when it is zero.
                        row["firewallRulesCount"].as_u64().unwrap_or(0).to_string(),
                        count_field(row, "hostCount"),
                        str_field(row, "description").to_string(),
                        priority(row).map(|n| n.to_string()).unwrap_or_default(),
                    ]
                })
                .collect()
        },
    )
}

pub fn roles_get(client: &Client, args: &RoleGetArgs, json: bool) -> anyhow::Result<()> {
    let id = args.role_id.trim();
    validate_role_id(id)?;
    print_rule_holder(client, &client.get_role(id)?, json, "role", render_role)
}

pub fn tags_get(client: &Client, args: &TagGetArgs, json: bool) -> anyhow::Result<()> {
    let name = args.tag.trim();
    print_rule_holder(
        client,
        &client.get_tag(name)?,
        json,
        "tag",
        |data, names| render_tag(data, name, names),
    )
}

/// Delete one role. The confirmation names it and says how many hosts it is
/// assigned to.
pub fn roles_delete(client: &Client, args: &RoleDeleteArgs, json: bool) -> anyhow::Result<()> {
    let id = args.role_id.trim();
    validate_role_id(id)?;
    let target = DeleteTarget {
        kind: "role",
        id,
        json_key: "id",
        read_scope: "roles:read",
    };
    confirm_and_delete(
        &target,
        args.yes,
        json,
        || {
            let data = &client.get_role(id)?["data"];
            Ok(Described {
                name: sanitize_for_display(str_field(data, "name")),
                detail: host_count_detail(data),
            })
        },
        || client.delete_role(id),
    )
}

/// Delete one tag. Tags are named by `key:value`, so the confirmation adds
/// only how many hosts carry it.
pub fn tags_delete(client: &Client, args: &TagDeleteArgs, json: bool) -> anyhow::Result<()> {
    let name = args.tag.trim();
    let target = DeleteTarget {
        kind: "tag",
        id: name,
        json_key: "name",
        read_scope: "tags:read",
    };
    confirm_and_delete(
        &target,
        args.yes,
        json,
        || {
            Ok(Described {
                name: String::new(),
                detail: host_count_detail(&client.get_tag(name)?["data"]),
            })
        },
        || client.delete_tag(name),
    )
}

/// Print a `role get` / `tag get` response: the raw envelope for `--json`,
/// otherwise `render` of its `data` with rule role names resolved.
fn print_rule_holder(
    client: &Client,
    res: &Value,
    json: bool,
    holder: &str,
    render: impl FnOnce(&Value, &HashMap<String, String>) -> anyhow::Result<String>,
) -> anyhow::Result<()> {
    if json {
        return print_json(res);
    }
    let data = res
        .get("data")
        .filter(|d| d.is_object())
        .ok_or_else(|| anyhow!("unexpected response: missing {holder} data"))?;
    print!("{}", render(data, &rule_role_names(client, data))?);
    Ok(())
}

/// Role names for the roles `data.firewallRules` allow, resolved the way
/// the admin panel does. The lookup needs `roles:list`, so a failure
/// degrades to raw ids; no rule naming a role skips it.
fn rule_role_names(client: &Client, data: &Value) -> HashMap<String, String> {
    let references_roles = data
        .get("firewallRules")
        .and_then(Value::as_array)
        .is_some_and(|rules| rules.iter().any(|r| r["allowedRoleID"].is_string()));
    if !references_roles {
        return HashMap::new();
    }
    match client.list_roles() {
        Ok(r) => role_names_by_id(&r),
        Err(e) => {
            let e = sanitize_for_display(&format!("{e:#}"));
            eprintln!("note: showing role ids, not names (roles list failed: {e})");
            HashMap::new()
        }
    }
}

/// Map role id to role name from a `list_roles` response.
fn role_names_by_id(res: &Value) -> HashMap<String, String> {
    res.get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| {
            Some((
                r.get("id")?.as_str()?.to_string(),
                r.get("name")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

/// Render a role and its inbound firewall rules, laid out like the admin
/// panel's rule list: same column order, wording and sort.
///
/// Fails on a `firewallRules` that is missing or not an array, or on a rule
/// whose fields have unexpected types, rather than rendering it: every
/// lenient default here (no role, no tags, any port) would read as a wider
/// rule than the API holds.
fn render_role(data: &Value, role_names: &HashMap<String, String>) -> anyhow::Result<String> {
    let rules = checked_firewall_rules(data)?;

    let mut out = String::new();
    let id = sanitize_for_display(str_field(data, "id"));
    match sanitize_for_display(str_field(data, "name")) {
        name if name.is_empty() => out.push_str(&format!("{id}\n")),
        name => out.push_str(&format!("{name} ({id})\n")),
    }
    push_description_and_hosts(&mut out, data);
    push_rules(
        &mut out,
        data,
        rules,
        role_names,
        "role",
        "this role allows no inbound traffic. Rules on a host's tags can still allow some.",
    );
    Ok(out)
}

/// Render a tag and the inbound firewall rules it adds to every host that
/// carries it, with the same layout and strictness as [`render_role`].
/// A response without a name falls back to `requested`, the name asked for.
fn render_tag(
    data: &Value,
    requested: &str,
    role_names: &HashMap<String, String>,
) -> anyhow::Result<String> {
    let rules = checked_firewall_rules(data)?;

    let returned = str_field(data, "name");
    let shown = sanitize_for_display(returned);
    let mut out = match shown.trim() {
        "" => format!("{}\n", sanitize_for_display(requested)),
        _ => format!("{shown}\n"),
    };
    if !shown.trim().is_empty() && returned != requested {
        out.push_str(&format!(
            "Warning: asked for \"{}\", but the server returned this tag.\n",
            sanitize_for_display(requested)
        ));
    }
    push_description_and_hosts(&mut out, data);
    if let Some(n) = data.get("priority").and_then(Value::as_i64) {
        out.push_str(&format!("Priority: {n}\n"));
    }
    push_rules(
        &mut out,
        data,
        rules,
        role_names,
        "tag",
        "this tag adds no inbound traffic. The host's role and other tags still apply.",
    );
    Ok(out)
}

/// The rules section shared by role and tag views: a warning when
/// `firewallRulesCount` disagrees with the rules listed (the table would show
/// fewer or more than the API holds), `none` when there are no rules,
/// otherwise an allow-everything warning and the rule table sorted like the
/// admin panel. `holder` names what carries the rules: "role" or "tag".
fn push_rules(
    out: &mut String,
    data: &Value,
    rules: &[Value],
    role_names: &HashMap<String, String>,
    holder: &str,
    none: &str,
) {
    if let Some(count) = data["firewallRulesCount"].as_u64()
        && count != rules.len() as u64
    {
        out.push_str(&format!(
            "\nWarning: the response counts {count} firewall rules but lists {}; \
             this view may be incomplete.\n",
            rules.len()
        ));
    }
    if rules.is_empty() {
        out.push_str(&format!("\nNo firewall rules: {none}\n"));
        return;
    }
    // Rules add up across a host's role and tags, so one allow-everything
    // rule opens the host whatever else applies — worth saying even alone.
    if rules.iter().any(is_allow_everything_rule) {
        out.push_str(&format!(
            "\nWarning: a rule allows all hosts on any protocol and port, \
             so every host with this {holder} accepts all inbound traffic.\n"
        ));
        if rules.len() > 1 {
            out.push_str("The more specific rules have no effect.\n");
        }
    }
    let mut sorted: Vec<&Value> = rules.iter().collect();
    sorted.sort_by(|a, b| compare_firewall_rules(a, b));
    let rows: Vec<Vec<String>> = sorted
        .into_iter()
        .map(|r| firewall_rule_row(r, role_names))
        .collect();
    out.push('\n');
    out.push_str(&render_table(
        &["ALLOWED HOSTS", "PROTOCOL", "PORTS", "DESCRIPTION"],
        &rows,
    ));
}

/// `data.firewallRules`, failing on a missing or non-list value or on a
/// rule [`check_firewall_rule`] rejects.
fn checked_firewall_rules(data: &Value) -> anyhow::Result<&Vec<Value>> {
    let rules = data
        .get("firewallRules")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("unexpected response: firewallRules missing or not a list"))?;
    for (i, rule) in rules.iter().enumerate() {
        check_firewall_rule(rule)
            .map_err(|e| anyhow!("unexpected response: firewall rule {i}: {e}"))?;
    }
    Ok(rules)
}

fn push_description_and_hosts(out: &mut String, data: &Value) {
    let description = sanitize_for_display(str_field(data, "description"));
    if !description.trim().is_empty() {
        out.push_str(&format!("{description}\n"));
    }
    if let Some(n) = data.get("hostCount").and_then(Value::as_u64) {
        out.push_str(&format!("Hosts: {n}\n"));
    }
}

/// Check the shape of one firewall rule: `protocol` one of `ANY`, `TCP`,
/// `UDP`, `ICMP`; `allowedRoleID` present and null or a non-empty string;
/// `allowedTags` absent, null, or a list of strings; `portRange` present and
/// null or `{from, to}` with `from <= to <= 65535`. A missing key would
/// otherwise read as null, i.e. all hosts or every port.
fn check_firewall_rule(rule: &Value) -> anyhow::Result<()> {
    if !rule.is_object() {
        bail!("not an object");
    }
    match rule["protocol"].as_str() {
        Some("ANY" | "TCP" | "UDP" | "ICMP") => {}
        _ => bail!("protocol is not ANY, TCP, UDP or ICMP"),
    }
    match rule.get("allowedRoleID") {
        Some(Value::Null) => {}
        Some(Value::String(id)) if !id.is_empty() => {}
        _ => bail!("allowedRoleID is not null or a role id"),
    }
    match rule.get("allowedTags") {
        None | Some(Value::Null) => {}
        Some(Value::Array(tags)) if tags.iter().all(Value::is_string) => {}
        _ => bail!("allowedTags is not null or a list of strings"),
    }
    match rule.get("portRange") {
        Some(Value::Null) => {}
        Some(r) => match (r["from"].as_u64(), r["to"].as_u64()) {
            (Some(from), Some(to)) if from <= to && to <= 65535 => {}
            _ => bail!("portRange is not null or {{from, to}} with from <= to <= 65535"),
        },
        None => bail!("portRange is missing"),
    }
    Ok(())
}

/// The rule's port range, or `None` when it covers every port: a null
/// range, an ICMP rule (Nebula ignores ports there), or a range starting at
/// 0 (Nebula's any-port value, which also discards the end port).
fn rule_ports(rule: &Value) -> Option<(u64, u64)> {
    if rule["protocol"].as_str() == Some("ICMP") {
        return None;
    }
    let r = rule.get("portRange").filter(|r| !r.is_null())?;
    match (r["from"].as_u64(), r["to"].as_u64()) {
        (Some(0), _) => None,
        (Some(from), Some(to)) => Some((from, to)),
        _ => None,
    }
}

fn rule_tags(rule: &Value) -> Vec<&str> {
    rule.get("allowedTags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// Port-range width (`to - from`) for sorting; a rule covering every port
/// is widest.
fn rule_port_width(rule: &Value) -> u64 {
    rule_ports(rule).map_or(u64::MAX, |(from, to)| to.saturating_sub(from))
}

/// The admin panel's rule order: protocol, then all-hosts rules before
/// role-scoped ones, then wider port ranges first, then untagged rules
/// first and more tags before fewer. Ties keep API order (`sort_by` is
/// stable).
fn compare_firewall_rules(a: &Value, b: &Value) -> std::cmp::Ordering {
    let protocol = |r: &Value| r["protocol"].as_str().unwrap_or_default().to_string();
    let has_role = |r: &Value| r["allowedRoleID"].is_string();
    let tag_rank = |r: &Value| match rule_tags(r).len() {
        0 => (0, 0),
        n => (1, usize::MAX - n),
    };
    protocol(a)
        .cmp(&protocol(b))
        .then_with(|| has_role(a).cmp(&has_role(b)))
        .then_with(|| rule_port_width(b).cmp(&rule_port_width(a)))
        .then_with(|| tag_rank(a).cmp(&tag_rank(b)))
}

/// Any protocol, any port, any host, no tags: every other rule is redundant.
fn is_allow_everything_rule(rule: &Value) -> bool {
    rule["protocol"].as_str() == Some("ANY")
        && rule_ports(rule).is_none()
        && !rule["allowedRoleID"].is_string()
        && rule_tags(rule).is_empty()
}

/// One `role get` / `tag get` table row: allowed hosts, protocol, ports, description.
///
/// Allowed hosts reads like the admin panel — `All hosts` or `"<role>" hosts`,
/// then `tagged "a" + "b"` when tags narrow it (a host needs every tag).
/// Names and tags are quoted so neither can pass for the fixed wording (a
/// role named `All`, a tag containing ` + `); an unknown or empty role name
/// falls back to the id. Ports is `any` when the rule covers every port
/// (see [`rule_ports`]) and a single port when `from == to`.
fn firewall_rule_row(rule: &Value, role_names: &HashMap<String, String>) -> Vec<String> {
    let mut hosts = match rule["allowedRoleID"].as_str() {
        None => "All hosts".to_string(),
        Some(id) => {
            let name = role_names
                .get(id)
                .map(String::as_str)
                .filter(|n| !n.trim().is_empty())
                .unwrap_or(id);
            format!("{name:?} hosts")
        }
    };
    let tags = rule_tags(rule);
    if !tags.is_empty() {
        hosts.push_str(" tagged ");
        let quoted: Vec<String> = tags.iter().map(|t| format!("{t:?}")).collect();
        hosts.push_str(&quoted.join(" + "));
    }

    let protocol = match rule["protocol"].as_str().unwrap_or_default() {
        "ANY" => "Any".to_string(),
        p => p.to_string(),
    };

    let ports = match rule_ports(rule) {
        None => "any".to_string(),
        Some((from, to)) if from == to => from.to_string(),
        Some((from, to)) => format!("{from}-{to}"),
    };

    let description = rule["description"].as_str().unwrap_or_default().to_string();

    vec![hosts, protocol, ports, description]
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rule(role: Option<&str>, tags: &[&str], protocol: &str, ports: Option<(u64, u64)>) -> Value {
        json!({
            "allowedRoleID": role,
            "allowedTags": if tags.is_empty() { Value::Null } else { json!(tags) },
            "protocol": protocol,
            "portRange": ports.map(|(from, to)| json!({"from": from, "to": to})),
            "description": "",
        })
    }

    #[test]
    fn firewall_rule_row_renders_all_hosts_and_any_port() {
        assert_eq!(
            firewall_rule_row(&rule(None, &[], "ANY", None), &HashMap::new()),
            ["All hosts", "Any", "any", ""]
        );
    }

    #[test]
    fn firewall_rule_row_joins_tags_with_plus() {
        assert_eq!(
            firewall_rule_row(
                &rule(None, &["team:ops", "os:linux"], "TCP", Some((22, 22))),
                &HashMap::new()
            ),
            [
                "All hosts tagged \"team:ops\" + \"os:linux\"",
                "TCP",
                "22",
                ""
            ]
        );
    }

    #[test]
    fn firewall_rule_row_names_role_and_falls_back_to_id() {
        let names = HashMap::from([("role-ABC".to_string(), "Servers".to_string())]);
        let r = rule(Some("role-ABC"), &["env:prod"], "UDP", Some((5000, 5010)));
        assert_eq!(
            firewall_rule_row(&r, &names),
            [
                "\"Servers\" hosts tagged \"env:prod\"",
                "UDP",
                "5000-5010",
                ""
            ]
        );
        assert_eq!(
            firewall_rule_row(&r, &HashMap::new())[0],
            "\"role-ABC\" hosts tagged \"env:prod\""
        );
    }

    #[test]
    fn compare_firewall_rules_matches_admin_panel_order() {
        // Input in API order, shuffled; expected order is the admin panel's.
        let mut rules = vec![
            rule(None, &["os:linux"], "UDP", Some((21116, 21116))),
            rule(None, &["os:linux"], "TCP", Some((222, 222))),
            rule(Some("role-B"), &[], "ANY", None),
            rule(None, &["os:linux"], "TCP", Some((21114, 21119))),
            rule(None, &[], "ICMP", None),
            rule(None, &["os:linux"], "UDP", Some((60000, 61000))),
            rule(None, &["os:linux", "team:ops"], "ANY", None),
            rule(None, &[], "ANY", None),
            rule(None, &["team:ops"], "ANY", None),
        ];
        rules.sort_by(compare_firewall_rules);
        let rows: Vec<String> = rules
            .iter()
            .map(|r| firewall_rule_row(r, &HashMap::new()).join(" | "))
            .collect();
        assert_eq!(
            rows,
            [
                "All hosts | Any | any | ",
                "All hosts tagged \"os:linux\" + \"team:ops\" | Any | any | ",
                "All hosts tagged \"team:ops\" | Any | any | ",
                "\"role-B\" hosts | Any | any | ",
                "All hosts | ICMP | any | ",
                "All hosts tagged \"os:linux\" | TCP | 21114-21119 | ",
                "All hosts tagged \"os:linux\" | TCP | 222 | ",
                "All hosts tagged \"os:linux\" | UDP | 60000-61000 | ",
                "All hosts tagged \"os:linux\" | UDP | 21116 | ",
            ]
        );
    }

    #[test]
    fn render_role_warns_on_allow_everything_rule() {
        let data = json!({
            "id": "role-A", "name": "Servers", "description": "", "hostCount": 2,
            "firewallRules": [rule(None, &[], "ANY", None), rule(None, &[], "TCP", Some((22, 22)))],
        });
        let out = render_role(&data, &HashMap::new()).unwrap();
        assert!(out.starts_with("Servers (role-A)\nHosts: 2\n"), "{out}");
        assert!(out.contains("Warning: a rule allows all hosts"), "{out}");
        assert!(out.contains("every host with this role"), "{out}");
        assert!(
            out.contains("The more specific rules have no effect."),
            "{out}"
        );
    }

    #[test]
    fn render_role_no_warning_when_allow_all_is_tagged() {
        let data = json!({
            "id": "role-A", "name": "Servers",
            "firewallRules": [rule(None, &["team:ops"], "ANY", None)],
        });
        let out = render_role(&data, &HashMap::new()).unwrap();
        assert!(!out.contains("Warning"), "{out}");
    }

    #[test]
    fn render_role_reports_deny_all_only_for_explicit_empty_rules() {
        let empty = json!({"id": "role-A", "name": "", "firewallRules": []});
        let out = render_role(&empty, &HashMap::new()).unwrap();
        assert_eq!(
            out,
            "role-A\n\nNo firewall rules: this role allows no inbound traffic. \
             Rules on a host's tags can still allow some.\n"
        );
        for bad in [
            json!({"id": "role-A"}),
            json!({"id": "role-A", "firewallRules": null}),
        ] {
            assert!(render_role(&bad, &HashMap::new()).is_err(), "{bad}");
        }
    }

    #[test]
    fn render_role_rejects_rules_that_would_read_wider_than_they_are() {
        let bad_rules = [
            json!("not a rule"),
            json!({"protocol": "TCP", "allowedRoleID": 7}),
            json!({"protocol": "TCP", "allowedRoleID": ""}),
            json!({"protocol": "TCP", "allowedTags": "team:ops"}),
            json!({"protocol": "TCP", "allowedTags": [1]}),
            json!({"protocol": "TCP", "portRange": {"from": 22}}),
            json!({"protocol": null}),
            json!({"protocol": "any", "allowedRoleID": null, "portRange": null}),
            json!({"protocol": "", "allowedRoleID": null, "portRange": null}),
            json!({"protocol": "TCP", "portRange": null}),
            json!({"protocol": "TCP", "allowedRoleID": null}),
            json!({"protocol": "TCP", "allowedRoleID": null, "portRange": {"from": 30, "to": 20}}),
            json!({"protocol": "TCP", "allowedRoleID": null, "portRange": {"from": 1, "to": 70000}}),
        ];
        for bad in bad_rules {
            let data = json!({"id": "role-A", "name": "A", "firewallRules": [bad]});
            let err = render_role(&data, &HashMap::new()).unwrap_err().to_string();
            assert!(err.contains("firewall rule 0"), "{bad}: {err}");
        }
    }

    #[test]
    fn firewall_rule_row_quotes_role_name_so_it_cannot_pass_for_all_hosts() {
        let names = HashMap::from([
            ("role-A".to_string(), "All".to_string()),
            ("role-B".to_string(), " ".to_string()),
        ]);
        let row = |id| firewall_rule_row(&rule(Some(id), &[], "TCP", None), &names)[0].clone();
        assert_eq!(row("role-A"), "\"All\" hosts");
        assert_eq!(row("role-B"), "\"role-B\" hosts");
    }

    #[test]
    fn port_zero_and_icmp_rules_cover_every_port() {
        let names = HashMap::new();
        for r in [
            rule(None, &[], "TCP", Some((0, 0))),
            rule(None, &[], "TCP", Some((0, 100))),
            rule(None, &[], "ICMP", Some((22, 22))),
        ] {
            assert_eq!(firewall_rule_row(&r, &names)[2], "any", "{r}");
            assert_eq!(rule_port_width(&r), u64::MAX, "{r}");
        }
        assert!(is_allow_everything_rule(&rule(
            None,
            &[],
            "ANY",
            Some((0, 0))
        )));
    }

    #[test]
    fn render_role_warns_on_a_lone_allow_everything_rule() {
        let data = json!({
            "id": "role-A", "name": "A", "firewallRules": [rule(None, &[], "ANY", None)],
        });
        let out = render_role(&data, &HashMap::new()).unwrap();
        assert!(
            out.contains("every host with this role accepts all inbound traffic"),
            "{out}"
        );
        assert!(!out.contains("more specific"), "{out}");
    }

    #[test]
    fn render_role_skips_blank_description() {
        let data = json!({
            "id": "role-A", "name": "A", "description": "\u{7}\u{1b}", "firewallRules": []
        });
        let out = render_role(&data, &HashMap::new()).unwrap();
        assert!(
            out.starts_with("A (role-A)\n\nNo firewall rules"),
            "{out:?}"
        );
    }

    #[test]
    fn role_names_by_id_skips_incomplete_rows() {
        let res = json!({"data": [
            {"id": "role-A", "name": "Servers"},
            {"id": "role-B"},
            {"name": "orphan"},
        ]});
        assert_eq!(
            role_names_by_id(&res),
            HashMap::from([("role-A".to_string(), "Servers".to_string())])
        );
    }

    #[test]
    fn render_tag_shows_header_and_sorted_rules() {
        let tag = json!({
            "name": "env:prod",
            "description": "Production hosts",
            "hostCount": 3,
            "priority": 6,
            "firewallRules": [
                rule(Some("role-ADM"), &[], "TCP", Some((22, 22))),
                rule(None, &[], "ICMP", None),
            ],
        });
        let names = HashMap::from([("role-ADM".to_string(), "Admins".to_string())]);
        let out = render_tag(&tag, "env:prod", &names).unwrap();
        assert!(
            out.starts_with("env:prod\nProduction hosts\nHosts: 3\nPriority: 6\n\n"),
            "{out}"
        );
        let icmp = out.find("All hosts").unwrap();
        let ssh = out.find("\"Admins\" hosts").unwrap();
        assert!(icmp < ssh, "ICMP sorts before TCP:\n{out}");
    }

    #[test]
    fn render_tag_empty_rules_defers_to_role_and_rejects_missing_rules() {
        let empty = json!({"name": "env:dev", "firewallRules": []});
        assert_eq!(
            render_tag(&empty, "env:dev", &HashMap::new()).unwrap(),
            "env:dev\n\nNo firewall rules: this tag adds no inbound traffic. \
             The host's role and other tags still apply.\n"
        );
        assert!(render_tag(&json!({"name": "env:dev"}), "env:dev", &HashMap::new()).is_err());
    }

    #[test]
    fn render_tag_falls_back_to_requested_name() {
        for data in [
            json!({"firewallRules": []}),
            json!({"name": "\u{7}", "firewallRules": []}),
        ] {
            let out = render_tag(&data, "env:dev", &HashMap::new()).unwrap();
            assert!(out.starts_with("env:dev\n"), "{out}");
        }
    }

    #[test]
    fn render_tag_flags_a_name_other_than_the_one_requested() {
        let tag = json!({"name": "env:other", "firewallRules": []});
        let out = render_tag(&tag, "env:prod", &HashMap::new()).unwrap();
        assert!(
            out.starts_with("env:other\nWarning: asked for \"env:prod\""),
            "{out}"
        );
        let same = json!({"name": "env:prod", "firewallRules": []});
        let out = render_tag(&same, "env:prod", &HashMap::new()).unwrap();
        assert!(!out.contains("Warning"), "{out}");
    }

    #[test]
    fn render_tag_flags_a_rules_count_mismatch() {
        let tag = json!({"name": "env:prod", "firewallRulesCount": 2, "firewallRules": []});
        let out = render_tag(&tag, "env:prod", &HashMap::new()).unwrap();
        assert!(out.contains("counts 2 firewall rules but lists 0"), "{out}");
        let tag = json!({
            "name": "env:prod", "firewallRulesCount": 1,
            "firewallRules": [rule(None, &[], "ICMP", None)],
        });
        let out = render_tag(&tag, "env:prod", &HashMap::new()).unwrap();
        assert!(!out.contains("Warning"), "{out}");
    }

    #[test]
    fn render_tag_warns_on_a_lone_allow_everything_rule() {
        let tag = json!({"name": "env:prod", "firewallRules": [rule(None, &[], "ANY", None)]});
        let out = render_tag(&tag, "env:prod", &HashMap::new()).unwrap();
        assert!(
            out.contains("every host with this tag accepts all inbound traffic"),
            "{out}"
        );
    }
}
