//! `route list` and `route get`: the routes hosts can subscribe to through
//! their tags, each a router host plus the IPv4 ranges it forwards for.

use std::collections::HashMap;

use serde_json::Value;

use super::firewall::{
    checked_firewall_rules, compare_firewall_rules, firewall_rule_row, is_allow_everything_rule,
    print_rule_holder,
};
use crate::api::Client;
use crate::cli::{PageArgs, RouteGetArgs};
use crate::ids::validate_id;
use crate::output::{
    OutputMode, count_field, print_list, render_details, render_table, sanitize_for_display,
    str_field,
};

pub fn routes_list(client: &Client, page: &PageArgs, output: OutputMode) -> anyhow::Result<()> {
    let headers = ["ID", "NAME", "ROUTER HOST", "CIDRS", "RULES", "DESCRIPTION"];
    print_list(
        &client.list_routes(page)?,
        output,
        "No routes found.",
        &headers,
        |rows| {
            rows.iter()
                .map(|row| {
                    vec![
                        str_field(row, "id").to_string(),
                        str_field(row, "name").to_string(),
                        str_field(row, "routerHostID").to_string(),
                        routable_cidrs(row).join(", "),
                        count_field(row, "firewallRulesCount"),
                        str_field(row, "description").to_string(),
                    ]
                })
                .collect()
        },
    )
}

pub fn routes_get(client: &Client, args: &RouteGetArgs, output: OutputMode) -> anyhow::Result<()> {
    let id = args.route_id.trim();
    validate_id("route", id)?;
    print_rule_holder(
        client,
        &client.get_route(id)?,
        output,
        "route",
        render_route,
    )
}

/// The route's `routableCIDRs` keys, each marked when hosts don't install
/// it (`install: false` means the range is only reachable, not routed on
/// the subscribing host). Keys come back in API order.
fn routable_cidrs(data: &Value) -> Vec<String> {
    data.get("routableCIDRs")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(
            |(cidr, v)| match v.get("install").and_then(Value::as_bool) {
                Some(false) => format!("{cidr} (not installed)"),
                _ => cidr.to_string(),
            },
        )
        .collect()
}

/// Render a route: its name, router host, routable ranges, then the inbound
/// rules its router accepts on each local range, laid out like a role's
/// rules with a LOCAL CIDR column in front. The same strictness applies:
/// a rule this code can't read is an error, not a wider rule.
fn render_route(data: &Value, role_names: &HashMap<String, String>) -> anyhow::Result<String> {
    let rules = checked_firewall_rules(data)?;
    // The shared check covers the rule's source and ports; a route rule
    // also has a destination, which a blank cell would misreport as "all".
    for (i, rule) in rules.iter().enumerate() {
        if rule
            .get("localCIDR")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            anyhow::bail!(
                "unexpected response: firewall rule {i}: localCIDR missing or not a string"
            );
        }
    }

    let id = sanitize_for_display(str_field(data, "id"));
    let mut out = match sanitize_for_display(str_field(data, "name")) {
        name if name.trim().is_empty() => format!("{id}\n"),
        name => format!("{name} ({id})\n"),
    };
    out.push_str(&render_details(&[
        ("Description", str_field(data, "description").to_string()),
        ("ID", id),
        (
            "Router host",
            match data.get("routerHostID").and_then(Value::as_str) {
                Some(host) => host.to_string(),
                None => "none".to_string(),
            },
        ),
        ("Routable CIDRs", routable_cidrs(data).join(", ")),
        ("Created", str_field(data, "createdAt").to_string()),
    ]));

    if rules.is_empty() {
        out.push_str(
            "\nNo firewall rules: the router host accepts no inbound traffic for these ranges.\n",
        );
        return Ok(out);
    }
    if rules.iter().any(is_allow_everything_rule) {
        out.push_str(
            "\nWarning: a rule allows all hosts on any protocol and port into its local CIDR.\n",
        );
    }
    let mut sorted: Vec<&Value> = rules.iter().collect();
    sorted.sort_by(|a, b| {
        let cidr = |r: &Value| r["localCIDR"].as_str().unwrap_or_default().to_string();
        cidr(a)
            .cmp(&cidr(b))
            .then_with(|| compare_firewall_rules(a, b))
    });
    let rows: Vec<Vec<String>> = sorted
        .into_iter()
        .map(|rule| {
            let mut row = vec![str_field(rule, "localCIDR").to_string()];
            row.extend(firewall_rule_row(rule, role_names));
            row
        })
        .collect();
    out.push('\n');
    out.push_str(&render_table(
        &[
            "LOCAL CIDR",
            "ALLOWED HOSTS",
            "PROTOCOL",
            "PORTS",
            "DESCRIPTION",
        ],
        &rows,
    ));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn routable_cidrs_marks_ranges_hosts_do_not_install() {
        let data = json!({"routableCIDRs": {
            "192.168.14.0/26": {"install": true},
            "10.0.0.0/8": {"install": false},
            "172.16.0.0/12": {}
        }});
        assert_eq!(
            routable_cidrs(&data),
            [
                "192.168.14.0/26",
                "10.0.0.0/8 (not installed)",
                "172.16.0.0/12"
            ]
        );
        assert!(routable_cidrs(&json!({})).is_empty());
    }

    #[test]
    fn render_route_lists_ranges_then_rules_by_local_cidr() {
        let data = json!({"id": "route-WWEWSRIBWD77UALE2F3BIOXCFM", "name": "Office LAN", "description": "to the printers",
        "routerHostID": "host-ESTNM4GWPFZRIZVV3WT63CHS4E", "createdAt": "2024-03-15T13:59:09Z",
        "routableCIDRs": {"192.168.14.0/26": {"install": true}},
        "firewallRules": [
            {"localCIDR": "192.168.14.56/32", "protocol": "TCP", "portRange": {"from": 22, "to": 22},
             "allowedRoleID": "role-TBY4VAJYZPCHTUL7AEEJSBZA6I", "allowedTags": null, "description": "ssh to the printer"},
            {"localCIDR": "192.168.14.0/26", "protocol": "ICMP", "portRange": null,
             "allowedRoleID": null, "allowedTags": null, "description": "ping"}
        ]});
        let names = HashMap::from([(
            "role-TBY4VAJYZPCHTUL7AEEJSBZA6I".to_string(),
            "Admins".to_string(),
        )]);
        let shown = render_route(&data, &names).unwrap();
        assert!(
            shown.starts_with("Office LAN (route-WWEWSRIBWD77UALE2F3BIOXCFM)\n"),
            "{shown}"
        );
        assert!(
            shown.contains("Router host:     host-ESTNM4GWPFZRIZVV3WT63CHS4E\n"),
            "{shown}"
        );
        assert!(
            shown.contains("Routable CIDRs:  192.168.14.0/26\n"),
            "{shown}"
        );
        let ping = shown.find("192.168.14.0/26   All hosts").unwrap();
        let ssh = shown.find("192.168.14.56/32  \"Admins\" hosts").unwrap();
        assert!(ping < ssh, "{shown}");
    }

    #[test]
    fn render_route_without_a_router_or_rules_says_so() {
        let data = json!({"id": "route-WWEWSRIBWD77UALE2F3BIOXCFM", "name": "", "description": "", "routerHostID": null,
            "routableCIDRs": {}, "firewallRules": []});
        let shown = render_route(&data, &HashMap::new()).unwrap();
        assert!(
            shown.starts_with("route-WWEWSRIBWD77UALE2F3BIOXCFM\n"),
            "{shown}"
        );
        assert!(shown.contains("Router host:  none\n"), "{shown}");
        assert!(shown.contains("No firewall rules"), "{shown}");
    }

    #[test]
    fn render_route_refuses_a_rule_it_cannot_read() {
        let rule = |local: serde_json::Value| {
            let mut r = json!({"protocol": "TCP", "portRange": null, "allowedRoleID": null,
                               "allowedTags": null, "description": ""});
            if !local.is_null() {
                r["localCIDR"] = local;
            }
            json!({"id": "route-WWEWSRIBWD77UALE2F3BIOXCFM", "firewallRules": [r]})
        };
        assert!(render_route(&rule(json!("10.0.0.0/8")), &HashMap::new()).is_ok());
        for bad in [
            json!({"id": "route-WWEWSRIBWD77UALE2F3BIOXCFM", "firewallRules": [{"protocol": "FOO"}]}),
            rule(json!(null)),
            rule(json!("")),
            rule(json!(7)),
        ] {
            let err = render_route(&bad, &HashMap::new()).unwrap_err().to_string();
            assert!(
                err.contains("unexpected response: firewall rule 0"),
                "{err}"
            );
        }
    }
}
