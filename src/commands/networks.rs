use serde_json::Value;

use crate::api::Client;
use crate::cli::{NetworkDeleteArgs, NetworkGetArgs};
use crate::commands::delete::{DeleteTarget, Described, confirm_and_delete, host_count_detail};
use crate::ids::validate_id;
use crate::output::{
    count_field, data_object, joined_field, print_json, print_list, render_details,
    sanitize_for_display, str_field,
};

pub fn networks_list(client: &Client, json: bool) -> anyhow::Result<()> {
    let headers = [
        "ID",
        "NAME",
        "CIDRS",
        "HOSTS",
        "MANAGED LH",
        "LH AS RELAYS",
        "CURVE",
        "CERT",
        "DESCRIPTION",
    ];
    print_list(
        &client.list_networks()?,
        json,
        "No networks found.",
        &headers,
        |rows| rows.iter().map(|r| network_row(r).to_vec()).collect(),
    )
}

pub fn networks_get(client: &Client, args: &NetworkGetArgs, json: bool) -> anyhow::Result<()> {
    let id = args.network_id.trim();
    validate_id("network", id)?;
    let res = client.get_network(id)?;
    if json {
        return print_json(&res);
    }
    print!("{}", render_network(data_object(&res, "network")?));
    Ok(())
}

/// The human view of a v2 network: its name, then the `network list` columns
/// as aligned `label: value` lines, plus the signing CA and creation time.
fn render_network(data: &Value) -> String {
    let [
        id,
        name,
        cidrs,
        hosts,
        managed,
        lh_relays,
        curve,
        cert,
        description,
    ] = network_row(data);
    let mut out = match sanitize_for_display(&name).trim() {
        "" => format!("{}\n", sanitize_for_display(&id)),
        shown => format!("{shown}\n"),
    };
    out.push_str(&render_details(&[
        ("Description", description),
        ("ID", id),
        ("CIDRs", cidrs),
        ("Hosts", hosts),
        ("Managed lighthouses", managed),
        ("Lighthouses as relays", lh_relays),
        ("Curve", curve),
        ("Cert version", cert),
        ("Signing CA", str_field(data, "signingCAID").to_string()),
        ("Created", str_field(data, "createdAt").to_string()),
    ]));
    out
}

/// Delete one network. The API refuses while it still has hosts, so the
/// confirmation shows the host count alongside the name.
pub fn networks_delete(
    client: &Client,
    args: &NetworkDeleteArgs,
    json: bool,
) -> anyhow::Result<()> {
    let id = args.network_id.trim();
    validate_id("network", id)?;
    let target = DeleteTarget {
        kind: "network",
        id,
        json_key: "id",
        read_scope: "networks:read",
    };
    confirm_and_delete(
        &target,
        args.yes,
        json,
        || {
            let data = &client.get_network(id)?["data"];
            Ok(Described {
                name: sanitize_for_display(str_field(data, "name")),
                detail: host_count_detail(data),
            })
        },
        || client.delete_network(id),
    )
}

/// The columns the human network table renders. Strings fall back to empty
/// when absent or non-string; `cidrs` joins the overlay prefixes (an IPv6
/// one and, on dual-stack networks, an IPv4 one) the way the host table joins
/// IPs. Managed lighthouses are Defined's hosted fleet and never appear in
/// `host list`, so this table is where that setting is visible; the API
/// stores it inverted (`disableManagedLighthouses`) and the column reports it
/// the way the admin panel does — whether managed lighthouses are on.
fn network_row(row: &Value) -> [String; 9] {
    let yes_no = |key, invert: bool| {
        row.get(key)
            .and_then(Value::as_bool)
            .map(|b| if b != invert { "yes" } else { "no" }.to_string())
            .unwrap_or_default()
    };
    let cert = row
        .get("certVersion")
        .and_then(Value::as_u64)
        .map(|v| format!("v{v}"))
        .unwrap_or_default();
    [
        str_field(row, "id").to_string(),
        str_field(row, "name").to_string(),
        joined_field(row, "cidrs"),
        count_field(row, "hostCount"),
        yes_no("disableManagedLighthouses", true),
        yes_no("lighthousesAsRelays", false),
        str_field(row, "curve").to_string(),
        cert,
        str_field(row, "description").to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn network_row_renders_dual_stack_network() {
        let row = json!({
            "id": "network-EXAMPLE",
            "name": "office",
            "description": "main site",
            "cidrs": ["fd00:c0:c0::/80", "100.100.0.0/22"],
            "hostCount": 14,
            "disableManagedLighthouses": false,
            "lighthousesAsRelays": true,
            "curve": "25519",
            "certVersion": 2,
        });
        assert_eq!(
            network_row(&row),
            [
                "network-EXAMPLE",
                "office",
                "fd00:c0:c0::/80, 100.100.0.0/22",
                "14",
                "yes",
                "yes",
                "25519",
                "v2",
                "main site",
            ]
        );
    }

    #[test]
    fn render_network_shows_every_field() {
        let data = json!({
            "id": "network-EXAMPLE",
            "signingCAID": "ca-EXAMPLE",
            "name": "office",
            "description": "main site",
            "cidrs": ["100.100.0.0/22", "fd00:c0:c0::/80"],
            "certVersion": 2,
            "hostCount": 12,
            "lighthousesAsRelays": false,
            "disableManagedLighthouses": false,
            "curve": "25519",
            "createdAt": "2023-02-14T20:34:59Z"
        });
        assert_eq!(
            render_network(&data),
            "office\n\
             Description:            main site\n\
             ID:                     network-EXAMPLE\n\
             CIDRs:                  100.100.0.0/22, fd00:c0:c0::/80\n\
             Hosts:                  12\n\
             Managed lighthouses:    yes\n\
             Lighthouses as relays:  no\n\
             Curve:                  25519\n\
             Cert version:           v2\n\
             Signing CA:             ca-EXAMPLE\n\
             Created:                2023-02-14T20:34:59Z\n"
        );
    }

    #[test]
    fn render_network_sanitizes_an_id_used_as_the_title() {
        let out = render_network(&json!({"id": "network-\u{1b}[31m"}));
        assert!(out.starts_with("network- [31m\n"), "{out:?}");
    }

    #[test]
    fn render_network_titles_a_nameless_network_by_id() {
        let out = render_network(&json!({"id": "network-EXAMPLE", "hostCount": 0}));
        assert_eq!(out, "network-EXAMPLE\nID:     network-EXAMPLE\nHosts:  0\n");
    }

    #[test]
    fn network_row_reports_lighthouse_settings_off() {
        // The API stores managed lighthouses as a *disable* flag; the table
        // must not echo it verbatim.
        let row = json!({"disableManagedLighthouses": true, "lighthousesAsRelays": false});
        let cells = network_row(&row);
        assert_eq!((cells[4].as_str(), cells[5].as_str()), ("no", "no"));
    }

    #[test]
    fn network_row_defaults_missing_or_wrong_type() {
        let row = json!({
            "id": "network-EXAMPLE",
            "cidrs": 42,
            "hostCount": "many",
            "certVersion": "2",
            "lighthousesAsRelays": "true",
        });
        assert_eq!(
            network_row(&row),
            ["network-EXAMPLE", "", "", "", "", "", "", "", ""]
        );
    }
}
