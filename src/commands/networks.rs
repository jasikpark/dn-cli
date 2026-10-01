use serde_json::Value;

use crate::api::Client;
use crate::output::{count_field, joined_field, print_list, str_field};

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
        |rows| rows.iter().map(network_row).collect(),
    )
}

/// The columns the human network table renders. Strings fall back to empty
/// when absent or non-string; `cidrs` joins the overlay prefixes (an IPv6
/// one and, on dual-stack networks, an IPv4 one) the way the host table joins
/// IPs. Managed lighthouses are Defined's hosted fleet and never appear in
/// `host list`, so this table is where that setting is visible; the API
/// stores it inverted (`disableManagedLighthouses`) and the column reports it
/// the way the admin panel does — whether managed lighthouses are on.
fn network_row(row: &Value) -> Vec<String> {
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
    vec![
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
