use serde_json::Value;

use crate::api::Client;
use crate::output::render_table;

pub fn networks_list(client: &Client, json: bool) -> anyhow::Result<()> {
    let res = client.list_networks()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&res)?);
        return Ok(());
    }

    let empty: Vec<Value> = Vec::new();
    let rows = res.get("data").and_then(Value::as_array).unwrap_or(&empty);
    if rows.is_empty() {
        println!("No networks found.");
        return Ok(());
    }

    let table_rows: Vec<Vec<String>> = rows.iter().map(network_row).collect();
    print!(
        "{}",
        render_table(
            &[
                "ID",
                "NAME",
                "CIDRS",
                "HOSTS",
                "MANAGED LH",
                "LH AS RELAYS",
                "CURVE",
                "CERT",
                "DESCRIPTION",
            ],
            &table_rows
        )
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

/// The columns the human network table renders. Strings fall back to empty
/// when absent or non-string; `cidrs` joins the overlay prefixes (an IPv6
/// one and, on dual-stack networks, an IPv4 one) the way the host table joins
/// IPs. Managed lighthouses are Defined's hosted fleet and never appear in
/// `host list`, so this table is where that setting is visible; the API
/// stores it inverted (`disableManagedLighthouses`) and the column reports it
/// the way the admin panel does — whether managed lighthouses are on.
fn network_row(row: &Value) -> Vec<String> {
    let field = |key| {
        row.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let yes_no = |enabled: bool| if enabled { "yes" } else { "no" }.to_string();
    let cidrs = row
        .get("cidrs")
        .and_then(Value::as_array)
        .map(|cidrs| {
            cidrs
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let hosts = row
        .get("hostCount")
        .and_then(Value::as_u64)
        .map(|n| n.to_string())
        .unwrap_or_default();
    let managed_lighthouses = row
        .get("disableManagedLighthouses")
        .and_then(Value::as_bool)
        .map(|disabled| yes_no(!disabled))
        .unwrap_or_default();
    let lighthouses_as_relays = row
        .get("lighthousesAsRelays")
        .and_then(Value::as_bool)
        .map(yes_no)
        .unwrap_or_default();
    let cert = row
        .get("certVersion")
        .and_then(Value::as_u64)
        .map(|v| format!("v{v}"))
        .unwrap_or_default();
    vec![
        field("id"),
        field("name"),
        cidrs,
        hosts,
        managed_lighthouses,
        lighthouses_as_relays,
        field("curve"),
        cert,
        field("description"),
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
