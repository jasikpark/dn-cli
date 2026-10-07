use serde_json::Value;

use super::{validate_host_id, validate_role_id};
use crate::api::Client;
use crate::cli::HostGetArgs;
use crate::output::{
    data_object, joined_field, print_json, render_details, sanitize_for_display, str_field,
};

/// Show one host. `--json` prints the response as-is; the human view resolves
/// the role id to its name.
pub fn hosts_get(client: &Client, args: &HostGetArgs, json: bool) -> anyhow::Result<()> {
    validate_host_id(&args.host_id)?;
    let res = client.get_host(&args.host_id)?;
    if json {
        return print_json(&res);
    }
    let data = data_object(&res, "host")?;
    let role = data["roleID"].as_str().filter(|id| !id.is_empty());
    // A malformed id from the server is shown as-is rather than spliced
    // into a lookup path.
    let role_name = role
        .filter(|id| validate_role_id(id).is_ok())
        .and_then(|id| role_name(client, id));
    print!("{}", render_host(data, role_name.as_deref()));
    Ok(())
}

/// The name of role `id`, or `None` with a stderr note when the lookup fails
/// (it needs `roles:read`, which a hosts-only key may lack).
fn role_name(client: &Client, id: &str) -> Option<String> {
    match client.get_role(id) {
        Ok(res) => Some(str_field(&res["data"], "name").to_string()).filter(|n| !n.is_empty()),
        Err(e) => {
            let e = sanitize_for_display(&format!("{e:#}"));
            eprintln!("note: showing the role id, not its name (role lookup failed: {e})");
            None
        }
    }
}

/// The human view of a v2 host: its name, then one aligned `label: value`
/// line per field that has a value.
fn render_host(data: &Value, role_name: Option<&str>) -> String {
    let id = str_field(data, "id");
    let name = sanitize_for_display(str_field(data, "name"));
    let mut out = match name.trim() {
        "" => format!("{id}\n"),
        _ => format!("{name}\n"),
    };

    let flag = |key| data[key].as_bool().unwrap_or(false);
    let kind = match (flag("isLighthouse"), flag("isRelay")) {
        (true, true) => "lighthouse, relay",
        (true, false) => "lighthouse",
        (false, true) => "relay",
        (false, false) => "host",
    };
    let role = match (data["roleID"].as_str().filter(|r| !r.is_empty()), role_name) {
        (Some(id), Some(name)) => format!("{name} ({id})"),
        (Some(id), None) => id.to_string(),
        (None, _) => "none".to_string(),
    };
    let listen_port = data["listenPort"]
        .as_u64()
        .filter(|&p| p != 0)
        .map(|p| p.to_string())
        .unwrap_or_default();
    let overrides = data["configOverrides"]
        .as_array()
        .filter(|o| !o.is_empty())
        .map(|o| o.len().to_string())
        .unwrap_or_default();

    let meta = &data["metadata"];
    let last_seen = match meta.get("lastSeenAt") {
        Some(Value::Null) => "never".to_string(),
        Some(v) => v.as_str().unwrap_or_default().to_string(),
        None => String::new(),
    };
    let mut client = [str_field(meta, "platform"), str_field(meta, "version")]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if !client.is_empty() && meta["updateAvailable"].as_bool() == Some(true) {
        client.push_str(" (update available)");
    }

    out.push_str(&render_details(&[
        ("ID", id.to_string()),
        ("Type", kind.to_string()),
        ("Network", str_field(data, "networkID").to_string()),
        ("Role", role),
        ("IP addresses", joined_field(data, "ipAddresses")),
        ("Tags", joined_field(data, "tags")),
        ("Static addresses", joined_field(data, "staticAddresses")),
        ("Listen port", listen_port),
        (
            "Blocked",
            if flag("isBlocked") { "yes" } else { "" }.to_string(),
        ),
        (
            "OIDC user",
            str_field(data, "endpointOIDCUserID").to_string(),
        ),
        ("Config overrides", overrides),
        ("Client", client),
        ("Last seen", last_seen),
        ("Created", str_field(data, "createdAt").to_string()),
    ]));
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn render_host_shows_a_lighthouse_with_its_role_name() {
        let data = json!({
            "id": "host-EXAMPLE",
            "networkID": "network-EXAMPLE",
            "roleID": "role-EXAMPLE",
            "name": "lh-1",
            "ipAddresses": ["100.100.0.1", "fd00::1"],
            "staticAddresses": ["203.0.113.5:4242"],
            "listenPort": 4242,
            "isLighthouse": true,
            "isRelay": false,
            "isBlocked": false,
            "createdAt": "2025-01-25T18:15:27Z",
            "tags": ["env:prod", "site:hou"],
            "configOverrides": [],
            "metadata": {
                "lastSeenAt": "2025-02-01T00:00:00Z",
                "platform": "dnclient",
                "updateAvailable": true,
                "version": "0.9.3"
            }
        });
        assert_eq!(
            render_host(&data, Some("Lighthouses")),
            "lh-1\n\
             ID:                host-EXAMPLE\n\
             Type:              lighthouse\n\
             Network:           network-EXAMPLE\n\
             Role:              Lighthouses (role-EXAMPLE)\n\
             IP addresses:      100.100.0.1, fd00::1\n\
             Tags:              env:prod, site:hou\n\
             Static addresses:  203.0.113.5:4242\n\
             Listen port:       4242\n\
             Client:            dnclient 0.9.3 (update available)\n\
             Last seen:         2025-02-01T00:00:00Z\n\
             Created:           2025-01-25T18:15:27Z\n"
        );
    }

    #[test]
    fn render_host_marks_no_role_never_seen_and_blocked() {
        let data = json!({
            "id": "host-EXAMPLE",
            "name": "",
            "roleID": null,
            "isBlocked": true,
            "configOverrides": [{"key": "a", "value": 1}],
            "metadata": {"lastSeenAt": null, "platform": null, "version": null}
        });
        let out = render_host(&data, None);
        assert!(out.starts_with("host-EXAMPLE\n"), "{out}");
        assert!(out.contains("Role:              none\n"), "{out}");
        assert!(out.contains("Blocked:           yes\n"), "{out}");
        assert!(out.contains("Config overrides:  1\n"), "{out}");
        assert!(out.contains("Last seen:         never\n"), "{out}");
        assert!(!out.contains("Client:"), "{out}");
    }

    #[test]
    fn render_host_falls_back_to_the_role_id() {
        let data = json!({"id": "host-1", "name": "web", "roleID": "role-1"});
        let out = render_host(&data, None);
        assert!(out.contains("Role:  role-1\n"), "{out}");
        // No metadata object at all says nothing about when it was seen.
        assert!(!out.contains("Last seen"), "{out}");
    }
}
