use serde_json::Value;

use crate::api::Client;
use crate::cli::AuditLogListArgs;
use crate::output::{print_list, str_field};

pub fn audit_log_list(client: &Client, args: &AuditLogListArgs, json: bool) -> anyhow::Result<()> {
    let mut params = Vec::new();
    if let Some(id) = &args.target {
        params.push(("filter.targetID", id.as_str()));
    }
    if let Some(kind) = &args.target_type {
        params.push(("filter.targetType", kind.as_str()));
    }
    let res = client.list_audit_logs(&params, &args.page)?;
    let headers = ["TIME", "EVENT", "TARGET TYPE", "TARGET", "ACTOR"];
    print_list(
        &res,
        json,
        "No audit log entries found.",
        &headers,
        |rows| rows.iter().map(|r| audit_log_row(r).to_vec()).collect(),
    )
}

/// The columns the human audit log table renders. The event's `before` and
/// `after` states vary by target and event type, so only `--json` shows them.
fn audit_log_row(row: &Value) -> [String; 5] {
    let target = &row["target"];
    [
        trim_fraction(str_field(row, "timestamp")),
        str_field(&row["event"], "type").to_string(),
        str_field(target, "type").to_string(),
        str_field(target, "id").to_string(),
        actor_label(&row["actor"]),
    ]
}

/// An RFC 3339 timestamp without its fractional seconds:
/// `2023-02-15T13:59:09.828868Z` becomes `2023-02-15T13:59:09Z`.
fn trim_fraction(ts: &str) -> String {
    match ts.split_once('.') {
        Some((whole, rest)) => {
            let zone = rest.trim_start_matches(|c: char| c.is_ascii_digit());
            format!("{whole}{zone}")
        }
        None => ts.to_string(),
    }
}

/// Who performed the action, in a form a person recognizes. Each actor type
/// carries different fields: users, SSO users and device owners (people who
/// enrolled a device by signing in) an email, API keys and hosts an id plus
/// an optional name, support and system nothing at all. A type this doesn't
/// know is shown with whatever name or id it carries.
fn actor_label(actor: &Value) -> String {
    let named = |kind: &str| {
        let name = str_field(actor, "name");
        let shown = if name.trim().is_empty() {
            str_field(actor, "id")
        } else {
            name
        };
        format!("{kind} {shown}").trim().to_string()
    };
    // An identity without an email (e.g. one since deleted) still shows
    // whatever else identifies it.
    let person = |kind: &str, suffix: &str| {
        let email = str_field(actor, "email");
        if email.trim().is_empty() {
            named(kind)
        } else {
            format!("{email}{suffix}")
        }
    };
    match str_field(actor, "type") {
        "user" => person("user", ""),
        "oidcUser" => person("SSO user", " (SSO)"),
        "endpointOIDCUser" => person("device owner", " (device owner)"),
        "apiKey" => named("API key"),
        "host" => named("host"),
        "support" => "Defined Networking support".to_string(),
        other => named(other),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn audit_log_row_renders_the_documented_example() {
        let row = json!({
            "id": "log-EXAMPLE",
            "organizationID": "org-EXAMPLE",
            "timestamp": "2023-02-15T13:59:09.828868Z",
            "actor": {"id": "dnkey-EXAMPLE", "name": "example api key", "type": "apiKey"},
            "target": {"id": "role-EXAMPLE", "type": "role"},
            "event": {"type": "CREATED", "before": null, "after": {"name": "My New Role"}},
        });
        assert_eq!(
            audit_log_row(&row),
            [
                "2023-02-15T13:59:09Z",
                "CREATED",
                "role",
                "role-EXAMPLE",
                "API key example api key",
            ]
        );
    }

    #[test]
    fn audit_log_row_defaults_missing_fields() {
        assert_eq!(audit_log_row(&json!({})), ["", "", "", "", ""]);
    }

    #[test]
    fn trim_fraction_keeps_the_zone() {
        assert_eq!(
            trim_fraction("2023-02-15T13:59:09.8Z"),
            "2023-02-15T13:59:09Z"
        );
        assert_eq!(
            trim_fraction("2023-02-15T13:59:09.123+05:00"),
            "2023-02-15T13:59:09+05:00"
        );
        assert_eq!(
            trim_fraction("2023-02-15T13:59:09Z"),
            "2023-02-15T13:59:09Z"
        );
        assert_eq!(trim_fraction(""), "");
    }

    #[test]
    fn actor_label_names_each_actor_type() {
        let cases = [
            (
                json!({"type": "user", "id": "user-1", "email": "a@example.com"}),
                "a@example.com",
            ),
            (
                json!({"type": "oidcUser", "email": "b@example.com", "issuer": "i", "subject": "s"}),
                "b@example.com (SSO)",
            ),
            (
                json!({"type": "apiKey", "id": "dnkey-1", "name": "ci"}),
                "API key ci",
            ),
            (
                json!({"type": "apiKey", "id": "dnkey-1", "name": null}),
                "API key dnkey-1",
            ),
            (
                json!({"type": "host", "id": "host-1", "name": "  "}),
                "host host-1",
            ),
            (json!({"type": "host"}), "host"),
            (json!({"type": "support"}), "Defined Networking support"),
            (
                json!({"type": "endpointOIDCUser", "email": "c@example.com", "issuer": "i", "subject": "s"}),
                "c@example.com (device owner)",
            ),
            (
                json!({"type": "user", "id": "user-1", "email": null}),
                "user user-1",
            ),
            (json!({"type": "oidcUser", "email": ""}), "SSO user"),
            (json!({"type": "system"}), "system"),
            (json!({"name": "x"}), "x"),
            (json!({"type": "robot", "id": "robot-1"}), "robot robot-1"),
            (json!({}), ""),
        ];
        for (actor, want) in cases {
            assert_eq!(actor_label(&actor), want, "{actor}");
        }
    }
}
