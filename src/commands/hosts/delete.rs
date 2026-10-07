use super::host_fields;
use crate::api::Client;
use crate::cli::HostDeleteArgs;
use crate::commands::delete::{DeleteTarget, Described, confirm_and_delete};
use crate::ids::validate_id;
use crate::output::sanitize_for_display;

/// Delete one host. The confirmation names it by name and IPs, so a mistyped
/// id is visible before the device loses its access.
pub fn hosts_delete(client: &Client, args: &HostDeleteArgs, json: bool) -> anyhow::Result<()> {
    validate_id("host", &args.host_id)?;
    let id = args.host_id.as_str();
    let target = DeleteTarget {
        kind: "host",
        id,
        json_key: "id",
        read_scope: "hosts:read",
    };
    confirm_and_delete(
        &target,
        args.yes,
        json,
        || {
            let res = client.get_host(id)?;
            let (_, name, ips) = host_fields(&res["data"]);
            Ok(Described {
                name: sanitize_for_display(name),
                detail: sanitize_for_display(&ips),
            })
        },
        || client.delete_host(id),
    )
}
