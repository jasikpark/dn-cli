use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Context, bail};
use serde_json::{Value, json};

use super::{host_fields, validate_host_id};
use crate::api::Client;
use crate::cli::HostDeleteArgs;
use crate::output::{print_json, sanitize_for_display};

/// Delete one host, confirming interactively unless `--yes` says not to.
/// The confirmation lookup is what makes the human path safe (you see the
/// name and IPs of the host you typed an id for), so it runs before the
/// prompt and its failure is fatal.
pub fn hosts_delete(client: &Client, args: &HostDeleteArgs, json: bool) -> anyhow::Result<()> {
    validate_host_id(&args.host_id)?;
    let id = args.host_id.as_str();
    let mut name = String::new();

    match delete_confirmation(args.yes, json, std::io::stdin().is_terminal()) {
        DeleteConfirmation::Skip => {}
        DeleteConfirmation::Refuse => bail!(DELETE_NEEDS_YES),
        DeleteConfirmation::Prompt => {
            let res = client.get_host(id).with_context(|| {
                format!(
                    "could not read host {id} to confirm the deletion (the API key needs \
                     hosts:read; pass --yes to skip the lookup)"
                )
            })?;
            let (_, found, ips) = host_fields(&res["data"]);
            name = sanitize_for_display(found);
            let ips = sanitize_for_display(&ips);

            let mut err = std::io::stderr();
            write!(err, "{}", delete_prompt(id, &name, &ips))?;
            err.flush()?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            if !confirmation_accepted(&line) {
                bail!("aborted, host not deleted");
            }
        }
    }

    client.delete_host(id)?;

    if json {
        return print_json(&delete_json_payload(id));
    }
    if name.is_empty() {
        println!("Deleted host {id}.");
    } else {
        println!("Deleted host \"{name}\" ({id}).");
    }
    Ok(())
}

pub const DELETE_NEEDS_YES: &str =
    "pass --yes to delete without a confirmation prompt when running non-interactively";

/// How `dn host delete` should confirm a deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteConfirmation {
    /// Delete straight away: no lookup, no prompt. Only `hosts:delete` is
    /// needed.
    Skip,
    /// Look the host up, then ask on stderr.
    Prompt,
    /// Nowhere to ask — the run has to opt in with `--yes` instead.
    Refuse,
}

/// `--yes` is the only way a non-interactive run reaches the DELETE: a prompt
/// with no terminal behind it would hang a `--json` caller or a script, so it
/// is refused rather than skipped.
pub fn delete_confirmation(yes: bool, json: bool, stdin_is_tty: bool) -> DeleteConfirmation {
    if yes {
        DeleteConfirmation::Skip
    } else if json || !stdin_is_tty {
        DeleteConfirmation::Refuse
    } else {
        DeleteConfirmation::Prompt
    }
}

/// `y` / `yes`, case- and whitespace-insensitive. Everything else — a bare
/// newline included — declines, so the default is the non-destructive one.
fn confirmation_accepted(input: &str) -> bool {
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// The confirmation line, naming the host by everything the lookup returned so
/// a mistyped id is visible before it costs a device its access. The id is
/// always shown; name and IPs are dropped when the response lacks them.
fn delete_prompt(id: &str, name: &str, ips: &str) -> String {
    if name.is_empty() {
        format!("Delete host {id}? [y/N] ")
    } else if ips.is_empty() {
        format!("Delete host \"{name}\" ({id})? [y/N] ")
    } else {
        format!("Delete host \"{name}\" ({id}; {ips})? [y/N] ")
    }
}

/// The `--json` success payload. The API answers a delete with an empty
/// envelope, so the id and the outcome are echoed for the caller to key on.
fn delete_json_payload(id: &str) -> Value {
    json!({"id": id, "deleted": true})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_confirmation_skips_the_prompt_whenever_yes_is_passed() {
        for json in [false, true] {
            for tty in [false, true] {
                assert_eq!(
                    delete_confirmation(true, json, tty),
                    DeleteConfirmation::Skip,
                    "--yes must win over json={json} tty={tty}"
                );
            }
        }
    }

    #[test]
    fn delete_confirmation_refuses_without_yes_when_nothing_can_answer() {
        // --json is an agent run: a prompt there would hang the caller.
        assert_eq!(
            delete_confirmation(false, true, true),
            DeleteConfirmation::Refuse
        );
        // Piped stdin, human output: still nobody to ask.
        assert_eq!(
            delete_confirmation(false, false, false),
            DeleteConfirmation::Refuse
        );
    }

    #[test]
    fn delete_confirmation_prompts_an_interactive_human() {
        assert_eq!(
            delete_confirmation(false, false, true),
            DeleteConfirmation::Prompt
        );
    }

    #[test]
    fn confirmation_accepted_takes_only_y_and_yes() {
        assert!(confirmation_accepted("y"));
        assert!(confirmation_accepted("Y"));
        assert!(confirmation_accepted("yes"));
        assert!(confirmation_accepted("YES \n"));
        // Enter alone is a decline: the [y/N] default is the safe one.
        assert!(!confirmation_accepted(""));
        assert!(!confirmation_accepted("n"));
        assert!(!confirmation_accepted("no"));
    }

    #[test]
    fn delete_prompt_names_the_host_and_its_ips() {
        assert_eq!(
            delete_prompt("host-1", "web", "10.0.0.1, fd00::1"),
            "Delete host \"web\" (host-1; 10.0.0.1, fd00::1)? [y/N] "
        );
    }

    #[test]
    fn delete_prompt_falls_back_to_the_id_alone_without_a_name() {
        assert_eq!(
            delete_prompt("host-2", "", "10.0.0.2"),
            "Delete host host-2? [y/N] "
        );
    }

    #[test]
    fn delete_prompt_omits_the_ip_clause_when_there_are_none() {
        assert_eq!(
            delete_prompt("host-3", "db", ""),
            "Delete host \"db\" (host-3)? [y/N] "
        );
    }

    #[test]
    fn delete_json_payload_echoes_the_id_and_outcome() {
        assert_eq!(
            delete_json_payload("host-1"),
            json!({"id": "host-1", "deleted": true})
        );
    }
}
