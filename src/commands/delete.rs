//! The confirm-then-delete flow shared by `host delete`, `role delete` and
//! `tag delete`.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::bail;
use serde_json::{Value, json};

use crate::output::print_json;

pub const DELETE_NEEDS_YES: &str =
    "pass --yes to delete without a confirmation prompt when running non-interactively";

/// How a `delete` command should confirm a deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteConfirmation {
    /// Delete straight away: no lookup, no prompt. Only the `*:delete` scope
    /// is needed.
    Skip,
    /// Look the resource up, then ask on stderr.
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

/// What the confirmation lookup found, already sanitized for the terminal.
/// Either part may be empty when the response lacks it.
#[derive(Debug, Default)]
pub struct Described {
    /// A display name distinct from the id (a host's or role's name). Tags are
    /// named by their id, so they leave this empty.
    pub name: String,
    /// Extra context worth seeing before saying yes: a host's IPs, how many
    /// hosts carry a role or tag.
    pub detail: String,
}

/// One resource a `delete` command is about to remove.
pub struct DeleteTarget<'a> {
    /// `host`, `role` or `tag`: used in the prompt and messages.
    pub kind: &'a str,
    /// The id (or, for tags, the `key:value` name) the user typed.
    pub id: &'a str,
    /// The `--json` payload key that echoes `id`.
    pub json_key: &'a str,
    /// The scope the confirmation lookup needs, named when it fails.
    pub read_scope: &'a str,
}

/// Delete one resource, confirming interactively unless `--yes` says not to.
/// The confirmation lookup is what makes the human path safe (you see what
/// the id you typed actually names), so it runs before the prompt and its
/// failure is fatal.
pub fn confirm_and_delete(
    target: &DeleteTarget,
    yes: bool,
    json: bool,
    lookup: impl FnOnce() -> anyhow::Result<Described>,
    delete: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let DeleteTarget {
        kind,
        id,
        json_key,
        read_scope,
    } = *target;
    let mut name = String::new();

    match delete_confirmation(yes, json, std::io::stdin().is_terminal()) {
        DeleteConfirmation::Skip => {}
        DeleteConfirmation::Refuse => bail!(DELETE_NEEDS_YES),
        DeleteConfirmation::Prompt => {
            let found = lookup().map_err(|e| {
                e.context(format!(
                    "could not read {kind} {id} to confirm the deletion (the API key needs \
                     {read_scope}; pass --yes to skip the lookup)"
                ))
            })?;
            name = found.name;

            let mut err = std::io::stderr();
            write!(err, "{}", delete_prompt(kind, id, &name, &found.detail))?;
            err.flush()?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            if !confirmation_accepted(&line) {
                bail!("aborted, {kind} not deleted");
            }
        }
    }

    delete()?;

    if json {
        return print_json(&delete_json_payload(json_key, id));
    }
    println!("Deleted {}.", label(kind, id, &name));
    Ok(())
}

/// `y` / `yes`, case- and whitespace-insensitive. Everything else — a bare
/// newline included — declines, so the default is the non-destructive one.
fn confirmation_accepted(input: &str) -> bool {
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// `host "web" (host-1)`, or just `tag env:prod` when there is no separate
/// name.
fn label(kind: &str, id: &str, name: &str) -> String {
    if name.is_empty() {
        format!("{kind} {id}")
    } else {
        format!("{kind} \"{name}\" ({id})")
    }
}

/// The confirmation line, naming the resource by everything the lookup
/// returned so a mistyped id is visible before it costs anything. The id is
/// always shown; name and detail are dropped when the response lacks them.
fn delete_prompt(kind: &str, id: &str, name: &str, detail: &str) -> String {
    let what = match (name.is_empty(), detail.is_empty()) {
        (_, true) => label(kind, id, name),
        (true, false) => format!("{kind} {id} ({detail})"),
        (false, false) => format!("{kind} \"{name}\" ({id}; {detail})"),
    };
    format!("Delete {what}? [y/N] ")
}

/// The `--json` success payload. The API answers a delete with an empty
/// envelope, so the id and the outcome are echoed for the caller to key on.
fn delete_json_payload(key: &str, id: &str) -> Value {
    json!({key: id, "deleted": true})
}

/// `"1 host"` / `"3 hosts"` from a response's `hostCount`, or empty when it
/// is absent — the prompt detail for roles and tags.
pub fn host_count_detail(data: &Value) -> String {
    match data.get("hostCount").and_then(Value::as_u64) {
        Some(1) => "1 host".to_string(),
        Some(n) => format!("{n} hosts"),
        None => String::new(),
    }
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
            delete_prompt("host", "host-1", "web", "10.0.0.1, fd00::1"),
            "Delete host \"web\" (host-1; 10.0.0.1, fd00::1)? [y/N] "
        );
    }

    #[test]
    fn delete_prompt_keeps_the_detail_without_a_name() {
        assert_eq!(
            delete_prompt("host", "host-2", "", "10.0.0.2"),
            "Delete host host-2 (10.0.0.2)? [y/N] "
        );
        assert_eq!(
            delete_prompt("tag", "env:prod", "", "3 hosts"),
            "Delete tag env:prod (3 hosts)? [y/N] "
        );
    }

    #[test]
    fn delete_prompt_falls_back_to_the_id_alone() {
        assert_eq!(
            delete_prompt("tag", "env:prod", "", ""),
            "Delete tag env:prod? [y/N] "
        );
    }

    #[test]
    fn delete_prompt_omits_the_detail_clause_when_empty() {
        assert_eq!(
            delete_prompt("role", "role-3", "db", ""),
            "Delete role \"db\" (role-3)? [y/N] "
        );
    }

    #[test]
    fn delete_json_payload_echoes_the_id_and_outcome() {
        assert_eq!(
            delete_json_payload("id", "host-1"),
            json!({"id": "host-1", "deleted": true})
        );
        assert_eq!(
            delete_json_payload("name", "env:prod"),
            json!({"name": "env:prod", "deleted": true})
        );
    }

    #[test]
    fn host_count_detail_pluralizes_and_defaults_empty() {
        assert_eq!(host_count_detail(&json!({"hostCount": 0})), "0 hosts");
        assert_eq!(host_count_detail(&json!({"hostCount": 1})), "1 host");
        assert_eq!(host_count_detail(&json!({"hostCount": 12})), "12 hosts");
        assert_eq!(host_count_detail(&json!({"hostCount": "3"})), "");
        assert_eq!(host_count_detail(&json!({})), "");
    }
}
