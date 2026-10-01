use std::fmt;
use std::io::{ErrorKind, IsTerminal};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};

use super::{API_KEY_ENV, OP_SCHEME, Profile};

/// Where the API key comes from, in precedence order. The environment always
/// wins so CI and agents can inject a key without touching the config file.
#[derive(Clone, PartialEq)]
pub enum KeySource {
    /// `DEFINED_API_KEY` holds the raw key.
    Env(String),
    /// `DEFINED_API_KEY` holds an `op://` reference to resolve.
    EnvRef(String),
    /// The selected profile's `op://` reference.
    FileRef(String),
    /// The OS keyring entry for the named profile.
    Keyring(String),
}

/// The raw env key never appears in debug output.
impl fmt::Debug for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySource::Env(_) => f.write_str("Env(<redacted>)"),
            KeySource::EnvRef(r) => f.debug_tuple("EnvRef").field(r).finish(),
            KeySource::FileRef(r) => f.debug_tuple("FileRef").field(r).finish(),
            KeySource::Keyring(p) => f.debug_tuple("Keyring").field(p).finish(),
        }
    }
}

impl KeySource {
    pub fn label(&self) -> &'static str {
        match self {
            KeySource::Env(_) => "env",
            KeySource::EnvRef(_) => "env-ref",
            KeySource::FileRef(_) => "file",
            KeySource::Keyring(_) => "keyring",
        }
    }

    /// The `op://` reference, if this source is one. Safe to display; the raw
    /// env key deliberately has no accessor here.
    pub fn reference(&self) -> Option<&str> {
        match self {
            KeySource::Env(_) | KeySource::Keyring(_) => None,
            KeySource::EnvRef(r) | KeySource::FileRef(r) => Some(r),
        }
    }
}

/// Where a stored profile's key comes from, without resolving it: the OS
/// keyring, or its `op://` reference. `None` for a profile saved with only a
/// URL (e.g. migrated from `config.json`), which needs `DEFINED_API_KEY`.
pub fn profile_key_source(name: &str, profile: &Profile) -> Result<Option<KeySource>> {
    if profile.uses_keyring() {
        return Ok(Some(KeySource::Keyring(name.to_string())));
    }
    resolve_key_source(None, profile.key.as_deref()).with_context(|| format!("profile {name:?}"))
}

/// Pure precedence: env (raw or `op://`) beats the file reference. `None` when
/// neither is set; `Err` when the env var is set but blank, or when a
/// reference is present but malformed.
pub fn resolve_key_source(
    env_key: Option<&str>,
    file_ref: Option<&str>,
) -> Result<Option<KeySource>> {
    if let Some(key) = env_key.map(str::trim) {
        if key.is_empty() {
            bail!(
                "{API_KEY_ENV} is set but empty. Unset it to use the stored reference, \
                 or set it to a key or op:// reference."
            );
        }
        return if key.starts_with(OP_SCHEME) {
            validate_op_ref(key)
                .with_context(|| format!("{API_KEY_ENV} holds an invalid op:// reference"))?;
            Ok(Some(KeySource::EnvRef(key.to_string())))
        } else {
            Ok(Some(KeySource::Env(key.to_string())))
        };
    }
    if let Some(r) = file_ref.map(str::trim).filter(|r| !r.is_empty()) {
        validate_op_ref(r).context("the stored key is an invalid op:// reference")?;
        return Ok(Some(KeySource::FileRef(r.to_string())));
    }
    Ok(None)
}

/// Clean up a pasted reference. 1Password's "Copy Secret Reference" wraps the
/// value in double quotes when an item or section name contains spaces
/// (`"op://Personal/DN production API Key/credential"`), so the shell-quoted
/// form is what lands in a prompt or `--ref`.
pub fn normalize_op_ref(s: &str) -> String {
    let s = s.trim();
    let unquoted = [('"', '"'), ('\'', '\'')]
        .iter()
        .find_map(|(open, close)| s.strip_prefix(*open)?.strip_suffix(*close))
        .unwrap_or(s);
    unquoted.trim().to_string()
}

/// A 1Password secret reference is `op://vault/item/field` or
/// `op://vault/item/section/field`; every segment must be non-empty.
pub fn validate_op_ref(s: &str) -> Result<()> {
    let s = s.trim();
    let Some(path) = s.strip_prefix(OP_SCHEME) else {
        bail!("expected a 1Password secret reference starting with {OP_SCHEME}, got {s:?}");
    };
    // A trailing query selects an attribute of the field rather than naming it,
    // and `op` takes exactly one `key=value` pair there (`?attribute=otp`,
    // `?ssh-format=openssh`).
    let (path, query) = match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    };
    if let Some(query) = query {
        let well_formed = query.split_once('=').is_some_and(|(key, value)| {
            !key.is_empty()
                && !value.is_empty()
                && [key, value].iter().all(|part| {
                    part.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                })
        });
        if !well_formed {
            bail!(
                "expected a single ?attribute=value query in {s} (`?attribute=otp` is the common form), got {query:?}"
            );
        }
    }
    let segments: Vec<&str> = path.split('/').collect();
    if !(3..=4).contains(&segments.len()) || segments.iter().any(|seg| seg.trim().is_empty()) {
        bail!(
            "expected {OP_SCHEME}vault/item/field (optionally {OP_SCHEME}vault/item/section/field), got {s:?}"
        );
    }
    // `op` accepts names made of alphanumerics, `-`, `_`, `.`, `=` and ASCII
    // spaces; a vault/item/field whose name has anything else (an `@` in an
    // email-style title, a `:`) must be referenced by its ID instead.
    for seg in &segments {
        if let Some(bad) = seg
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '=' | ' ')))
        {
            bail!(
                "1Password can't resolve {seg:?} in {s}: {bad:?} isn't allowed in a secret reference name.\n\
                 Use the item's ID instead — in 1Password, right-click the field \u{2192} Copy Secret Reference \
                 gives the ID form (op://vault/<item-id>/field)."
            );
        }
    }
    Ok(())
}

/// The key a profile keeps in the OS keyring, trimmed. Anything not a
/// plausible key (empty, or with spaces or control characters, as an entry
/// edited outside `dn` can be) is refused here, not sent to the API.
pub(super) fn keyring_key(profile: &str) -> Result<String> {
    let key = crate::keystore::get(profile)?.trim().to_string();
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_graphic()) {
        bail!(
            "the OS keyring entry for profile {profile:?} is not an API key; run \
             `dn auth login --profile {profile}` to replace it"
        );
    }
    Ok(key)
}

/// Resolve a secret reference through the 1Password CLI. This is the
/// per-invocation gate: `op` prompts for unlock (biometric or password) per
/// its own session policy, so a stored reference alone grants nothing.
///
/// stdin is always inherited so `op` can prompt for a password. stderr is
/// inherited only when it is a terminal, where a human is there to read the
/// prompt and the "waiting for authorization" progress; when it is redirected
/// nobody is watching, so it is captured and folded into the error chain rather
/// than lost. stdout is always captured — it carries the secret.
pub fn op_read(reference: &str) -> Result<String> {
    let stderr_is_terminal = std::io::stderr().is_terminal();
    let output = Command::new("op")
        .args(["read", "--no-newline", reference])
        .stdin(Stdio::inherit())
        .stderr(if stderr_is_terminal {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| match e.kind() {
            ErrorKind::NotFound => anyhow!(
                "the 1Password CLI (`op`) is not installed or not on PATH.\n\
                 Install it: https://developer.1password.com/docs/cli/get-started/"
            ),
            _ => anyhow!(e).context("failed to run `op read`"),
        })?;
    if !output.status.success() {
        let code = output
            .status
            .code()
            .map_or("signal".to_string(), |c| c.to_string());
        if stderr_is_terminal {
            bail!("`op read {reference}` failed (exit {code}); see op's output above");
        }
        let diag = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if diag.is_empty() {
            bail!("`op read {reference}` failed (exit {code})");
        }
        return Err(anyhow!(diag).context(format!("`op read {reference}` failed (exit {code})")));
    }
    let key = String::from_utf8(output.stdout)
        .context("`op read` returned non-UTF-8 output")?
        .trim()
        .to_string();
    if key.is_empty() {
        bail!("`op read {reference}` returned an empty value");
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_raw_key_wins_over_file() {
        let got = resolve_key_source(Some("dnkey_abc"), Some("op://v/i/f")).unwrap();
        assert_eq!(got, Some(KeySource::Env("dnkey_abc".into())));
    }

    #[test]
    fn env_op_ref_is_detected_and_wins() {
        let got = resolve_key_source(Some(" op://Personal/item/credential "), Some("op://v/i/f"))
            .unwrap();
        assert_eq!(
            got,
            Some(KeySource::EnvRef("op://Personal/item/credential".into()))
        );
    }

    #[test]
    fn file_ref_used_when_env_absent() {
        let got = resolve_key_source(None, Some(" op://v/i/f\n")).unwrap();
        assert_eq!(got, Some(KeySource::FileRef("op://v/i/f".into())));
        let got = resolve_key_source(None, Some("op://v/i/s/f")).unwrap();
        assert_eq!(got, Some(KeySource::FileRef("op://v/i/s/f".into())));
    }

    #[test]
    fn blank_env_key_is_an_error_never_a_fallthrough() {
        let err = resolve_key_source(Some(""), Some("op://v/i/f")).unwrap_err();
        assert!(err.to_string().contains("set but empty"), "{err}");
        assert!(resolve_key_source(Some("   \n"), None).is_err());
    }

    #[test]
    fn nothing_configured_is_none() {
        assert_eq!(resolve_key_source(None, None).unwrap(), None);
        assert_eq!(resolve_key_source(None, Some("  ")).unwrap(), None);
    }

    #[test]
    fn malformed_refs_are_errors() {
        assert!(resolve_key_source(Some("op://onlyvault"), None).is_err());
        assert!(resolve_key_source(None, Some("op://v//f")).is_err());
        assert!(resolve_key_source(None, Some("http://v/i/f")).is_err());
        assert!(resolve_key_source(None, Some("op://v/i/s/x/f")).is_err());
    }

    #[test]
    fn validate_op_ref_rejects_unsupported_name_characters_with_id_hint() {
        let err = validate_op_ref("op://Personal/someone@example.com - DN API Key/credential")
            .unwrap_err()
            .to_string();
        assert!(err.contains("'@'"), "{err}");
        assert!(err.contains("item's ID"), "{err}");
        assert!(validate_op_ref("op://Personal/DN API: hosts/credential").is_err());
        validate_op_ref("op://Personal/abcdefghijklmnopqrstuvwxyz/credential").unwrap();
        validate_op_ref("op://Personal/My_item.v2 - prod/one time password?attribute=otp").unwrap();
    }

    #[test]
    fn normalize_op_ref_strips_pasted_quotes() {
        let want = "op://Personal/DN production API Key/credential";
        assert_eq!(normalize_op_ref(&format!("  \"{want}\"\n")), want);
        assert_eq!(normalize_op_ref(&format!("'{want}'")), want);
        assert_eq!(normalize_op_ref(want), want);
        assert_eq!(normalize_op_ref("\"op://v/i/f"), "\"op://v/i/f");
        validate_op_ref(&normalize_op_ref(&format!("\"{want}\""))).unwrap();
    }

    #[test]
    fn validate_op_ref_accepts_three_and_four_segments() {
        validate_op_ref("op://Personal/item/credential").unwrap();
        validate_op_ref("op://Personal/item/Section One/credential").unwrap();
        validate_op_ref("  op://v/i/f  ").unwrap();
    }

    #[test]
    fn key_source_labels_refs_and_redacted_debug() {
        assert_eq!(KeySource::Env("k".into()).label(), "env");
        assert_eq!(KeySource::Env("k".into()).reference(), None);
        assert_eq!(KeySource::EnvRef("op://v/i/f".into()).label(), "env-ref");
        assert_eq!(
            KeySource::FileRef("op://v/i/f".into()).reference(),
            Some("op://v/i/f")
        );
        let dbg = format!("{:?}", KeySource::Env("dnkey_secret".into()));
        assert!(!dbg.contains("dnkey_secret"), "{dbg}");
        assert_eq!(dbg, "Env(<redacted>)");
    }

    #[test]
    fn validate_op_ref_rejects_non_ascii_whitespace() {
        assert!(validate_op_ref("op://v/i/a\u{00A0}b").is_err());
        assert!(validate_op_ref("op://v/i/a\tb").is_err());
        assert!(validate_op_ref("op://v/i/a\u{3000}b").is_err());
        validate_op_ref("op://v/i/a b").unwrap();
    }

    #[test]
    fn validate_op_ref_accepts_equals_in_names() {
        validate_op_ref("op://v/i/f=g").unwrap();
    }

    #[test]
    fn validate_op_ref_validates_query_suffix() {
        validate_op_ref("op://v/i/f?attribute=otp").unwrap();
        validate_op_ref("op://v/i/f?ssh-format=openssh").unwrap();
        for bad in [
            "op://v/i/f?",
            "op://v/i/f?g",
            "op://v/i/f?attribute",
            "op://v/i/f?attribute=/x",
            "op://v/i/f?attribute=otp&x=1",
        ] {
            assert!(validate_op_ref(bad).is_err(), "{bad} should be rejected");
        }
    }
}
