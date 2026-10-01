use std::io::IsTerminal;

use anyhow::{Context, anyhow, bail};
use serde_json::{Value, json};

use crate::api::{ApiError, Client};
use crate::cli::{AuthLoginArgs, AuthLogoutArgs, AuthSwitchArgs};
use crate::config::{
    Active, AuthFile, AuthLock, Config, DEFAULT_PROFILE, KEYRING, KeySource, Profile,
    api_key_env_is_set, api_url, auth_path, check_api_url, normalize_api_url, normalize_op_ref,
    op_read, requested_profile, select_profile, stored_api_url, validate_op_ref,
};
use crate::error::InvalidArgument;
use crate::keystore;
use crate::output::{print_json, render_table};

const API_KEYS_URL: &str = "https://admin.defined.net/settings/api-keys/add";

pub fn auth_login(
    args: &AuthLoginArgs,
    profile_flag: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    // Verify against the URL the profile will be saved with, before taking
    // the lock: `op read` may wait on a 1Password prompt, and every other
    // `dn` call that migrates or edits credentials would wait with it.
    let (planned, _) = AuthFile::load_or_reset()?;
    let name = requested_profile(profile_flag)?
        .or_else(|| planned.default_profile.clone())
        .unwrap_or_else(|| DEFAULT_PROFILE.to_string());
    if args.reference.is_none() {
        keystore::ensure_available()?;
    }
    let key = read_login_key(args)?;
    let saved_url = || {
        args.api_url
            .as_deref()
            .map(normalize_api_url)
            .or_else(|| planned.profiles.get(&name).and_then(|p| p.api_url.clone()))
    };
    if !args.no_verify {
        let target = Profile {
            api_url: saved_url(),
            ..Profile::default()
        };
        let url = stored_api_url(Some(&target));
        check_api_url(&url)?;
        let api_key = match &key {
            LoginKey::Keyring(key) => key.clone(),
            LoginKey::Reference(reference) => op_read(reference)?,
        };
        Client::new(Config {
            api_key,
            api_url: url,
            profile: None,
        })
        .verify_key()
        .map_err(label_verify_error)?;
    }

    // The keyring write can also wait on an unlock prompt, so it happens
    // before the lock too, and before auth.json points at it. If saving the
    // profile then fails, the keyring goes back to what auth.json still
    // describes: the profile's old key, or no entry.
    let had_keyring_entry = planned
        .profiles
        .get(&name)
        .is_some_and(|p| p.uses_keyring());
    let mut old_key = None;
    if let LoginKey::Keyring(key) = &key {
        if had_keyring_entry {
            old_key = keystore::get(&name).ok();
        }
        keystore::set(&name, key)?;
    }
    let saved = save_login(args, &name, &key);
    let (auth, replaced, previous_default, path) = match saved {
        Ok(saved) => saved,
        Err(e) => {
            if matches!(key, LoginKey::Keyring(_)) {
                restore_keyring_entry(&name, old_key.as_deref(), had_keyring_entry);
            }
            return Err(e);
        }
    };
    // Judged by the profile this save replaced, not `planned`: another login
    // may have pointed it at the keyring while this one waited on a prompt.
    let mut keyring_left = Vec::new();
    if replaced.is_some_and(|p| p.uses_keyring())
        && matches!(key, LoginKey::Reference(_))
        && !forget_keyring_entry(&name)
    {
        keyring_left.push(name.clone());
    }
    let env_override = warn_env_override();

    if json {
        let mut out = profiles_json(&auth);
        out.as_object_mut().unwrap().extend([
            ("ok".into(), json!(true)),
            ("profile".into(), json!(name)),
            ("auth_path".into(), json!(path)),
            ("env_override".into(), json!(env_override)),
            ("keyring_left".into(), json!(keyring_left)),
        ]);
        return print_json(&out);
    }
    match &key {
        LoginKey::Keyring(_) => println!(
            "Saved profile \"{name}\" to {}, with its key in the OS keyring.",
            path.display()
        ),
        LoginKey::Reference(_) => println!(
            "Saved profile \"{name}\" to {}. `dn` will resolve its key with `op read` on every call.",
            path.display()
        ),
    }
    print_default_change(previous_default.as_deref(), &auth);
    print!("{}", render_profiles(&auth));
    Ok(())
}

/// Record a login in auth.json under the lock: re-read it and apply only this
/// login's change, so a concurrent login or migration isn't overwritten.
/// Returns the saved file, the previous default and its path.
fn save_login(
    args: &AuthLoginArgs,
    name: &str,
    key: &LoginKey,
) -> anyhow::Result<(
    AuthFile,
    Option<Profile>,
    Option<String>,
    std::path::PathBuf,
)> {
    let _lock = AuthLock::acquire()?;
    let (mut auth, corrupt) = AuthFile::load_or_reset()?;
    if let Some(err) = corrupt {
        eprintln!(
            "warning: replacing unreadable auth file ({err:#}); any keys its profiles kept in \
             the OS keyring (service {}) are left there",
            keystore::SERVICE
        );
    }
    let replaced = auth.profiles.get(name).cloned();
    let mut profile = replaced.clone().unwrap_or_default();
    if let Some(url) = &args.api_url {
        profile.api_url = Some(normalize_api_url(url));
    }
    profile.key = Some(match key {
        LoginKey::Keyring(_) => KEYRING.to_string(),
        LoginKey::Reference(reference) => reference.clone(),
    });
    auth.profiles.insert(name.to_string(), profile);
    // Like `gh` and `tg`, the profile just logged in to becomes the default,
    // unless asked not to.
    let previous_default = auth.default_profile.clone();
    if !args.keep_default {
        auth.default_profile = Some(name.to_string());
    }
    auth.ensure_default();
    let path = auth.save()?;
    Ok((auth, replaced, previous_default, path))
}

/// Delete a profile's keyring entry that nothing points at any more. Failing
/// to is only a warning, and `false`: the profile change it follows has
/// already happened.
fn forget_keyring_entry(profile: &str) -> bool {
    match keystore::delete(profile) {
        Ok(_) => true,
        Err(e) => {
            eprintln!(
                "warning: could not remove the OS keyring entry for profile {profile:?} \
                 ({e:#}); it is no longer used"
            );
            false
        }
    }
}

/// Warn about profiles logged out and deleted from the keyring that a
/// concurrent `auth login` has since saved again: the key that login stored
/// may be the one just deleted.
fn warn_relogged_profiles(forgotten: &[String]) {
    if forgotten.is_empty() {
        return;
    }
    let Ok(_lock) = AuthLock::acquire() else {
        return;
    };
    let Ok(auth) = AuthFile::load() else {
        return;
    };
    for name in forgotten {
        if auth.profiles.get(name).is_some_and(|p| p.uses_keyring()) {
            eprintln!(
                "warning: profile {name:?} was logged in again while it was being logged \
                 out, and its key may have been removed; run `dn auth login --profile {name}`"
            );
        }
    }
}

/// Put back the keyring entry a failed login replaced. With no `old_key` to
/// restore, an entry the profile didn't use before is removed, and one it did
/// use (but couldn't be read) is left holding the new key.
fn restore_keyring_entry(profile: &str, old_key: Option<&str>, had_entry: bool) {
    match old_key {
        Some(old) => {
            if let Err(e) = keystore::set(profile, old) {
                eprintln!(
                    "warning: could not restore the previous key for profile {profile:?} \
                     in the OS keyring ({e:#}); it now holds the key just entered"
                );
            }
        }
        None if !had_entry => {
            forget_keyring_entry(profile);
        }
        None => eprintln!(
            "warning: the OS keyring entry for profile {profile:?} now holds the key \
             just entered, though the profile was not saved"
        ),
    }
}

/// Say when a command changed the default profile.
fn print_default_change(previous: Option<&str>, auth: &AuthFile) {
    let current = auth.default_profile.as_deref();
    if current != previous {
        match current {
            Some(name) => println!("Default profile is now \"{name}\"."),
            None => println!("No profiles remain."),
        }
    }
}

/// `{default_profile, profiles: [{name, default, api_url, key_source,
/// api_key_ref}]}`,
/// the shape `auth list` prints and every command that changes profiles
/// includes.
fn profiles_json(auth: &AuthFile) -> Value {
    let default = auth.default_profile.as_deref();
    let profiles: Vec<Value> = auth
        .profiles
        .iter()
        .map(|(name, profile)| {
            json!({
                "name": name,
                "default": default == Some(name.as_str()),
                "api_url": stored_api_url(Some(profile)),
                // The same names `auth status` reports as `source`.
                "key_source": if profile.uses_keyring() {
                    json!("keyring")
                } else if profile.key.is_some() {
                    json!("file")
                } else {
                    Value::Null
                },
                "api_key_ref": profile.key.as_deref().filter(|_| !profile.uses_keyring()),
            })
        })
        .collect();
    json!({ "default_profile": default, "profiles": profiles })
}

/// The profiles as a table, `*` marking the default.
fn render_profiles(auth: &AuthFile) -> String {
    if auth.profiles.is_empty() {
        return "No profiles. Run `dn auth login` to create one.\n".to_string();
    }
    let default = auth.default_profile.as_deref();
    let rows: Vec<Vec<String>> = auth
        .profiles
        .iter()
        .map(|(name, profile)| {
            vec![
                if default == Some(name.as_str()) {
                    "*"
                } else {
                    ""
                }
                .to_string(),
                name.clone(),
                stored_api_url(Some(profile)),
                profile.key.clone().unwrap_or_default(),
            ]
        })
        .collect();
    render_table(&["", "PROFILE", "API URL", "KEY"], &rows)
}

/// Reject an `--api-url` that can't be an API base before anything is saved.
pub fn validate_api_url(url: &str) -> anyhow::Result<()> {
    check_api_url(url).context("--api-url")
}

/// Only an API response is evidence the key itself was rejected; anything
/// else (offline, bad `DEFINED_API_URL`) is a reachability problem.
fn label_verify_error(err: anyhow::Error) -> anyhow::Error {
    if err.downcast_ref::<ApiError>().is_some() {
        err.context("the API rejected the key")
    } else {
        err.context("could not reach the API to verify the key")
    }
}

/// The environment shadows the file, so a login/logout under an exported
/// `DEFINED_API_KEY` changes nothing for the next call. Say so.
fn warn_env_override() -> bool {
    let set = api_key_env_is_set();
    if set {
        eprintln!(
            "warning: DEFINED_API_KEY is set in this environment and takes precedence over the stored key."
        );
    }
    set
}

pub const KEY_STDIN_NEEDS_PIPE: &str = "--key-stdin reads the key from a pipe, and stdin is a \
     terminal; under --json `auth login` never prompts, so pipe the key in";

pub const LOGIN_NEEDS_KEY: &str = "pass --key-stdin, or --ref op://… to use 1Password: \
     `auth login` only prompts for the key in a terminal, and never under --json";

/// Far longer than any Defined Networking API key, and within Windows
/// Credential Manager's 2560-byte limit on a stored secret once the key is
/// stored as UTF-16 (two bytes per ASCII character).
const MAX_KEY_LEN: usize = 1280;

/// The key a login stores, or the 1Password reference that stands for it.
enum LoginKey {
    Keyring(String),
    Reference(String),
}

/// Read the key for `auth login`: from stdin with `--key-stdin`, else from a
/// hidden prompt. [`preflight`](crate::preflight) has already refused a non-interactive run
/// with neither `--key-stdin` nor `--ref`.
fn read_login_key(args: &AuthLoginArgs) -> anyhow::Result<LoginKey> {
    if let Some(reference) = &args.reference {
        let reference = normalize_op_ref(reference);
        validate_op_ref(&reference)?;
        return Ok(LoginKey::Reference(reference));
    }
    // `--key-stdin` from a terminal would echo the key as it's typed, so a
    // terminal always gets the hidden prompt.
    let key = if args.key_stdin && !std::io::stdin().is_terminal() {
        // Room for surrounding whitespace; a read that fills the buffer
        // was cut short, so it can't be judged after trimming.
        let limit = 2 * MAX_KEY_LEN;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(std::io::stdin().lock(), limit as u64),
            &mut bytes,
        )
        .context("failed to read the API key from stdin")?;
        if bytes.len() == limit {
            bail!("the input is longer than {MAX_KEY_LEN} bytes, so it isn't an API key");
        }
        String::from_utf8(bytes)
            .map_err(|_| anyhow!("an API key is printable ASCII; check what was piped in"))?
    } else {
        eprintln!(
            "Create an API key at {API_KEYS_URL} (pick only the permissions you need).\n\
             It will be stored in the OS keyring. To store a 1Password reference instead, \
             pass --ref op://vault/item/field."
        );
        rpassword::prompt_password("API key (input hidden): ")
            .context("failed to read the API key")?
    };
    let key = key.trim().to_string();
    if key.is_empty() {
        bail!("no API key entered");
    }
    if key.len() > MAX_KEY_LEN {
        bail!("the input is longer than {MAX_KEY_LEN} bytes, so it isn't an API key");
    }
    if key.starts_with("op://") {
        bail!("that is a 1Password secret reference, not a key; pass it with --ref instead");
    }
    if !key.bytes().all(|b| b.is_ascii_graphic()) {
        bail!(
            "an API key is printable ASCII with no spaces or line breaks; check what was entered"
        );
    }
    Ok(LoginKey::Keyring(key))
}

/// Read-only introspection: never resolves a secret and never fails on a
/// misconfigured key — unreadable credentials, a bad reference, or a blank
/// env var is reported as `source: "invalid"` so callers can branch on it.
pub fn auth_status(profile_flag: Option<&str>, json: bool) -> anyhow::Result<()> {
    let auth_path = auth_path()?;
    let active = Active::load(profile_flag);
    let profile = active.as_ref().ok().and_then(|a| a.profile.as_ref());
    let api_url = api_url(profile);
    let profile_name = active.as_ref().ok().and_then(|a| a.profile_name.clone());
    let source = active.as_ref().map(|a| a.source.as_ref());
    let (label, reference, message) = match &source {
        Ok(Some(s)) => (s.label(), s.reference(), None),
        Ok(None) => ("none", None, None),
        Err(e) => ("invalid", None, Some(format!("{e:#}"))),
    };

    if json {
        return print_json(&json!({
            "source": label,
            "profile": profile_name,
            "api_key_ref": reference,
            "message": message,
            "auth_path": auth_path,
            "api_url": api_url,
        }));
    }

    if let Some(name) = &profile_name {
        println!("Profile: {name}");
    }
    match &source {
        Ok(None) => {
            println!("No API key configured. Run `dn auth login` or set DEFINED_API_KEY.")
        }
        Ok(Some(KeySource::Env(_))) => {
            println!("API key: DEFINED_API_KEY (raw value in environment)")
        }
        Ok(Some(KeySource::EnvRef(r))) => {
            println!("API key: DEFINED_API_KEY -> {r} (resolved via op read)")
        }
        Ok(Some(KeySource::FileRef(r))) => println!(
            "API key: {r} (from {}, resolved via op read)",
            auth_path.display()
        ),
        Ok(Some(KeySource::Keyring(profile))) => {
            println!("API key: OS keyring (entry for profile {profile:?})")
        }
        Err(e) => println!("API key: invalid — {e:#}"),
    }
    println!("API URL: {api_url}");
    Ok(())
}

pub fn auth_list(json: bool) -> anyhow::Result<()> {
    let auth = AuthFile::load()?;
    if json {
        return print_json(&profiles_json(&auth));
    }
    print!("{}", render_profiles(&auth));
    Ok(())
}

pub fn auth_switch(args: &AuthSwitchArgs, json: bool) -> anyhow::Result<()> {
    let _lock = AuthLock::acquire()?;
    let mut auth = AuthFile::load()?;
    if !auth.profiles.contains_key(&args.name) {
        return Err(InvalidArgument(anyhow!(
            "no profile named {:?} (see `dn auth list`)",
            args.name
        ))
        .into());
    }
    let previous_default = auth.default_profile.clone();
    auth.default_profile = Some(args.name.clone());
    let path = auth.save()?;
    if json {
        let mut out = profiles_json(&auth);
        out.as_object_mut().unwrap().extend([
            ("ok".into(), json!(true)),
            ("auth_path".into(), json!(path)),
        ]);
        return print_json(&out);
    }
    if previous_default.as_deref() == Some(args.name.as_str()) {
        println!("\"{}\" is already the default profile.", args.name);
    } else {
        print_default_change(previous_default.as_deref(), &auth);
    }
    print!("{}", render_profiles(&auth));
    Ok(())
}

pub fn auth_logout(
    args: &AuthLogoutArgs,
    profile_flag: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    let path = auth_path()?;
    let lock = AuthLock::acquire()?;
    // Keyring entries to delete once the lock is released: deleting can wait
    // on an unlock prompt, and other `dn` calls shouldn't wait with it.
    let mut forget = Vec::new();
    // `--all` removes the file without reading it, so it also clears a
    // corrupt file or one from a newer `dn`. Removing one profile needs a
    // readable file; an unreadable one is an error, never a deletion.
    let mut auth = if args.all {
        AuthFile::default()
    } else {
        AuthFile::load()?
    };
    let previous_default = auth.default_profile.clone();
    let (removed, profile) = if args.all {
        // Keyring entries are found through the file, so read it if it can
        // be read; an unreadable one can't say which entries are ours.
        match AuthFile::load() {
            Ok(stored) => forget.extend(
                stored
                    .profiles
                    .into_iter()
                    .filter(|(_, p)| p.uses_keyring())
                    .map(|(name, _)| name),
            ),
            Err(e) => eprintln!(
                "warning: could not read the profiles ({e:#}), so any keys they kept in the \
                 OS keyring (service {}) are left there",
                keystore::SERVICE
            ),
        }
        (remove_auth_file(&path)?, None)
    } else {
        let requested = requested_profile(profile_flag)?;
        match select_profile(requested.as_deref(), &auth)? {
            None => (false, None),
            Some((name, _)) => {
                let removed = auth.profiles.remove(&name);
                auth.ensure_default();
                if auth.profiles.is_empty() {
                    remove_auth_file(&path)?;
                } else {
                    auth.save()?;
                }
                if removed.is_some_and(|p| p.uses_keyring()) {
                    forget.push(name.clone());
                }
                (true, Some(name))
            }
        }
    };
    drop(lock);
    let keyring_left: Vec<&String> = forget
        .iter()
        .filter(|name| !forget_keyring_entry(name))
        .collect();
    warn_relogged_profiles(&forget);
    let env_override = warn_env_override();

    if json {
        let mut out = profiles_json(&auth);
        out.as_object_mut().unwrap().extend([
            ("ok".into(), json!(true)),
            ("removed".into(), json!(removed)),
            ("profile".into(), json!(profile)),
            ("auth_path".into(), json!(path)),
            ("env_override".into(), json!(env_override)),
            ("keyring_left".into(), json!(keyring_left)),
        ]);
        return print_json(&out);
    }
    match (&profile, removed) {
        (Some(name), _) => println!("Removed profile \"{name}\"."),
        (None, true) => println!("Removed {}.", path.display()),
        (None, false) => {
            println!("No stored credentials to remove.");
            return Ok(());
        }
    }
    print_default_change(previous_default.as_deref(), &auth);
    if !auth.profiles.is_empty() {
        print!("{}", render_profiles(&auth));
    }
    Ok(())
}

/// Delete the credentials file (through a symlink, then the link itself).
/// `false` when there was nothing to delete.
fn remove_auth_file(path: &std::path::Path) -> anyhow::Result<bool> {
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let removed = match std::fs::remove_file(&target) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            return Err(e).with_context(|| format!("failed to remove {}", target.display()));
        }
    };
    if removed && target != path {
        let _ = std::fs::remove_file(path);
    }
    Ok(removed)
}
