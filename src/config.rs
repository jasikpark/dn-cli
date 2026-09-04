use std::fmt;
use std::fs;
use std::io::{ErrorKind, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_API_URL: &str = "https://api.defined.net";
const OP_SCHEME: &str = "op://";
const API_KEY_ENV: &str = "DEFINED_API_KEY";

/// Resolved runtime configuration: a usable bearer token plus the API base.
pub struct Config {
    pub api_key: String,
    pub api_url: String,
}

/// Settings file (`config.json`). Non-secret configuration like `api_url`.
/// Credentials live in [`AuthFile`] (`auth.json`).
///
/// Keys this binary doesn't model are preserved verbatim in `extra`, so a
/// round-trip through an older `dn` never drops what a newer one wrote.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl FileConfig {
    /// Read the settings file, treating a missing file as an empty config. A
    /// present-but-unparsable file is an error naming the path.
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("failed to parse {}", path.display())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }
}

/// Credentials file (`auth.json`). Separated from [`FileConfig`] so that
/// `dn auth logout` can delete credentials without touching settings.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_ref: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl AuthFile {
    pub fn load() -> Result<Self> {
        let path = auth_path()?;
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("failed to parse {}", path.display())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }

    pub fn load_or_reset() -> Result<(Self, Option<anyhow::Error>)> {
        Ok(match Self::load() {
            Ok(cfg) => (cfg, None),
            Err(e) => (Self::default(), Some(e)),
        })
    }

    pub fn save(&self) -> Result<PathBuf> {
        let path = auth_path()?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        write_private(&path, &text)?;
        Ok(path)
    }
}

/// Write to a per-process sibling temp file and rename it over the target. The
/// temp name carries this process's pid and is opened `create_new` (O_EXCL), so
/// two `dn` processes can never write the same temp and interleave, and the
/// open refuses to follow a symlink planted at the temp path. A freshly created
/// file is also the only place `mode` applies — open(2) ignores it for an
/// existing inode — so 0600 is guaranteed rather than inherited. The rename is
/// atomic within the directory, so a crash mid-write can never leave a
/// truncated config behind.
///
/// The target is canonicalized first because dotfile-managed configs are often
/// symlinks (`~/.config/dn/config.json` -> `~/dotfiles/dn.json`), and the write
/// has to land on the file the link points at instead of replacing the link.
fn write_private(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;

    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let name = target
        .file_name()
        .ok_or_else(|| anyhow!("{} is not a file path", target.display()))?;
    let tmp = target.with_file_name(format!(
        "{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = match opts.open(&tmp) {
        Ok(file) => file,
        // A temp this pid's predecessor left behind when it crashed mid-write.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            fs::remove_file(&tmp)
                .with_context(|| format!("failed to remove stale {}", tmp.display()))?;
            opts.open(&tmp)
                .with_context(|| format!("failed to open {}", tmp.display()))?
        }
        Err(e) => return Err(e).with_context(|| format!("failed to open {}", tmp.display())),
    };

    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("failed to write {}", tmp.display()));
    }
    if let Err(e) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("failed to replace {}", target.display()));
    }
    Ok(())
}

/// `$DN_CONFIG_DIR/config.json`, else the platform config dir:
/// `$XDG_CONFIG_HOME/dn` → `~/.config/dn` on unix (macOS included — CLI
/// convention, not `~/Library`), `%APPDATA%\dn` on Windows.
pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
}

pub fn auth_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("auth.json"))
}

fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = non_empty_env("DN_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if cfg!(windows) {
        return non_empty_env("APPDATA")
            .map(|d| PathBuf::from(d).join("dn"))
            .ok_or_else(|| anyhow!("APPDATA is not set; set DN_CONFIG_DIR instead"));
    }
    if let Some(dir) = non_empty_env("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(dir).join("dn"));
    }
    non_empty_env("HOME")
        .map(|h| PathBuf::from(h).join(".config").join("dn"))
        .ok_or_else(|| anyhow!("HOME is not set; set DN_CONFIG_DIR instead"))
}

/// An env var's trimmed value, or `None` if unset or blank.
fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// `DEFINED_API_KEY` as the resolver sees it: `None` when unset, `Some("")`
/// when set but blank (an error downstream — a blank key must never fall
/// through to someone else's stored reference).
fn api_key_env() -> Option<String> {
    std::env::var(API_KEY_ENV)
        .ok()
        .map(|v| v.trim().to_string())
}

/// Whether `DEFINED_API_KEY` is present at all, blank or not. Login/logout use
/// this to warn that the stored reference will be shadowed.
pub fn api_key_env_is_set() -> bool {
    std::env::var_os(API_KEY_ENV).is_some()
}

/// Where the API key comes from, in precedence order. The environment always
/// wins so CI and agents can inject a key without touching the config file.
#[derive(Clone, PartialEq)]
pub enum KeySource {
    /// `DEFINED_API_KEY` holds the raw key.
    Env(String),
    /// `DEFINED_API_KEY` holds an `op://` reference to resolve.
    EnvRef(String),
    /// The config file's `api_key_ref`.
    FileRef(String),
}

/// The raw env key never appears in debug output.
impl fmt::Debug for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySource::Env(_) => f.write_str("Env(<redacted>)"),
            KeySource::EnvRef(r) => f.debug_tuple("EnvRef").field(r).finish(),
            KeySource::FileRef(r) => f.debug_tuple("FileRef").field(r).finish(),
        }
    }
}

impl KeySource {
    pub fn label(&self) -> &'static str {
        match self {
            KeySource::Env(_) => "env",
            KeySource::EnvRef(_) => "env-ref",
            KeySource::FileRef(_) => "file",
        }
    }

    /// The `op://` reference, if this source is one. Safe to display; the raw
    /// env key deliberately has no accessor here.
    pub fn reference(&self) -> Option<&str> {
        match self {
            KeySource::Env(_) => None,
            KeySource::EnvRef(r) | KeySource::FileRef(r) => Some(r),
        }
    }

    /// Load the active source without resolving any secret. Stored credentials
    /// are only a fallback: a broken auth file must not block an environment
    /// key or mask an invalid environment key.
    pub fn load() -> Result<Option<Self>> {
        match resolve_key_source(api_key_env().as_deref(), None)? {
            Some(source) => Ok(Some(source)),
            None => {
                let auth = AuthFile::load()?;
                resolve_key_source(None, auth.api_key_ref.as_deref())
            }
        }
    }
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
        validate_op_ref(r).context("api_key_ref is an invalid op:// reference")?;
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

/// The API base: `DEFINED_API_URL` over the file's `api_url` over the
/// default, trimmed and without a trailing slash so path concatenation never
/// yields `//v2/...`.
pub fn api_url(file: &FileConfig) -> String {
    let raw = non_empty_env("DEFINED_API_URL")
        .or_else(|| {
            file.api_url
                .as_deref()
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| DEFAULT_API_URL.to_string());
    normalize_api_url(&raw)
}

fn normalize_api_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

impl Config {
    /// Build a config from an already-resolved key.
    pub fn with_key(api_key: String, file: &FileConfig) -> Self {
        Self {
            api_key,
            api_url: api_url(file),
        }
    }

    /// Resolve the API key (running `op read` if the source is a reference)
    /// and the base URL. Only commands that talk to the API call this.
    pub fn load() -> Result<Self> {
        let source = KeySource::load()?;
        let settings = FileConfig::load()?;
        let source = source.ok_or_else(|| {
            anyhow!(
                "No API key configured. Run `dn auth login` (stores a 1Password secret \
                 reference) or set {API_KEY_ENV}."
            )
        })?;
        let api_key = match source {
            KeySource::Env(key) => key,
            KeySource::EnvRef(r) | KeySource::FileRef(r) => op_read(&r)?,
        };
        Ok(Self::with_key(api_key, &settings))
    }
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
        let err = validate_op_ref("op://Personal/caleb@defined.net - DN API Key/credential")
            .unwrap_err()
            .to_string();
        assert!(err.contains("'@'"), "{err}");
        assert!(err.contains("item's ID"), "{err}");
        assert!(validate_op_ref("op://Personal/DN API: hosts/credential").is_err());
        validate_op_ref("op://Personal/z3sn5zvnff527fab3zrfqz7ymu/credential").unwrap();
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
        validate_op_ref("op://Personal/z3sn/credential").unwrap();
        validate_op_ref("op://Personal/z3sn/Section One/credential").unwrap();
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
    fn file_config_roundtrips_and_omits_none() {
        let cfg = FileConfig {
            api_url: Some("https://api.test".into()),
            ..FileConfig::default()
        };
        let text = serde_json::to_string(&cfg).unwrap();
        assert_eq!(text, r#"{"api_url":"https://api.test"}"#);
        let back: FileConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(back, cfg);
        let empty = serde_json::to_string(&FileConfig::default()).unwrap();
        assert_eq!(empty, "{}");
    }

    #[test]
    fn file_config_preserves_unknown_keys() {
        let text = r#"{"api_url":"https://api.test","future_flag":true}"#;
        let cfg: FileConfig = serde_json::from_str(text).unwrap();
        assert_eq!(
            cfg.extra.get("future_flag"),
            Some(&serde_json::Value::Bool(true))
        );
        let back: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(
            back,
            serde_json::json!({ "api_url": "https://api.test", "future_flag": true })
        );
    }

    #[test]
    fn auth_file_roundtrips_and_omits_none() {
        let auth = AuthFile {
            api_key_ref: Some("op://v/i/f".into()),
            ..AuthFile::default()
        };
        let text = serde_json::to_string(&auth).unwrap();
        assert_eq!(text, r#"{"api_key_ref":"op://v/i/f"}"#);
        let back: AuthFile = serde_json::from_str(&text).unwrap();
        assert_eq!(back, auth);
        let empty = serde_json::to_string(&AuthFile::default()).unwrap();
        assert_eq!(empty, "{}");
    }

    /// A per-process scratch directory, so parallel tests never share one.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dn-cli-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The temp path [`write_private`] picks for a target in this process.
    fn temp_sibling(target: &Path) -> PathBuf {
        target.with_file_name(format!(
            "{}.{}.tmp",
            target.file_name().unwrap().to_string_lossy(),
            std::process::id()
        ))
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_private_leaves_no_temp_file_and_sets_mode() {
        let dir = scratch_dir("write-private");
        let target = dir.join("config.json");

        write_private(&target, "{}\n").unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "{}\n");
        let entries: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries, vec![target.clone()], "temp file left behind");
        #[cfg(unix)]
        assert_eq!(mode_of(&target), 0o600, "{:o}", mode_of(&target));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_private_replaces_a_preexisting_stale_temp() {
        let dir = scratch_dir("stale-temp");
        let target = dir.join("config.json");
        let stale = temp_sibling(&target);
        fs::write(&stale, "stale").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&stale, fs::Permissions::from_mode(0o666)).unwrap();
        }

        write_private(&target, "fresh\n").unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "fresh\n");
        assert!(!stale.exists(), "stale temp survived the write");
        #[cfg(unix)]
        assert_eq!(mode_of(&target), 0o600, "{:o}", mode_of(&target));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn write_private_writes_through_a_symlinked_target() {
        let dir = scratch_dir("symlinked-target");
        let real = dir.join("dotfiles-dn.json");
        fs::write(&real, "old\n").unwrap();
        let link = dir.join("config.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_private(&link, "new\n").unwrap();

        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink was replaced by a regular file"
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), "new\n");
        let _ = fs::remove_dir_all(&dir);
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

    #[test]
    fn api_url_is_trimmed_and_unslashed() {
        assert_eq!(
            normalize_api_url(" https://api.defined.net/ "),
            "https://api.defined.net"
        );
        assert_eq!(normalize_api_url("https://x.test//"), "https://x.test");
        assert_eq!(normalize_api_url(DEFAULT_API_URL), DEFAULT_API_URL);
    }
}
