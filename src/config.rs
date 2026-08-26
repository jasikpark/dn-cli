use std::fmt;
use std::fs;
use std::io::ErrorKind;
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

/// On-disk config. Holds a 1Password *secret reference* for the API key, never
/// the key itself — the secret is fetched with `op read` on every invocation,
/// so each call goes through 1Password's own unlock gate.
///
/// Keys this binary doesn't model are preserved verbatim in `extra`, so a
/// round-trip through an older `dn` never drops what a newer one wrote.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl FileConfig {
    pub fn is_empty(&self) -> bool {
        self.api_key_ref.is_none() && self.api_url.is_none() && self.extra.is_empty()
    }

    /// Read the config file, treating a missing file as an empty config. A
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

    /// Like [`load`](Self::load), but an unparsable file yields an empty config
    /// plus the parse error, so commands that are about to overwrite or remove
    /// the file can proceed instead of being wedged by their own corrupt state.
    pub fn load_or_reset() -> Result<(Self, Option<anyhow::Error>)> {
        match Self::load() {
            Ok(cfg) => Ok((cfg, None)),
            Err(e) if e.downcast_ref::<serde_json::Error>().is_some() => {
                Ok((Self::default(), Some(e)))
            }
            Err(e) => Err(e),
        }
    }

    /// Write the config (pretty JSON, owner-only on unix, atomic replace),
    /// creating the parent directory. Always writes — an empty config is `{}`;
    /// deleting the file is the caller's decision.
    pub fn save(&self) -> Result<PathBuf> {
        let path = config_path()?;
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

/// Write via a freshly created `<path>.tmp` and rename over the target. A
/// new file is the only place `mode` applies (open(2) ignores it for an
/// existing inode), and the rename means a crash mid-write can never leave a
/// truncated config behind.
fn write_private(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("json.tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .with_context(|| format!("failed to open {}", tmp.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    drop(file);
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("failed to replace {}", path.display()));
    }
    Ok(())
}

/// `$DN_CONFIG_DIR/config.json`, else the platform config dir:
/// `$XDG_CONFIG_HOME/dn` → `~/.config/dn` on unix (macOS included — CLI
/// convention, not `~/Library`), `%APPDATA%\dn` on Windows.
pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
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

    /// Detect the active source from the environment and an already-loaded
    /// file config, without resolving any secret.
    pub fn detect(file: &FileConfig) -> Result<Option<Self>> {
        resolve_key_source(api_key_env().as_deref(), file.api_key_ref.as_deref())
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
        validate_op_ref(r).context("config api_key_ref is an invalid op:// reference")?;
        return Ok(Some(KeySource::FileRef(r.to_string())));
    }
    Ok(None)
}

/// A 1Password secret reference is `op://vault/item/field` or
/// `op://vault/item/section/field`; every segment must be non-empty.
pub fn validate_op_ref(s: &str) -> Result<()> {
    let s = s.trim();
    let Some(path) = s.strip_prefix(OP_SCHEME) else {
        bail!("expected a 1Password secret reference starting with {OP_SCHEME}, got {s:?}");
    };
    let segments: Vec<&str> = path.split('/').collect();
    if !(3..=4).contains(&segments.len()) || segments.iter().any(|seg| seg.trim().is_empty()) {
        bail!(
            "expected {OP_SCHEME}vault/item/field (optionally {OP_SCHEME}vault/item/section/field), got {s:?}"
        );
    }
    Ok(())
}

/// Resolve a secret reference through the 1Password CLI. This is the
/// per-invocation gate: `op` prompts for unlock (biometric or password) per
/// its own session policy, so a stored reference alone grants nothing.
///
/// stdin and stderr are inherited so `op` can prompt for a password and show
/// its own "waiting for authorization" progress; only stdout is captured.
pub fn op_read(reference: &str) -> Result<String> {
    let output = Command::new("op")
        .args(["read", "--no-newline", reference])
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
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
        bail!("`op read {reference}` failed (exit {code}); see op's output above");
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
        let file = FileConfig::load()?;
        let source = KeySource::detect(&file)?.ok_or_else(|| {
            anyhow!(
                "No API key configured. Run `dn auth login` (stores a 1Password secret \
                 reference) or set {API_KEY_ENV}."
            )
        })?;
        let api_key = match source {
            KeySource::Env(key) => key,
            KeySource::EnvRef(r) | KeySource::FileRef(r) => op_read(&r)?,
        };
        Ok(Self::with_key(api_key, &file))
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
            api_key_ref: Some("op://v/i/f".into()),
            ..FileConfig::default()
        };
        let text = serde_json::to_string(&cfg).unwrap();
        assert_eq!(text, r#"{"api_key_ref":"op://v/i/f"}"#);
        let back: FileConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(back, cfg);
        assert!(FileConfig::default().is_empty());
        assert!(!cfg.is_empty());
    }

    #[test]
    fn file_config_preserves_unknown_keys() {
        let text = r#"{"api_key_ref":"op://v/i/f","future_flag":true}"#;
        let mut cfg: FileConfig = serde_json::from_str(text).unwrap();
        assert_eq!(
            cfg.extra.get("future_flag"),
            Some(&serde_json::Value::Bool(true))
        );
        cfg.api_key_ref = None;
        assert!(!cfg.is_empty(), "unknown keys keep the config non-empty");
        let back: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(back, serde_json::json!({ "future_flag": true }));
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
