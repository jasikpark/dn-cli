use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_API_URL: &str = "https://api.defined.net";
const OP_SCHEME: &str = "op://";

/// Resolved runtime configuration: a usable bearer token plus the API base.
pub struct Config {
    pub api_key: String,
    pub api_url: String,
}

/// On-disk config. Holds a 1Password *secret reference* for the API key, never
/// the key itself — the secret is fetched with `op read` on every invocation,
/// so each call goes through 1Password's own unlock gate.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
}

impl FileConfig {
    pub fn is_empty(&self) -> bool {
        self.api_key_ref.is_none() && self.api_url.is_none()
    }

    /// Read the config file, treating a missing file as an empty config.
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("failed to parse {}", path.display())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }

    /// Write the config (pretty JSON, owner-only permissions on unix), creating
    /// the parent directory. An empty config removes the file instead.
    pub fn save(&self) -> Result<PathBuf> {
        let path = config_path()?;
        if self.is_empty() {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("failed to remove {}", path.display()));
                }
            }
            return Ok(path);
        }

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

#[cfg(unix)]
fn write_private(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, text: &str) -> Result<()> {
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
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

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Where the API key comes from, in precedence order. The environment always
/// wins so CI and agents can inject a key without touching the config file.
#[derive(Debug, Clone, PartialEq)]
pub enum KeySource {
    /// `DEFINED_API_KEY` holds the raw key.
    Env(String),
    /// `DEFINED_API_KEY` holds an `op://` reference to resolve.
    EnvRef(String),
    /// The config file's `api_key_ref`.
    FileRef(String),
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

    /// Detect the active source without resolving any secret.
    pub fn detect() -> Result<Option<Self>> {
        let env_key = non_empty_env("DEFINED_API_KEY");
        let file = FileConfig::load()?;
        resolve_key_source(env_key.as_deref(), file.api_key_ref.as_deref())
    }
}

/// Pure precedence: env (raw or `op://`) beats the file reference. `None` when
/// neither is set; `Err` when a reference is present but malformed.
pub fn resolve_key_source(
    env_key: Option<&str>,
    file_ref: Option<&str>,
) -> Result<Option<KeySource>> {
    if let Some(key) = env_key.map(str::trim).filter(|k| !k.is_empty()) {
        return if key.starts_with(OP_SCHEME) {
            validate_op_ref(key).context("DEFINED_API_KEY holds an invalid op:// reference")?;
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
pub fn op_read(reference: &str) -> Result<String> {
    let output = Command::new("op")
        .args(["read", "--no-newline", reference])
        .output()
        .map_err(|e| match e.kind() {
            ErrorKind::NotFound => anyhow!(
                "the 1Password CLI (`op`) is not installed or not on PATH.\n\
                 Install it: https://developer.1password.com/docs/cli/get-started/"
            ),
            _ => anyhow!(e).context("failed to run `op read`"),
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!("`op read {reference}` failed: {stderr}");
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

impl Config {
    /// Build a config from an already-resolved key, honouring `DEFINED_API_URL`
    /// over the file's `api_url` over the default.
    pub fn with_key(api_key: String, file: &FileConfig) -> Self {
        let api_url = non_empty_env("DEFINED_API_URL")
            .or_else(|| file.api_url.clone())
            .unwrap_or_else(|| DEFAULT_API_URL.to_string());
        Self { api_key, api_url }
    }

    /// Resolve the API key (running `op read` if the source is a reference)
    /// and the base URL. Only commands that talk to the API call this.
    pub fn load() -> Result<Self> {
        let file = FileConfig::load()?;
        let env_key = non_empty_env("DEFINED_API_KEY");
        let source = resolve_key_source(env_key.as_deref(), file.api_key_ref.as_deref())?
            .ok_or_else(|| {
                anyhow!(
                    "No API key configured. Run `dn auth login` (stores a 1Password secret \
                     reference) or set DEFINED_API_KEY."
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
    fn file_ref_used_when_env_absent_or_blank() {
        let got = resolve_key_source(Some("   "), Some(" op://v/i/f\n")).unwrap();
        assert_eq!(got, Some(KeySource::FileRef("op://v/i/f".into())));
        let got = resolve_key_source(None, Some("op://v/i/s/f")).unwrap();
        assert_eq!(got, Some(KeySource::FileRef("op://v/i/s/f".into())));
    }

    #[test]
    fn nothing_configured_is_none() {
        assert_eq!(resolve_key_source(None, None).unwrap(), None);
        assert_eq!(resolve_key_source(Some(""), Some("")).unwrap(), None);
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
    fn key_source_labels_and_refs() {
        assert_eq!(KeySource::Env("k".into()).label(), "env");
        assert_eq!(KeySource::Env("k".into()).reference(), None);
        assert_eq!(KeySource::EnvRef("op://v/i/f".into()).label(), "env-ref");
        assert_eq!(
            KeySource::FileRef("op://v/i/f".into()).reference(),
            Some("op://v/i/f")
        );
    }

    #[test]
    fn file_config_roundtrips_and_omits_none() {
        let cfg = FileConfig {
            api_key_ref: Some("op://v/i/f".into()),
            api_url: None,
        };
        let text = serde_json::to_string(&cfg).unwrap();
        assert_eq!(text, r#"{"api_key_ref":"op://v/i/f"}"#);
        let back: FileConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(back, cfg);
        assert!(FileConfig::default().is_empty());
        assert!(!cfg.is_empty());
    }
}
