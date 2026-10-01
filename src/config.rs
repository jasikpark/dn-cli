use std::collections::BTreeMap;
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
const PROFILE_ENV: &str = "DN_PROFILE";
/// The `auth.json` layout this binary writes. Files without a `version` are
/// the single-reference layout that came before profiles.
const AUTH_VERSION: u64 = 2;
/// The profile an old single-reference `auth.json` migrates into, and the one
/// `auth login` creates when nothing else is named.
pub const DEFAULT_PROFILE: &str = "default";
/// A profile `key` meaning "the OS keyring holds it, under the profile name".
pub const KEYRING: &str = "keyring";

/// Resolved runtime configuration: a usable bearer token plus the API base.
pub struct Config {
    pub api_key: String,
    pub api_url: String,
    /// The profile the URL came from, for [`Config::non_default_url_note`].
    pub profile: Option<String>,
}

/// One named account: which API to talk to and where its key comes from.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Falls back to https://api.defined.net when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    /// Where the API key is: [`KEYRING`] for the OS keyring, or a 1Password
    /// secret reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Credentials file (`auth.json`): named profiles and which one is the
/// default. Whenever there are profiles, the default names one of them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthFile {
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Profile {
    /// Whether this profile's key lives in the OS keyring.
    pub fn uses_keyring(&self) -> bool {
        self.key.as_deref().map(str::trim) == Some(KEYRING)
    }
}

impl Default for AuthFile {
    fn default() -> Self {
        Self {
            version: AUTH_VERSION,
            default_profile: None,
            profiles: BTreeMap::new(),
            extra: serde_json::Map::new(),
        }
    }
}

/// An `auth.json` whose `version` this binary doesn't know.
#[derive(Debug)]
pub struct UnsupportedAuthVersion(String);

impl fmt::Display for UnsupportedAuthVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported auth.json version {} (written by a newer dn?); upgrade dn, \
             or run `dn auth logout --all` to discard it",
            self.0
        )
    }
}

impl std::error::Error for UnsupportedAuthVersion {}

/// An exclusive advisory lock on the credentials, held while a command reads,
/// changes and writes `auth.json` (and, when migrating, `config.json`), so
/// concurrent `dn` processes can't lose each other's changes. It lives in a
/// separate `auth.json.lock` because `auth.json` itself is replaced by rename.
/// Released on drop.
pub struct AuthLock(#[allow(dead_code)] fs::File);

impl AuthLock {
    pub fn acquire() -> Result<Self> {
        let path = config_dir()?.join("auth.json.lock");
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        file.lock()
            .with_context(|| format!("failed to lock {}", path.display()))?;
        Ok(Self(file))
    }
}

/// The `auth.json` layout before profiles: one reference, no `version`.
#[derive(Deserialize)]
struct LegacyAuthFile {
    #[serde(default)]
    api_key_ref: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl From<LegacyAuthFile> for AuthFile {
    fn from(legacy: LegacyAuthFile) -> Self {
        let mut auth = AuthFile {
            extra: legacy.extra,
            ..AuthFile::default()
        };
        if let Some(reference) = legacy.api_key_ref.filter(|r| !r.trim().is_empty()) {
            let profile = Profile {
                key: Some(reference),
                ..Profile::default()
            };
            auth.profiles.insert(DEFAULT_PROFILE.to_string(), profile);
            auth.default_profile = Some(DEFAULT_PROFILE.to_string());
        }
        auth
    }
}

impl AuthFile {
    /// Parse either layout. The flag is true for the old single-reference
    /// layout, which comes back already converted to profiles.
    ///
    /// A hand-edited default that is missing or names no profile is repaired
    /// in memory (see [`AuthFile::ensure_default`]), so callers can rely on a
    /// default whenever there are profiles.
    fn parse(text: &str) -> Result<(Self, bool)> {
        let value: serde_json::Value = serde_json::from_str(text)?;
        let (mut auth, legacy) = match value.get("version") {
            None => (
                serde_json::from_value::<LegacyAuthFile>(value)?.into(),
                true,
            ),
            Some(version) if version.as_u64() == Some(AUTH_VERSION) => {
                (serde_json::from_value::<AuthFile>(value)?, false)
            }
            Some(version) => return Err(UnsupportedAuthVersion(version.to_string()).into()),
        };
        auth.ensure_default();
        Ok((auth, legacy))
    }

    /// Read the credentials file, treating a missing file as no profiles. An
    /// old-layout file is converted in memory; see [`migrate_to_profiles`].
    pub fn load() -> Result<Self> {
        let path = auth_path()?;
        match fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text)
                .map(|(auth, _)| auth)
                .with_context(|| format!("failed to parse {}", path.display())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }

    /// Like [`AuthFile::load`], but an unparsable file comes back as no
    /// profiles plus the error, for `auth login` to replace. A file from a
    /// newer `dn` is still an error: replacing it would lose its profiles.
    pub fn load_or_reset() -> Result<(Self, Option<anyhow::Error>)> {
        match Self::load() {
            Ok(cfg) => Ok((cfg, None)),
            Err(e) if e.downcast_ref::<UnsupportedAuthVersion>().is_some() => Err(e),
            Err(e) => Ok((Self::default(), Some(e))),
        }
    }

    pub fn save(&self) -> Result<PathBuf> {
        let path = auth_path()?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        write_private(&path, &self.to_text()?)?;
        Ok(path)
    }

    /// Keep the default pointing at a real profile: when it is unset or names
    /// a profile that no longer exists, pick the first one by name. Returns
    /// the newly chosen default, if it changed.
    pub fn ensure_default(&mut self) -> Option<String> {
        let valid = self
            .default_profile
            .as_ref()
            .is_some_and(|d| self.profiles.contains_key(d));
        if valid {
            return None;
        }
        self.default_profile = self.profiles.keys().next().cloned();
        self.default_profile.clone()
    }

    fn to_text(&self) -> Result<String> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }
}

/// What [`migrate_to_profiles`] did, for stderr: notices of what moved, and
/// warnings for what couldn't be done.
#[derive(Debug, Default)]
pub struct Migration {
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
}

/// The parsed pieces migration looks at: the credentials (converted in
/// memory if old), whether they were in the old layout, and `config.json`
/// as a JSON object if it parses.
struct MigrationInputs {
    auth: AuthFile,
    legacy: bool,
    config: Option<serde_json::Map<String, serde_json::Value>>,
}

impl MigrationInputs {
    /// `None` when `auth.json` can't be read or parsed; the command itself
    /// reports that.
    fn read(auth_path: &Path, config_path: &Path) -> Option<Self> {
        let (auth, legacy) = match read_optional(auth_path).ok()? {
            None => (AuthFile::default(), false),
            Some(text) => AuthFile::parse(&text).ok()?,
        };
        let config = read_optional(config_path)
            .ok()
            .flatten()
            .and_then(|text| serde_json::from_str(&text).ok());
        Some(Self {
            auth,
            legacy,
            config,
        })
    }

    fn needed(&self) -> bool {
        self.legacy
            || self
                .config
                .as_ref()
                .is_some_and(|c| c.contains_key("api_url"))
    }
}

/// Bring credentials into the profiles layout. Every `dn` call runs this
/// first, so old layouts disappear on first contact:
///
/// - an `auth.json` from before profiles (one `api_key_ref`, no `version`)
///   becomes a `default` profile;
/// - `config.json`'s `api_url` moves into the default profile (unless that
///   profile already has one) and is removed from `config.json`, which is
///   deleted once empty.
///
/// It never fails the command. The common case, nothing to migrate, reads
/// without locking; otherwise the work is redone under [`AuthLock`], so
/// parallel calls migrate once and can't lose a concurrent `auth login`.
/// `auth.json` is written before `config.json` is stripped, so a failure in
/// between leaves the URL in both places, never in neither.
pub fn migrate_to_profiles() -> Migration {
    let mut migration = Migration::default();
    let (Ok(auth_path), Ok(config_path)) = (auth_path(), config_path()) else {
        return migration;
    };
    if !MigrationInputs::read(&auth_path, &config_path).is_some_and(|m| m.needed()) {
        return migration;
    }
    let _lock = match AuthLock::acquire() {
        Ok(lock) => lock,
        Err(e) => {
            migration.warnings.push(format!(
                "could not migrate credentials ({e:#}); using them as-is and retrying next time"
            ));
            return migration;
        }
    };
    let Some(MigrationInputs {
        mut auth,
        legacy,
        mut config,
    }) = MigrationInputs::read(&auth_path, &config_path)
    else {
        return migration;
    };

    let mut auth_changed = legacy;
    if legacy {
        migration
            .notes
            .push(format!("converted {} to profiles", auth_path.display()));
    }
    let config_url = config.as_mut().and_then(|c| c.remove("api_url"));
    if let Some(url) = config_url
        .as_ref()
        .and_then(|u| u.as_str())
        .map(normalize_api_url)
        .filter(|u| !u.is_empty())
    {
        let target = auth
            .default_profile
            .clone()
            .unwrap_or_else(|| DEFAULT_PROFILE.to_string());
        let profile = auth.profiles.entry(target.clone()).or_default();
        match profile.api_url.as_deref().map(normalize_api_url) {
            None => {
                profile.api_url = Some(url);
                auth_changed = true;
                migration.notes.push(format!(
                    "moved api_url from {} into profile {target:?}",
                    config_path.display()
                ));
            }
            Some(existing) if existing != url => migration.notes.push(format!(
                "dropped api_url {url} from {}: profile {target:?} already uses {existing}",
                config_path.display()
            )),
            Some(_) => {}
        }
        auth.ensure_default();
    }

    if auth_changed && let Err(e) = auth.save() {
        migration.notes.clear();
        migration.warnings.push(format!(
            "could not migrate {} ({e:#}); using it as-is and retrying next time",
            auth_path.display()
        ));
        return migration;
    }
    if config_url.is_some() {
        let stripped = match &config {
            Some(rest) if rest.is_empty() => remove_file_if_present(&config_path),
            Some(rest) => serde_json::to_string_pretty(rest)
                .map_err(anyhow::Error::from)
                .and_then(|mut text| {
                    text.push('\n');
                    write_private(&config_path, &text)
                }),
            None => Ok(()),
        };
        if let Err(e) = stripped {
            migration.warnings.push(format!(
                "api_url in {} is no longer used, but it couldn't be removed ({e:#}); \
                 remove it by hand",
                config_path.display()
            ));
        }
    }
    migration
}

/// A file's contents, or `None` if it doesn't exist.
fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    match fs::remove_file(&target) {
        Ok(()) => {
            if target != path {
                let _ = fs::remove_file(path);
            }
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to remove {}", target.display())),
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

/// `$DN_CONFIG_DIR/config.json`, else the platform config dir. Only read to
/// migrate its `api_url` into a profile; see [`migrate_to_profiles`]. Same
/// directory rules as [`auth_path`]:
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

/// Validate a profile name: 1–64 ASCII letters, digits, `-`, `_` or `.`, so
/// it is safe as a keyring account name and in messages.
pub fn validate_profile_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        bail!("invalid profile name {name:?}: use 1-64 letters, digits, '-', '_' or '.'");
    }
    Ok(())
}

/// The profile named for this call: `--profile`, else `DN_PROFILE`. `None`
/// means "use the default profile". Existence is not checked here, since
/// `auth login` creates the profile it names.
pub fn requested_profile(flag: Option<&str>) -> Result<Option<String>> {
    let name = flag
        .map(|f| f.trim().to_string())
        .or_else(|| non_empty_env(PROFILE_ENV));
    if let Some(name) = &name {
        validate_profile_name(name)
            .with_context(|| format!("{PROFILE_ENV} or --profile names an invalid profile"))?;
    }
    Ok(name)
}

/// The profile a command runs as, looked up in `auth`: the requested one,
/// else the default. `None` when nothing is requested and no default is set.
pub fn select_profile<'a>(
    requested: Option<&str>,
    auth: &'a AuthFile,
) -> Result<Option<(String, &'a Profile)>> {
    let Some(name) = requested.or(auth.default_profile.as_deref()) else {
        return Ok(None);
    };
    match auth.profiles.get(name) {
        Some(profile) => Ok(Some((name.to_string(), profile))),
        None if requested.is_some() => bail!(
            "no profile named {name:?}. Run `dn auth list` to see profiles, or \
             `dn auth login --profile {name}` to create it."
        ),
        None => bail!(
            "the default profile {name:?} does not exist. Run `dn auth switch <name>` \
             to pick another (see `dn auth list`)."
        ),
    }
}

/// Everything a call needs to know about its credentials, short of the secret.
pub struct Active {
    pub source: Option<KeySource>,
    pub profile_name: Option<String>,
    pub profile: Option<Profile>,
}

impl Active {
    /// Load without resolving any secret. `DEFINED_API_KEY` wins over any
    /// profile's key, and a broken auth file must not block it or mask an
    /// invalid one; the file then only supplies the profile's URL, and is
    /// skipped when it can't be read unless a profile was asked for by name.
    pub fn load(profile_flag: Option<&str>) -> Result<Self> {
        let requested = requested_profile(profile_flag)?;
        if let Some(source) = resolve_key_source(api_key_env().as_deref(), None)? {
            let auth = match AuthFile::load() {
                Ok(auth) => auth,
                Err(e) if requested.is_some() => return Err(e),
                Err(_) => AuthFile::default(),
            };
            let selected = match select_profile(requested.as_deref(), &auth) {
                Ok(selected) => selected,
                Err(e) if requested.is_some() => return Err(e),
                Err(_) => None,
            };
            let (profile_name, profile) = selected.map(|(n, p)| (n, p.clone())).unzip();
            return Ok(Self {
                source: Some(source),
                profile_name,
                profile,
            });
        }
        let auth = AuthFile::load()?;
        let Some((name, profile)) = select_profile(requested.as_deref(), &auth)? else {
            return Ok(Self {
                source: None,
                profile_name: None,
                profile: None,
            });
        };
        let source = profile_key_source(&name, profile)?;
        Ok(Self {
            source,
            profile_name: Some(name),
            profile: Some(profile.clone()),
        })
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

/// The API base: `DEFINED_API_URL` over [`stored_api_url`].
pub fn api_url(profile: Option<&Profile>) -> String {
    match non_empty_env("DEFINED_API_URL") {
        Some(url) => normalize_api_url(&url),
        None => stored_api_url(profile),
    }
}

/// The API base a profile is configured with, ignoring the environment: its
/// `api_url`, else the default. Trimmed and without a trailing slash so path
/// concatenation never yields `//v2/...`.
pub fn stored_api_url(profile: Option<&Profile>) -> String {
    let raw = profile
        .and_then(|p| p.api_url.as_deref())
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .unwrap_or(DEFAULT_API_URL);
    normalize_api_url(raw)
}

/// Require an API URL that can carry the key safely: `https://`, or
/// `http://` only to this machine (`localhost`, `127.*`, `[::1]`), which is
/// what a local mock API needs. Anything else would send the key in clear.
pub fn check_api_url(url: &str) -> Result<()> {
    let url = url.trim();
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        bail!("expected an https:// URL, got {url:?}");
    };
    // A base URL has no credentials, query or fragment. Refusing `@`
    // anywhere also stops `http://localhost:80@evil.example`, whose real
    // host is after the `@`; `\` is refused because some parsers treat it
    // as `/`.
    if let Some(bad) = rest
        .chars()
        .find(|c| c.is_whitespace() || matches!(c, '@' | '?' | '#' | '\\'))
    {
        bail!("expected a plain API base URL, but {url:?} contains {bad:?}");
    }
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((host, port)) if port.is_empty() || port.starts_with(':') => host,
            _ => bail!("malformed IPv6 host in {url:?}"),
        },
        None => authority.split(':').next().unwrap_or_default(),
    };
    if host.is_empty() {
        bail!("expected a URL with a host, got {url:?}");
    }
    if secure {
        return Ok(());
    }
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        bail!(
            "refusing to send the API key over plain http:// to {host:?}; use https://, \
             or http:// only for a local mock server (localhost, 127.0.0.1, [::1])"
        );
    }
    Ok(())
}

pub fn normalize_api_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

impl Config {
    /// Build a config from an already-resolved key.
    pub fn with_key(api_key: String, profile: Option<&Profile>) -> Self {
        Self {
            api_key,
            api_url: api_url(profile),
            profile: None,
        }
    }

    /// A reminder that this call isn't talking to the production API, naming
    /// where the URL came from; `None` for the default URL.
    pub fn non_default_url_note(&self) -> Option<String> {
        if self.api_url == DEFAULT_API_URL {
            return None;
        }
        let from = if non_empty_env("DEFINED_API_URL").is_some() {
            "DEFINED_API_URL".to_string()
        } else {
            match &self.profile {
                Some(name) => format!("profile {name:?}"),
                None => "the default profile".to_string(),
            }
        };
        Some(format!("note: using {} (from {from})", self.api_url))
    }

    /// Resolve the API key (running `op read` if the source is a reference)
    /// and the base URL for the selected profile. Only commands that talk to
    /// the API call this.
    pub fn load(profile_flag: Option<&str>) -> Result<Self> {
        let active = Active::load(profile_flag)?;
        let source = active.source.ok_or_else(|| {
            anyhow!(
                "No API key configured. Run `dn auth login` (stores the key in the OS \
                 keyring) or set {API_KEY_ENV}."
            )
        })?;
        // Refuse an unusable URL before `op read`, which may prompt to unlock.
        let url = api_url(active.profile.as_ref());
        check_api_url(&url).with_context(|| match non_empty_env("DEFINED_API_URL") {
            Some(_) => "DEFINED_API_URL is not usable".to_string(),
            None => format!(
                "the API URL of profile {:?} is not usable",
                active.profile_name.as_deref().unwrap_or(DEFAULT_PROFILE)
            ),
        })?;
        let api_key = match source {
            KeySource::Env(key) => key,
            KeySource::EnvRef(r) | KeySource::FileRef(r) => op_read(&r)?,
            KeySource::Keyring(profile) => crate::keystore::get(&profile)?,
        };
        let mut config = Self::with_key(api_key, active.profile.as_ref());
        config.profile = active.profile_name;
        Ok(config)
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
    fn auth_file_roundtrips_profiles_and_unknown_keys() {
        let text = r#"{"version":2,"default_profile":"prod","profiles":{"prod":{"key":"op://v/i/f","future":1}},"later":true}"#;
        let (auth, legacy) = AuthFile::parse(text).unwrap();
        assert!(!legacy);
        assert_eq!(auth.default_profile.as_deref(), Some("prod"));
        assert_eq!(auth.profiles["prod"].key.as_deref(), Some("op://v/i/f"));
        assert_eq!(auth.profiles["prod"].api_url, None);
        let back: serde_json::Value = serde_json::from_str(&auth.to_text().unwrap()).unwrap();
        assert_eq!(
            back,
            serde_json::from_str::<serde_json::Value>(text).unwrap()
        );
    }

    #[test]
    fn legacy_auth_file_becomes_a_default_profile() {
        let (auth, legacy) =
            AuthFile::parse(r#"{"api_key_ref":"op://v/i/f","other":"kept"}"#).unwrap();
        assert!(legacy);
        assert_eq!(
            serde_json::to_value(&auth).unwrap(),
            serde_json::json!({
                "version": 2,
                "default_profile": "default",
                "profiles": { "default": { "key": "op://v/i/f" } },
                "other": "kept",
            })
        );
    }

    #[test]
    fn legacy_auth_file_without_a_reference_has_no_profiles() {
        for text in ["{}", r#"{"api_key_ref":"  "}"#] {
            let (auth, legacy) = AuthFile::parse(text).unwrap();
            assert!(legacy, "{text}");
            assert!(auth.profiles.is_empty(), "{text}");
            assert_eq!(auth.default_profile, None, "{text}");
        }
    }

    #[test]
    fn unknown_auth_file_versions_are_errors() {
        let err = AuthFile::parse(r#"{"version":3}"#).unwrap_err().to_string();
        assert!(err.contains("unsupported auth.json version 3"), "{err}");
        assert!(AuthFile::parse(r#"{"version":"2"}"#).is_err());
        assert!(AuthFile::parse("[]").is_err());
    }

    fn two_profiles() -> AuthFile {
        let mut auth = AuthFile {
            default_profile: Some("prod".into()),
            ..AuthFile::default()
        };
        for name in ["prod", "staging"] {
            auth.profiles.insert(
                name.into(),
                Profile {
                    key: Some(format!("op://v/{name}/f")),
                    ..Profile::default()
                },
            );
        }
        auth
    }

    #[test]
    fn select_profile_prefers_the_requested_one_over_the_default() {
        let auth = two_profiles();
        let pick = |requested| select_profile(requested, &auth).unwrap().map(|(n, _)| n);
        assert_eq!(pick(None).as_deref(), Some("prod"));
        assert_eq!(pick(Some("staging")).as_deref(), Some("staging"));
        assert_eq!(select_profile(None, &AuthFile::default()).unwrap(), None);
    }

    #[test]
    fn select_profile_rejects_missing_profiles() {
        let mut auth = two_profiles();
        let err = select_profile(Some("qa"), &auth).unwrap_err().to_string();
        assert!(err.contains("no profile named \"qa\""), "{err}");
        assert!(err.contains("auth login --profile qa"), "{err}");
        auth.default_profile = Some("gone".into());
        let err = select_profile(None, &auth).unwrap_err().to_string();
        assert!(err.contains("default profile \"gone\""), "{err}");
    }

    #[test]
    fn profile_names_are_restricted() {
        for good in ["default", "staging-2", "a.b_c", &"x".repeat(64)] {
            validate_profile_name(good).unwrap();
        }
        for bad in ["", "a b", "a/b", "prod:1", "é", &"x".repeat(65)] {
            assert!(validate_profile_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn stored_api_url_prefers_the_profile_then_the_default() {
        let profile = Profile {
            api_url: Some(" https://staging.test/ ".into()),
            ..Profile::default()
        };
        let blank = Profile {
            api_url: Some("  ".into()),
            ..Profile::default()
        };
        assert_eq!(stored_api_url(Some(&profile)), "https://staging.test");
        assert_eq!(stored_api_url(Some(&blank)), DEFAULT_API_URL);
        assert_eq!(stored_api_url(None), DEFAULT_API_URL);
    }

    #[test]
    fn check_api_url_allows_plain_http_only_to_this_machine() {
        for good in [
            "https://api.defined.net",
            "https://staging.example:8443/base",
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://127.0.0.1:1",
            "http://127.1.2.3/",
            "http://[::1]:9000",
        ] {
            check_api_url(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for bad in [
            "",
            "staging.example",
            "ftp://x.test",
            "https://",
            "https:///path",
            "http://staging.example",
            "http://10.0.0.5:8080",
            "http://localhost.evil.test",
            "http://127.0.0.1.evil.test",
            "http://[::2]",
            "https://a b",
            // Userinfo: the real host is after the `@`.
            "http://localhost:80@evil.example",
            "http://localhost:@evil.example",
            "http://[::1]@evil.example",
            "http://127.0.0.1@evil.example",
            "https://user@api.defined.net",
            "https://@",
            // A base URL can't carry a query or fragment.
            "https://api.defined.net?x=1",
            "https://api.defined.net#frag",
        ] {
            assert!(check_api_url(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn ensure_default_picks_a_real_profile() {
        let mut auth = two_profiles();
        assert_eq!(auth.ensure_default(), None);
        auth.profiles.remove("prod");
        assert_eq!(auth.ensure_default().as_deref(), Some("staging"));
        auth.profiles.clear();
        assert_eq!(auth.ensure_default(), None);
        assert_eq!(auth.default_profile, None);
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
