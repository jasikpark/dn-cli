use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use super::{
    AUTH_VERSION, DEFAULT_PROFILE, KEYRING, PROFILE_NAME_CHARS, auth_path, config_dir, config_path,
    is_valid_profile_name, normalize_api_url,
};

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

/// An `auth.json` naming a profile [`validate_profile_name`](super::validate_profile_name) rejects, which
/// can only come from editing the file by hand.
#[derive(Debug)]
pub struct InvalidStoredProfileName(String);

impl fmt::Display for InvalidStoredProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid profile name {:?}: rename it in auth.json to 1-64 {PROFILE_NAME_CHARS}",
            self.0
        )
    }
}

impl std::error::Error for InvalidStoredProfileName {}

/// An exclusive advisory lock on the credentials, held while a command reads,
/// changes and writes `auth.json` (and, when migrating, `config.json`), so
/// concurrent `dn` processes can't lose each other's changes. It lives in a
/// separate `auth.json.lock` because `auth.json` itself is replaced by rename.
/// Released on drop.
pub struct AuthLock(#[allow(dead_code)] fs::File);

impl AuthLock {
    pub fn acquire() -> Result<Self> {
        let path = config_dir()?.join("auth.json.lock");
        create_parent(&path)?;
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
        // Every name becomes a keyring account name, so one the CLI would
        // refuse (`Work` beside `work` would share a Windows Credential
        // Manager entry) is refused here too.
        let names = auth.profiles.keys().chain(&auth.default_profile);
        if let Some(bad) = names.into_iter().find(|n| !is_valid_profile_name(n)) {
            return Err(InvalidStoredProfileName(bad.clone()).into());
        }
        auth.ensure_default();
        Ok((auth, legacy))
    }

    /// Read the credentials file, treating a missing file as no profiles. An
    /// old-layout file is converted in memory; see [`migrate_to_profiles`].
    pub fn load() -> Result<Self> {
        let path = auth_path()?;
        match read_optional(&path)? {
            Some(text) => Self::parse(&text)
                .map(|(auth, _)| auth)
                .with_context(|| format!("failed to parse {}", path.display())),
            None => Ok(Self::default()),
        }
    }

    /// Like [`AuthFile::load`], but an unparsable file comes back as no
    /// profiles plus the error, for `auth login` to replace. A file from a
    /// newer `dn`, or one with a hand-edited bad name, is still an error:
    /// replacing it would lose its profiles and orphan their keyring entries.
    pub fn load_or_reset() -> Result<(Self, Option<anyhow::Error>)> {
        match Self::load() {
            Ok(cfg) => Ok((cfg, None)),
            Err(e)
                if e.downcast_ref::<UnsupportedAuthVersion>().is_some()
                    || e.downcast_ref::<InvalidStoredProfileName>().is_some() =>
            {
                Err(e)
            }
            Err(e) => Ok((Self::default(), Some(e))),
        }
    }

    pub fn save(&self) -> Result<PathBuf> {
        let path = auth_path()?;
        create_parent(&path)?;
        write_private(&path, &pretty_text(self)?)?;
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
            Some(rest) if rest.is_empty() => remove_file_if_present(&config_path).map(drop),
            Some(rest) => pretty_text(rest).and_then(|text| write_private(&config_path, &text)),
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

fn create_parent(path: &Path) -> Result<()> {
    let Some(dir) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))
}

/// Pretty JSON with a trailing newline, as the config files are written.
fn pretty_text(value: &impl Serialize) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)? + "\n")
}

/// A file's contents, or `None` if it doesn't exist.
fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

/// Delete a file (through a symlink, then the link itself). `false` when
/// there was nothing to delete.
pub fn remove_file_if_present(path: &Path) -> Result<bool> {
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    match fs::remove_file(&target) {
        Ok(()) => {
            if target != path {
                let _ = fs::remove_file(path);
            }
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_file_roundtrips_profiles_and_unknown_keys() {
        let text = r#"{"version":2,"default_profile":"prod","profiles":{"prod":{"key":"op://v/i/f","future":1}},"later":true}"#;
        let (auth, legacy) = AuthFile::parse(text).unwrap();
        assert!(!legacy);
        assert_eq!(auth.default_profile.as_deref(), Some("prod"));
        assert_eq!(auth.profiles["prod"].key.as_deref(), Some("op://v/i/f"));
        assert_eq!(auth.profiles["prod"].api_url, None);
        let back: serde_json::Value = serde_json::from_str(&pretty_text(&auth).unwrap()).unwrap();
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
}
