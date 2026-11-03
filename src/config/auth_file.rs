use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use super::{
    AUTH_VERSION, KEYRING, PROFILE_NAME_CHARS, auth_path, config_dir, is_valid_profile_name,
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

/// An `auth.json` with no `version`: the single-reference layout from before
/// profiles, which this binary no longer reads. Unlike a file from a newer
/// `dn`, `auth login` may replace it: its one reference is all it held.
#[derive(Debug)]
pub struct MissingAuthVersion;

impl fmt::Display for MissingAuthVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "auth.json has no \"version\" (written by a dn from before profiles); \
             run `dn auth login` to replace it"
        )
    }
}

impl std::error::Error for MissingAuthVersion {}

/// An exclusive advisory lock on the credentials, held while a command reads,
/// changes and writes `auth.json`, so
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

impl AuthFile {
    /// Parse the profiles layout.
    ///
    /// A hand-edited default that is missing or names no profile is repaired
    /// in memory (see [`AuthFile::ensure_default`]), so callers can rely on a
    /// default whenever there are profiles.
    fn parse(text: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(text)?;
        let mut auth = match value.get("version") {
            None => return Err(MissingAuthVersion.into()),
            Some(version) if version.as_u64() == Some(AUTH_VERSION) => {
                serde_json::from_value::<AuthFile>(value)?
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
        Ok(auth)
    }

    /// Read the credentials file, treating a missing file as no profiles.
    pub fn load() -> Result<Self> {
        let path = auth_path()?;
        match read_optional(&path)? {
            Some(text) => {
                Self::parse(&text).with_context(|| format!("failed to parse {}", path.display()))
            }
            None => Ok(Self::default()),
        }
    }

    /// Like [`AuthFile::load`], but an unparsable file comes back as no
    /// profiles plus the error, for `auth login` to replace. That includes a
    /// file from before profiles. A file from a newer `dn` or one with a
    /// hand-edited bad name is still an error:
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
        let auth = AuthFile::parse(text).unwrap();
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
    fn a_file_without_a_version_is_refused() {
        for text in [
            "{}",
            r#"{"api_key_ref":"op://v/i/f","other":"kept"}"#,
            r#"{"profiles":{"work":{"key":"keyring"}},"default_profile":"work"}"#,
        ] {
            let err = AuthFile::parse(text).unwrap_err();
            assert!(
                err.downcast_ref::<MissingAuthVersion>().is_some(),
                "{text}: {err:#}"
            );
            assert!(err.to_string().contains("run `dn auth login`"), "{err}");
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

    mod props {
        use proptest::prelude::*;
        use serde_json::{Value, json};

        use super::*;

        fn profile_name() -> impl Strategy<Value = String> {
            prop_oneof![
                4 => "[a-z0-9._-]{1,12}",
                1 => Just("Work".to_string()),
                1 => Just(String::new()),
            ]
        }

        fn profile() -> impl Strategy<Value = Value> {
            (
                prop::option::of(prop::sample::select(vec![
                    "https://api.defined.net",
                    " https://x.test/ ",
                ])),
                prop::option::of(prop::sample::select(vec!["keyring", "op://v/i/f", " "])),
                prop::option::of(prop::sample::select(vec![
                    json!(1),
                    json!("kept"),
                    json!(null),
                ])),
            )
                .prop_map(|(url, key, extra)| {
                    let mut p = serde_json::Map::new();
                    if let Some(url) = url {
                        p.insert("api_url".into(), json!(url));
                    }
                    if let Some(key) = key {
                        p.insert("key".into(), json!(key));
                    }
                    if let Some(extra) = extra {
                        p.insert("future".into(), extra);
                    }
                    Value::Object(p)
                })
        }

        /// An `auth.json` as it might be found on disk: an unknown or
        /// missing version, the old layout's `api_key_ref`, bad profile
        /// names, and keys from a later `dn`.
        fn auth_text() -> impl Strategy<Value = String> {
            let version =
                prop::option::of(prop::sample::select(vec![json!(2), json!(3), json!("2")]));
            let default = prop::option::of(profile_name());
            let profiles =
                prop::option::of(prop::collection::btree_map(profile_name(), profile(), 0..4));
            let api_key_ref = prop::option::of(prop::sample::select(vec!["op://v/i/f", "  "]));
            let later = prop::option::of(prop::sample::select(vec![json!(true), json!({"x": 1})]));
            (version, default, profiles, api_key_ref, later).prop_map(
                |(version, default, profiles, api_key_ref, later)| {
                    let mut root = serde_json::Map::new();
                    if let Some(v) = version {
                        root.insert("version".into(), v);
                    }
                    if let Some(d) = default {
                        root.insert("default_profile".into(), json!(d));
                    }
                    if let Some(p) = profiles {
                        root.insert("profiles".into(), json!(p));
                    }
                    if let Some(r) = api_key_ref {
                        root.insert("api_key_ref".into(), json!(r));
                    }
                    if let Some(l) = later {
                        root.insert("later".into(), l);
                    }
                    Value::Object(root).to_string()
                },
            )
        }

        proptest! {
            /// Whatever is read, saving it and reading it back changes
            /// nothing: no key written twice and no profile lost.
            #[test]
            fn saving_what_was_read_is_a_fixpoint(text in auth_text()) {
                if let Ok(auth) = AuthFile::parse(&text) {
                    let saved = pretty_text(&auth).unwrap();
                    let again = AuthFile::parse(&saved).unwrap();
                    prop_assert_eq!(&again, &auth, "saved: {}", saved);
                    prop_assert_eq!(pretty_text(&again).unwrap(), saved);
                }
            }

            /// A file that reads has a default whenever it has profiles, and
            /// the default names one of them.
            #[test]
            fn a_read_file_has_a_real_default(text in auth_text()) {
                if let Ok(auth) = AuthFile::parse(&text) {
                    match &auth.default_profile {
                        Some(name) => prop_assert!(auth.profiles.contains_key(name)),
                        None => prop_assert!(auth.profiles.is_empty()),
                    }
                }
            }

            /// Only the current version reads; a file without one is the
            /// pre-profiles layout, which `auth login` may replace.
            #[test]
            fn only_version_2_reads(text in auth_text()) {
                let version = serde_json::from_str::<Value>(&text).unwrap()["version"].clone();
                match AuthFile::parse(&text) {
                    Ok(_) => prop_assert_eq!(version, json!(2)),
                    Err(e) if version.is_null() => {
                        prop_assert!(e.downcast_ref::<MissingAuthVersion>().is_some(), "{:#}", e)
                    }
                    Err(_) => {}
                }
            }
        }
    }
}
