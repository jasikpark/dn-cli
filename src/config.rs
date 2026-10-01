mod auth_file;
mod key_source;

pub use auth_file::{
    AuthFile, AuthLock, InvalidStoredProfileName, Migration, Profile, migrate_to_profiles,
};
use key_source::keyring_key;
pub use key_source::{
    KeySource, normalize_op_ref, op_read, profile_key_source, resolve_key_source, validate_op_ref,
};

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};

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

/// Validate a profile name: 1–64 lowercase ASCII letters, digits, `-`, `_`
/// or `.`, so it is safe as a keyring account name and in messages. Lowercase
/// because Windows Credential Manager can't tell entries apart by case.
pub fn validate_profile_name(name: &str) -> Result<()> {
    if !is_valid_profile_name(name) {
        bail!("invalid profile name {name:?}: use 1-64 {PROFILE_NAME_CHARS}");
    }
    Ok(())
}

const PROFILE_NAME_CHARS: &str = "lowercase letters, digits, '-', '_' or '.'";

fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
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
            // A readable file with a bad name still knows the default
            // profile's URL; skipping it would send the key to the default API.
            let auth = match AuthFile::load() {
                Ok(auth) => auth,
                Err(e)
                    if requested.is_some()
                        || e.downcast_ref::<InvalidStoredProfileName>().is_some() =>
                {
                    return Err(e);
                }
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
            KeySource::Keyring(profile) => keyring_key(&profile)?,
        };
        let mut config = Self::with_key(api_key, active.profile.as_ref());
        config.profile = active.profile_name;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for bad in ["", "a b", "a/b", "prod:1", "é", "Work", &"x".repeat(65)] {
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
    fn api_url_is_trimmed_and_unslashed() {
        assert_eq!(
            normalize_api_url(" https://api.defined.net/ "),
            "https://api.defined.net"
        );
        assert_eq!(normalize_api_url("https://x.test//"), "https://x.test");
        assert_eq!(normalize_api_url(DEFAULT_API_URL), DEFAULT_API_URL);
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
}
