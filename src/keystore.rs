//! API keys kept in the OS credential store: macOS Keychain, Windows
//! Credential Manager, or the Secret Service (GNOME Keyring, KWallet) on
//! Linux. One entry per profile, under [`SERVICE`] with the profile name as
//! the account.
//!
//! Debug builds (and so the test suite) can point this at a JSON file with
//! `DN_TEST_KEYRING=<path>`, or make it unavailable with
//! `DN_TEST_KEYRING=unavailable`. Release builds never read that variable,
//! so a shipped `dn` can't be steered into storing keys in a plain file.

use anyhow::{Result, anyhow};

/// The keyring service name, reverse-DNS of the repo so it can't collide
/// with another app's entries.
pub const SERVICE: &str = "io.github.jasikpark.dn";

/// The key stored for `profile`.
pub fn get(profile: &str) -> Result<String> {
    #[cfg(debug_assertions)]
    if let Some(store) = test_store::from_env() {
        return store.get(profile);
    }
    let entry = entry(profile)?;
    entry.get_password().map_err(|e| describe(e, profile))
}

/// Store `key` for `profile`, replacing any existing one.
pub fn set(profile: &str, key: &str) -> Result<()> {
    #[cfg(debug_assertions)]
    if let Some(store) = test_store::from_env() {
        return store.set(profile, key);
    }
    let entry = entry(profile)?;
    entry.set_password(key).map_err(|e| describe(e, profile))
}

/// Remove the key stored for `profile`. `false` when there was none.
pub fn delete(profile: &str) -> Result<bool> {
    #[cfg(debug_assertions)]
    if let Some(store) = test_store::from_env() {
        return store.delete(profile);
    }
    let entry = entry(profile)?;
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(describe(e, profile)),
    }
}

fn entry(profile: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, profile).map_err(|e| describe(e, profile))
}

const UNAVAILABLE_HINT: &str = "no OS keyring is available (on Linux this needs a \
    Secret Service such as GNOME Keyring or KWallet, with a D-Bus session). Store a \
    1Password reference instead with `dn auth login --ref op://…`, or set DEFINED_API_KEY";

/// Turn a keyring error into a message that says what to do about it.
fn describe(err: keyring::Error, profile: &str) -> anyhow::Error {
    match err {
        keyring::Error::NoEntry => anyhow!(
            "profile {profile:?} has no key in the OS keyring; run \
             `dn auth login --profile {profile}` to store one"
        ),
        keyring::Error::NoDefaultStore => match keyring::Entry::store_status() {
            // The reason the store couldn't start (no D-Bus session, no
            // Secret Service on it) is only kept here.
            Err(cause) if !matches!(cause, keyring::Error::NoDefaultStore) => {
                anyhow!("{UNAVAILABLE_HINT} ({cause})")
            }
            _ => anyhow!("{UNAVAILABLE_HINT}"),
        },
        keyring::Error::NoStorageAccess(e) => {
            anyhow!("the OS keyring refused access (is it locked?): {e}")
        }
        other => anyhow!("OS keyring error: {other}"),
    }
}

#[cfg(debug_assertions)]
mod test_store {
    //! A stand-in keyring for tests: a JSON object of profile → key.

    use std::fs;
    use std::io::ErrorKind;
    use std::path::PathBuf;

    use anyhow::{Context, Result, anyhow, bail};
    use serde_json::{Map, Value};

    pub enum TestStore {
        File(PathBuf),
        Unavailable,
    }

    pub fn from_env() -> Option<TestStore> {
        let value = std::env::var("DN_TEST_KEYRING").ok()?;
        Some(if value == "unavailable" {
            TestStore::Unavailable
        } else {
            TestStore::File(PathBuf::from(value))
        })
    }

    impl TestStore {
        fn path(&self) -> Result<&PathBuf> {
            match self {
                TestStore::File(path) => Ok(path),
                TestStore::Unavailable => bail!("{}", super::UNAVAILABLE_HINT),
            }
        }

        fn load(&self) -> Result<Map<String, Value>> {
            let path = self.path()?;
            match fs::read_to_string(path) {
                Ok(text) => serde_json::from_str(&text).context("bad test keyring file"),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(Map::new()),
                Err(e) => Err(e.into()),
            }
        }

        fn save(&self, entries: &Map<String, Value>) -> Result<()> {
            fs::write(self.path()?, serde_json::to_string_pretty(entries)?)?;
            Ok(())
        }

        pub fn get(&self, profile: &str) -> Result<String> {
            self.load()?
                .get(profile)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| {
                    anyhow!(
                        "profile {profile:?} has no key in the OS keyring; run \
                         `dn auth login --profile {profile}` to store one"
                    )
                })
        }

        pub fn set(&self, profile: &str, key: &str) -> Result<()> {
            let mut entries = self.load()?;
            entries.insert(profile.to_string(), Value::String(key.to_string()));
            self.save(&entries)
        }

        pub fn delete(&self, profile: &str) -> Result<bool> {
            let mut entries = self.load()?;
            let removed = entries.remove(profile).is_some();
            self.save(&entries)?;
            Ok(removed)
        }
    }
}
