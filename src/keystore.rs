//! API keys kept in the OS credential store: macOS Keychain, Windows
//! Credential Manager, or the Secret Service (GNOME Keyring, KWallet) on
//! Linux. One entry per login, under [`SERVICE`] with an account from
//! [`new_account`], which the profile records in `auth.json`.
//!
//! Debug builds (and so the test suite) can point this at a JSON file with
//! `DN_TEST_KEYRING=<path>`, or make it unavailable with
//! `DN_TEST_KEYRING=unavailable`. Release builds never read that variable,
//! so a shipped `dn` can't be steered into storing keys in a plain file.

use anyhow::{Result, anyhow};

/// The keyring service name, reverse-DNS of the repo so it can't collide
/// with another app's entries.
pub const SERVICE: &str = "io.github.jasikpark.dn";

/// A keyring account no entry uses yet, for a login to `profile`:
/// `<profile>/<16 hex digits>`. The digits keep two config directories, and
/// two logins to one profile, from sharing an entry. `/` can't appear in a
/// profile name, so the account never equals one of the bare profile names
/// that entries were once stored under.
pub fn new_account(profile: &str) -> String {
    use std::hash::{BuildHasher, Hasher};

    // `RandomState` is keyed from the OS's random source.
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    format!("{profile}/{:016x}", hasher.finish())
}

/// The key stored under `account`. `profile` is the profile that points at
/// it, which is what errors name.
pub fn get(account: &str, profile: &str) -> Result<String> {
    #[cfg(debug_assertions)]
    if let Some(store) = test_store::from_env() {
        return store.get(account, profile);
    }
    entry(account, profile)?
        .get_password()
        .map_err(|e| describe(e, profile))
}

/// Store `key` under `account`, replacing any existing one.
pub fn set(account: &str, profile: &str, key: &str) -> Result<()> {
    #[cfg(debug_assertions)]
    if let Some(store) = test_store::from_env() {
        return store.set(account, key);
    }
    entry(account, profile)?
        .set_password(key)
        .map_err(|e| describe(e, profile))
}

/// Remove the key stored under `account`. `false` when there was none.
pub fn delete(account: &str, profile: &str) -> Result<bool> {
    #[cfg(debug_assertions)]
    if let Some(store) = test_store::from_env() {
        return store.delete(account);
    }
    match entry(account, profile)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(describe(e, profile)),
    }
}

/// Fail when no OS keyring could start, so `dn auth login` can say so before
/// asking for a key. An `Ok` doesn't promise a write will succeed: the
/// keyring can still be locked or refuse access.
pub fn ensure_available() -> Result<()> {
    #[cfg(debug_assertions)]
    if let Some(store) = test_store::from_env() {
        return store.path().map(|_| ());
    }
    match keyring::Entry::store_status() {
        Ok(()) => Ok(()),
        Err(cause) => Err(anyhow!("{UNAVAILABLE_HINT} ({cause})")),
    }
}

fn entry(account: &str, profile: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, account).map_err(|e| describe(e, profile))
}

const UNAVAILABLE_HINT: &str = "no OS keyring is available (on Linux this needs a \
    Secret Service such as GNOME Keyring or KWallet, with a D-Bus session). Store a \
    1Password reference instead with `dn auth login --ref op://…`, or set DEFINED_API_KEY";

fn no_entry(profile: &str) -> anyhow::Error {
    anyhow!(
        "profile {profile:?} has no key in the OS keyring; run \
         `dn auth login --profile {profile}` to store one"
    )
}

/// Turn a keyring error into a message that says what to do about it.
fn describe(err: keyring::Error, profile: &str) -> anyhow::Error {
    match err {
        keyring::Error::NoEntry => no_entry(profile),
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
        keyring::Error::BadEncoding(_) => anyhow!(
            "the OS keyring entry for profile {profile:?} is not text; run \
             `dn auth login --profile {profile}` to replace it"
        ),
        keyring::Error::Ambiguous(_) => anyhow!(
            "the OS keyring has more than one entry for profile {profile:?} under service \
             {SERVICE}; remove the extras in your keyring manager"
        ),
        other => anyhow!("OS keyring error: {other}"),
    }
}

#[cfg(debug_assertions)]
mod test_store {
    //! A stand-in keyring for tests: a JSON object of account → key.

    use std::fs;
    use std::io::ErrorKind;
    use std::path::PathBuf;

    use anyhow::{Context, Result, bail};
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
        pub fn path(&self) -> Result<&PathBuf> {
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

        /// Write the whole file by rename, so a concurrent reader sees the
        /// old entries or the new ones, never a half-written file.
        fn save(&self, entries: &Map<String, Value>) -> Result<()> {
            let path = self.path()?;
            let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
            fs::write(&tmp, serde_json::to_string_pretty(entries)?)?;
            fs::rename(&tmp, path)?;
            Ok(())
        }

        /// Read, change and save the entries under an exclusive lock on a
        /// sibling `.lock` file. A real keyring updates one entry at a time,
        /// so parallel `dn` calls never lose each other's entries; this
        /// stand-in rewrites the whole file and needs the lock to match.
        fn update<T>(&self, change: impl FnOnce(&mut Map<String, Value>) -> T) -> Result<T> {
            let lock = fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(self.path()?.with_extension("lock"))?;
            lock.lock()?;
            let mut entries = self.load()?;
            let result = change(&mut entries);
            self.save(&entries)?;
            Ok(result)
        }

        pub fn get(&self, account: &str, profile: &str) -> Result<String> {
            self.load()?
                .get(account)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| super::no_entry(profile))
        }

        pub fn set(&self, account: &str, key: &str) -> Result<()> {
            self.update(|entries| {
                entries.insert(account.to_string(), Value::String(key.to_string()));
            })
        }

        pub fn delete(&self, account: &str) -> Result<bool> {
            self.update(|entries| entries.remove(account).is_some())
        }
    }
}
