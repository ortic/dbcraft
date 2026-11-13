//! Connection passwords, SSH passwords and AI API keys in the OS keychain
//! (never in config files).

use tracing::warn;

/// A keychain service, with the ones it was called before the renames to
/// Pythia and to DbCraft: a secret found only there moves over when it is
/// first read.
struct Service {
    name: &'static str,
    legacy: &'static [&'static str],
}

/// Connection passwords, by connection.
const SERVICE: Service = Service {
    name: "dbcraft",
    legacy: &["pythia", "orui"],
};
/// API keys of AI backends, by backend id.
const AI_SERVICE: Service = Service {
    name: "dbcraft-ai",
    legacy: &["pythia-ai"],
};
/// SSH passwords and key passphrases, by connection.
const SSH_SERVICE: Service = Service {
    name: "dbcraft-ssh",
    legacy: &["pythia-ssh"],
};

fn entry(service: &str, account: &str) -> Option<keyring::Entry> {
    keyring::Entry::new(service, account)
        .inspect_err(|e| warn!("keychain unavailable: {e}"))
        .ok()
}

fn load_from(service: &Service, account: &str) -> Option<String> {
    if let Ok(secret) = entry(service.name, account)?.get_password() {
        return Some(secret);
    }
    service.legacy.iter().find_map(|name| {
        let legacy = entry(name, account)?;
        let secret = legacy.get_password().ok()?;
        if entry(service.name, account)?.set_password(&secret).is_ok() {
            let _ = legacy.delete_credential();
        }
        Some(secret)
    })
}

/// Forgets the secret under the service's names of now and before, so that
/// an old one doesn't come back on the next read.
fn forget_from(service: &Service, account: &str) {
    for name in std::iter::once(service.name).chain(service.legacy.iter().copied()) {
        if let Some(entry) = entry(name, account) {
            let _ = entry.delete_credential();
        }
    }
}

pub fn load(connection: &str) -> Option<String> {
    load_from(&SERVICE, connection)
}

/// Stores the password; the error says why the keychain doesn't keep it.
/// That was only logged, and the next connect had no password (#214).
pub fn store(connection: &str, password: &str) -> Result<(), String> {
    keyring::Entry::new(SERVICE.name, connection)
        .and_then(|entry| entry.set_password(password))
        .map_err(why)
}

pub fn forget(connection: &str) {
    forget_from(&SERVICE, connection);
}

pub fn load_ssh(connection: &str) -> Option<String> {
    load_from(&SSH_SERVICE, connection)
}

/// Stores the SSH password, or forgets it when it is empty.
pub fn store_ssh(connection: &str, password: &str) -> Result<(), String> {
    if password.is_empty() {
        forget_ssh(connection);
        return Ok(());
    }
    keyring::Entry::new(SSH_SERVICE.name, connection)
        .and_then(|entry| entry.set_password(password))
        .map_err(why)
}

/// Why passwords can't be saved, if there is no keychain (no Secret
/// Service on Linux, for one).
pub fn unavailable() -> Option<String> {
    keyring::Entry::store_status()
        .as_ref()
        .err()
        .map(|e| format!("there's no keychain ({e})"))
}

/// Why the keychain didn't take a password.
fn why(e: keyring::Error) -> String {
    match (&e, unavailable()) {
        (keyring::Error::NoDefaultStore, Some(none)) => none,
        _ => format!("the keychain refused it ({e})"),
    }
}

pub fn forget_ssh(connection: &str) {
    forget_from(&SSH_SERVICE, connection);
}

pub fn load_api_key(backend: &str) -> Option<String> {
    load_from(&AI_SERVICE, backend)
}

pub fn store_api_key(backend: &str, key: &str) -> Result<(), String> {
    keyring::Entry::new(AI_SERVICE.name, backend)
        .and_then(|entry| entry.set_password(key))
        .map_err(|e| format!("Could not store the key in the keychain: {e}"))
}

pub fn forget_api_key(backend: &str) {
    forget_from(&AI_SERVICE, backend);
}

#[cfg(test)]
mod tests {
    /// A password the keychain doesn't take says why (#214).
    #[test]
    fn refused_passwords_say_why() {
        let e = keyring::Error::NoStorageAccess("the keychain is locked".into());
        assert_eq!(
            super::why(e),
            "the keychain refused it (Couldn't access platform storage: the keychain is locked)"
        );
        // Without a keychain, the reason it couldn't be opened.
        let none = super::why(keyring::Error::NoDefaultStore);
        match super::unavailable() {
            Some(reason) => assert_eq!(none, reason),
            None => assert!(none.starts_with("the keychain refused it"), "{none}"),
        }
    }
}
