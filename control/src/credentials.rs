//! The credential vault: resolves a logical credential id (named by the policy engine
//! via a `CredentialRef`) into a real upstream secret. Secrets live only here and in
//! the data plane's outbound request; the agent never sees them.

use parking_lot::RwLock;
use std::collections::HashMap;

/// A resolved credential value. A semantic type, deliberately not a `String`: its
/// `Debug` is redacted so a secret can never leak into a log line, and the inner value
/// is reachable only through the explicit [`Secret::expose`] call.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Reveal the raw secret. Call sites are the audited boundary where a secret enters
    /// an outbound request; keep them few and obvious.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Resolves credential ids to secrets. A trait so the in-memory store here can later be
/// swapped for a GitHub App token minter, a KMS-backed vault, etc., with no change to
/// the data plane.
pub trait CredentialStore: Send + Sync {
    /// The real secret for `id`, or `None` if no such credential is configured.
    fn resolve(&self, id: &str) -> Option<Secret>;
}

/// A static, in-memory credential store seeded at startup. Adequate for v1, where the
/// real upstream credential (e.g. a GitHub App installation token) is provisioned out
/// of band and handed to halter.
#[derive(Default)]
pub struct InMemoryCredentials {
    secrets: RwLock<HashMap<String, Secret>>,
}

impl InMemoryCredentials {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace the secret for a logical credential id.
    pub fn insert(&self, id: impl Into<String>, secret: Secret) {
        self.secrets.write().insert(id.into(), secret);
    }
}

impl CredentialStore for InMemoryCredentials {
    fn resolve(&self, id: &str) -> Option<Secret> {
        self.secrets.read().get(id).cloned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("ghp_supersecret");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(s.expose(), "ghp_supersecret");
    }

    #[test]
    fn store_resolves_known_and_misses_unknown() {
        let store = InMemoryCredentials::new();
        store.insert("github-app", Secret::new("token-123"));
        assert_eq!(store.resolve("github-app").unwrap().expose(), "token-123");
        assert!(store.resolve("nope").is_none());
    }
}
