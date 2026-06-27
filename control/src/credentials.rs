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

/// An AWS temporary-credential *bundle*. Unlike a token-shaped credential (one [`Secret`]),
/// AWS SigV4 with temporary creds is a triple: the `access_key_id` (non-secret, but it rides
/// out on the wire with the signature), the `secret_access_key` (the signing secret), and an
/// optional `session_token` (sent in `X-Amz-Security-Token`, part of the signed header set).
/// `expires_at_ms` (epoch ms) drives rotation when the bundle is minted (assume-role); a
/// static IAM-user key pair has no session token and no expiry. The secrets carry the same
/// redacted [`Debug`] guarantee as [`Secret`] (hand-written below) so a bundle can never leak
/// into a log line.
#[derive(Clone)]
pub struct AwsCredential {
    pub access_key_id: String,
    pub secret_access_key: Secret,
    pub session_token: Option<Secret>,
    pub expires_at_ms: Option<u64>,
}

impl std::fmt::Debug for AwsCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredential")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &self.secret_access_key)
            .field("session_token", &self.session_token)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// What a single credential id resolves to: a token-shaped [`Secret`] **or** an
/// [`AwsCredential`] bundle — never both. A sum type so an id is unambiguously one kind: a
/// `resolve` (token) and a `resolve_aws` (bundle) read the same map and each return `Some`
/// only for the matching variant (fail closed otherwise).
#[derive(Clone, Debug)]
pub enum CredentialMaterial {
    /// A token-shaped secret (bearer/header/basic injection, or an IAM-user key as a plain
    /// string elsewhere). Resolved by [`CredentialStore::resolve`].
    Token(Secret),
    /// An AWS temporary-credential bundle. Resolved by [`CredentialStore::resolve_aws`].
    Aws(AwsCredential),
}

/// Resolves credential ids to secrets. A trait so the in-memory store here can later be
/// swapped for a GitHub App token minter, a KMS-backed vault, etc., with no change to
/// the data plane.
pub trait CredentialStore: Send + Sync {
    /// The real token-shaped secret for `id`, or `None` if no such credential is configured
    /// **or** the id holds an AWS bundle (an AWS bundle is not a token — fail closed; callers
    /// that want the bundle use [`Self::resolve_aws`]).
    fn resolve(&self, id: &str) -> Option<Secret>;

    /// The AWS credential bundle for `id`, or `None` if no such credential is configured
    /// **or** the id holds a token-shaped secret. Default: `None` (a store that knows only
    /// token-shaped secrets has no AWS bundles).
    fn resolve_aws(&self, id: &str) -> Option<AwsCredential> {
        let _ = id;
        None
    }

    /// Store (or replace) a secret at runtime under `id` — used when a service is
    /// registered live via the admin API with its credential supplied inline. Returns
    /// whether this store supports runtime insertion; a minting/static store may not.
    /// Default: unsupported (the operator must provision the secret out of band).
    fn insert_runtime(&self, id: String, secret: Secret) -> bool {
        let _ = (id, secret);
        false
    }

    /// Store (or replace) an AWS credential bundle at runtime under `id` — used when an
    /// `aws-static` credential is registered live via the admin API. Returns whether this
    /// store supports runtime AWS insertion. Default: unsupported.
    fn insert_aws_runtime(&self, id: String, cred: AwsCredential) -> bool {
        let _ = (id, cred);
        false
    }

    /// Register an AWS-bundle *minting provider* (assume-role / instance) at runtime under
    /// `id`. Returns whether this store supports AWS providers — only a minting store
    /// (`CachingCredentials`) does; a static [`InMemoryCredentials`] does not (the admin API
    /// then rejects the source with a 409, fail closed). Default: unsupported.
    ///
    /// The provider is boxed as `Box<dyn Any>` to keep the `Send + Sync` provider type out of
    /// the credentials module (it lives in `providers`); the implementor downcasts it. A store
    /// that can't downcast it returns `false`.
    fn register_aws_provider(
        &self,
        id: String,
        provider: Box<dyn std::any::Any + Send + Sync>,
    ) -> bool {
        let _ = (id, provider);
        false
    }

    /// The set of credential **ids** this store knows about — never the secrets. Surfaced
    /// by `GET /admin/credentials` for operator discovery. Default: none (a store that
    /// can't enumerate its keys reports an empty set rather than leaking shape).
    fn ids(&self) -> Vec<String> {
        Vec::new()
    }
}

/// A static, in-memory credential store seeded at startup. Adequate for v1, where the
/// real upstream credential (e.g. a GitHub App installation token) is provisioned out
/// of band and handed to hackamore. An id maps to a [`CredentialMaterial`] — a token or an
/// AWS bundle, never both.
#[derive(Default)]
pub struct InMemoryCredentials {
    material: RwLock<HashMap<String, CredentialMaterial>>,
}

impl InMemoryCredentials {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace the token-shaped secret for a logical credential id.
    pub fn insert(&self, id: impl Into<String>, secret: Secret) {
        self.material
            .write()
            .insert(id.into(), CredentialMaterial::Token(secret));
    }

    /// Register or replace the AWS credential bundle for a logical credential id.
    pub fn insert_aws(&self, id: impl Into<String>, cred: AwsCredential) {
        self.material
            .write()
            .insert(id.into(), CredentialMaterial::Aws(cred));
    }
}

impl CredentialStore for InMemoryCredentials {
    fn resolve(&self, id: &str) -> Option<Secret> {
        match self.material.read().get(id) {
            Some(CredentialMaterial::Token(s)) => Some(s.clone()),
            // An AWS bundle is not a token — fail closed for `resolve`.
            Some(CredentialMaterial::Aws(_)) | None => None,
        }
    }

    fn resolve_aws(&self, id: &str) -> Option<AwsCredential> {
        match self.material.read().get(id) {
            Some(CredentialMaterial::Aws(a)) => Some(a.clone()),
            Some(CredentialMaterial::Token(_)) | None => None,
        }
    }

    fn insert_runtime(&self, id: String, secret: Secret) -> bool {
        self.material
            .write()
            .insert(id, CredentialMaterial::Token(secret));
        true
    }

    fn insert_aws_runtime(&self, id: String, cred: AwsCredential) -> bool {
        self.material
            .write()
            .insert(id, CredentialMaterial::Aws(cred));
        true
    }

    fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.material.read().keys().cloned().collect();
        ids.sort();
        ids
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

    #[test]
    fn ids_lists_known_credentials_sorted_never_secrets() {
        let store = InMemoryCredentials::new();
        store.insert("zeta", Secret::new("s1"));
        store.insert("alpha", Secret::new("s2"));
        let ids = CredentialStore::ids(&store);
        assert_eq!(ids, vec!["alpha".to_string(), "zeta".to_string()]);
        // The listing is ids only — no secret value leaks into it.
        assert!(!ids.iter().any(|id| id == "s1" || id == "s2"));
    }

    #[test]
    fn aws_credential_debug_redacts_secrets() {
        let cred = AwsCredential {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: Secret::new("super-secret-key"),
            session_token: Some(Secret::new("super-session-token")),
            expires_at_ms: Some(1_700_000_000_000),
        };
        let shown = format!("{cred:?}");
        // The non-secret access key id is visible; both secrets are redacted.
        assert!(shown.contains("AKIDEXAMPLE"));
        assert!(!shown.contains("super-secret-key"));
        assert!(!shown.contains("super-session-token"));
        assert!(shown.contains("Secret(***)"));
        // The secrets are still reachable via the explicit boundary.
        assert_eq!(cred.secret_access_key.expose(), "super-secret-key");
    }

    #[test]
    fn token_and_aws_resolve_only_their_own_kind() {
        let store = InMemoryCredentials::new();
        store.insert("tok", Secret::new("a-token"));
        store.insert_aws(
            "aws",
            AwsCredential {
                access_key_id: "AKID".into(),
                secret_access_key: Secret::new("sak"),
                session_token: Some(Secret::new("sess")),
                expires_at_ms: None,
            },
        );

        // A token resolves only via `resolve`; an AWS bundle only via `resolve_aws`.
        assert_eq!(store.resolve("tok").unwrap().expose(), "a-token");
        assert!(store.resolve_aws("tok").is_none());

        let bundle = store.resolve_aws("aws").unwrap();
        assert_eq!(bundle.access_key_id, "AKID");
        assert_eq!(bundle.secret_access_key.expose(), "sak");
        assert_eq!(bundle.session_token.unwrap().expose(), "sess");
        // The AWS bundle is not a token — `resolve` fails closed for it.
        assert!(store.resolve("aws").is_none());

        // ids unions both kinds.
        let mut ids = CredentialStore::ids(&store);
        ids.sort();
        assert_eq!(ids, vec!["aws".to_string(), "tok".to_string()]);
    }

    #[test]
    fn insert_aws_runtime_stores_a_bundle() {
        let store = InMemoryCredentials::new();
        let ok = store.insert_aws_runtime(
            "aws".to_string(),
            AwsCredential {
                access_key_id: "AKID".into(),
                secret_access_key: Secret::new("sak"),
                session_token: None,
                expires_at_ms: None,
            },
        );
        assert!(ok);
        assert_eq!(store.resolve_aws("aws").unwrap().access_key_id, "AKID");
        // Replacing the same id with a token flips its kind (illegal-to-be-both holds).
        assert!(store.insert_runtime("aws".to_string(), Secret::new("now-a-token")));
        assert!(store.resolve_aws("aws").is_none());
        assert_eq!(store.resolve("aws").unwrap().expose(), "now-a-token");
    }
}
