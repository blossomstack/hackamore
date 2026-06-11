//! Short-lived launch tokens. The orchestrator mints a token bound to a submitted
//! [`Policy`] with a TTL; the consumer presents it to the proxy, which resolves it back
//! to that policy. The token is an opaque capability honored only by halter — it is
//! useless against the real upstream — and is revocable at any time. There is no agent
//! identity: the token *is* the policy binding.
//!
//! Time is passed in explicitly (`now_ms`) so minting, expiry, and resolution are all
//! deterministically testable; the binary supplies the wall clock via [`crate::now_ms`].

use models::control::MintResponse;
use models::policy::Policy;
use parking_lot::RwLock;
use std::collections::HashMap;
use uuid::Uuid;

struct Entry {
    policy: Policy,
    expires_at_ms: u64,
    /// For a SigV4 dummy credential, the dummy secret access key (used to verify the
    /// consumer's inbound signature). `None` for a bearer token.
    secret: Option<String>,
}

/// A minted dummy AWS SigV4 credential, bound to a policy. The consumer's tooling signs
/// with it; halter verifies that signature (with [`Tokens::resolve_sigv4`]) and re-signs
/// the outbound request with the real account credential. Useless against real AWS.
pub struct SigV4Mint {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub expires_at_ms: u64,
}

/// The in-memory token table. Keys are either an opaque bearer token or a dummy AWS access
/// key id; both map to `(policy, expiry, optional secret)`.
#[derive(Default)]
pub struct Tokens {
    entries: RwLock<HashMap<String, Entry>>,
}

impl Tokens {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh token bound to `policy`, valid for `ttl_seconds` from `now_ms`.
    pub fn mint(&self, policy: Policy, ttl_seconds: u64, now_ms: u64) -> MintResponse {
        // Two v4 UUIDs concatenated: ~244 bits of entropy, unguessable.
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let expires_at_ms = now_ms.saturating_add(ttl_seconds.saturating_mul(1000));
        self.entries.write().insert(
            token.clone(),
            Entry {
                policy,
                expires_at_ms,
                secret: None,
            },
        );
        MintResponse {
            token,
            expires_at_ms,
        }
    }

    /// Mint a dummy AWS SigV4 credential bound to `policy`. The access key id is the
    /// lookup key; the secret is stored to verify inbound signatures.
    pub fn mint_sigv4(&self, policy: Policy, ttl_seconds: u64, now_ms: u64) -> SigV4Mint {
        let access_key_id = format!("AKIAHALTER{}", &Uuid::new_v4().simple().to_string()[..10])
            .to_ascii_uppercase();
        let secret_access_key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let expires_at_ms = now_ms.saturating_add(ttl_seconds.saturating_mul(1000));
        self.entries.write().insert(
            access_key_id.clone(),
            Entry {
                policy,
                expires_at_ms,
                secret: Some(secret_access_key.clone()),
            },
        );
        SigV4Mint {
            access_key_id,
            secret_access_key,
            expires_at_ms,
        }
    }

    /// Resolve a dummy AWS access key id to its bound policy and dummy secret, or `None`
    /// if unknown, expired, or not a SigV4 credential.
    pub fn resolve_sigv4(&self, access_key_id: &str, now_ms: u64) -> Option<(Policy, String)> {
        let entries = self.entries.read();
        let entry = entries.get(access_key_id)?;
        if entry.expires_at_ms <= now_ms {
            return None;
        }
        let secret = entry.secret.clone()?;
        Some((entry.policy.clone(), secret))
    }

    /// Resolve a token to its bound policy, or `None` if unknown or expired at `now_ms`.
    pub fn resolve(&self, token: &str, now_ms: u64) -> Option<Policy> {
        self.resolve_full(token, now_ms).map(|(policy, _)| policy)
    }

    /// Resolve a token to its bound policy and absolute expiry, or `None` if unknown or
    /// expired at `now_ms`. Used by the provision projection.
    pub fn resolve_full(&self, token: &str, now_ms: u64) -> Option<(Policy, u64)> {
        let entries = self.entries.read();
        let entry = entries.get(token)?;
        if entry.expires_at_ms <= now_ms {
            return None;
        }
        Some((entry.policy.clone(), entry.expires_at_ms))
    }

    /// Revoke a token immediately. Returns whether a token was removed.
    pub fn revoke(&self, token: &str) -> bool {
        self.entries.write().remove(token).is_some()
    }

    /// Evict every entry expired at `now_ms`, returning how many were removed. `resolve`
    /// already refuses expired entries, but without this the table only grows — every
    /// SigV4 `/provision` mints a dummy credential that would otherwise never be reclaimed.
    /// A background sweeper calls this periodically.
    pub fn sweep(&self, now_ms: u64) -> usize {
        let mut entries = self.entries.write();
        let before = entries.len();
        entries.retain(|_, e| e.expires_at_ms > now_ms);
        before - entries.len()
    }

    /// The number of live (un-swept) entries. For metrics/tests.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Whether the token table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn empty_policy() -> Policy {
        Policy { rules: vec![] }
    }

    #[test]
    fn mint_then_resolve_within_ttl() {
        let tokens = Tokens::new();
        let minted = tokens.mint(empty_policy(), 60, 1_000);
        assert!(tokens.resolve(&minted.token, 1_000).is_some());
        // Just before expiry.
        assert!(tokens.resolve(&minted.token, 60_999).is_some());
    }

    #[test]
    fn token_expires() {
        let tokens = Tokens::new();
        let minted = tokens.mint(empty_policy(), 60, 1_000);
        // At/after expiry (1000 + 60_000).
        assert!(tokens.resolve(&minted.token, 61_000).is_none());
    }

    #[test]
    fn unknown_token_resolves_none() {
        let tokens = Tokens::new();
        assert!(tokens.resolve("bogus", 1).is_none());
    }

    #[test]
    fn sigv4_mint_resolves_by_access_key_id() {
        let tokens = Tokens::new();
        let m = tokens.mint_sigv4(empty_policy(), 60, 1_000);
        assert!(m.access_key_id.starts_with("AKIAHALTER"));
        let (_policy, secret) = tokens.resolve_sigv4(&m.access_key_id, 1_000).unwrap();
        assert_eq!(secret, m.secret_access_key);
        // Expired and unknown both miss.
        assert!(tokens.resolve_sigv4(&m.access_key_id, 61_000).is_none());
        assert!(tokens.resolve_sigv4("AKIAUNKNOWN", 1_000).is_none());
        // A bearer token is not a SigV4 credential.
        let bearer = tokens.mint(empty_policy(), 60, 1_000);
        assert!(tokens.resolve_sigv4(&bearer.token, 1_000).is_none());
    }

    #[test]
    fn revoke_invalidates() {
        let tokens = Tokens::new();
        let minted = tokens.mint(empty_policy(), 60, 0);
        assert!(tokens.revoke(&minted.token));
        assert!(tokens.resolve(&minted.token, 1).is_none());
        assert!(!tokens.revoke(&minted.token));
    }

    #[test]
    fn sweep_evicts_only_expired_entries() {
        let tokens = Tokens::new();
        // One short-lived (60s) and one long-lived (3600s) token, minted at t=1000.
        let short = tokens.mint(empty_policy(), 60, 1_000);
        let long = tokens.mint(empty_policy(), 3600, 1_000);
        let dummy = tokens.mint_sigv4(empty_policy(), 60, 1_000);
        assert_eq!(tokens.len(), 3);

        // At t=61_000 the short token and dummy cred are expired; sweep reclaims exactly
        // those two and leaves the long-lived token resolvable.
        assert_eq!(tokens.sweep(61_000), 2);
        assert_eq!(tokens.len(), 1);
        assert!(tokens.resolve(&short.token, 61_000).is_none());
        assert!(tokens.resolve_sigv4(&dummy.access_key_id, 61_000).is_none());
        assert!(tokens.resolve(&long.token, 61_000).is_some());

        // A second sweep at the same time is a no-op.
        assert_eq!(tokens.sweep(61_000), 0);
    }
}
