//! Multi-tenant mint authorization. When one hackamore serves more than one trust domain,
//! a tenant authenticates to the mint endpoint and may only mint tokens scoped to the
//! targets it **owns**. Without this, any caller could submit a policy naming another
//! tenant's target and launder its credential.
//!
//! Single-trust-domain deployments leave this registry empty, and minting is open (the
//! mint endpoint is the operator's own surface).

use parking_lot::RwLock;
use std::collections::{BTreeSet, HashMap};

/// Maps a tenant credential (an opaque key the operator issues) to the set of service
/// instance names that tenant owns.
#[derive(Default)]
pub struct Tenants {
    owned: RwLock<HashMap<String, BTreeSet<String>>>,
}

impl Tenants {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) a tenant's owned-target set.
    pub fn insert(&self, key: impl Into<String>, targets: impl IntoIterator<Item = String>) {
        self.owned
            .write()
            .insert(key.into(), targets.into_iter().collect());
    }

    /// Whether any tenant is configured. Empty ⇒ single-trust-domain ⇒ minting is open.
    pub fn is_empty(&self) -> bool {
        self.owned.read().is_empty()
    }

    /// The owned-target set for `key`, or `None` if the tenant key is unknown.
    pub fn owned(&self, key: &str) -> Option<BTreeSet<String>> {
        self.owned.read().get(key).cloned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_until_seeded_then_resolves_owned() {
        let t = Tenants::new();
        assert!(t.is_empty());
        t.insert("tenant-a", ["github".to_string(), "eks-prod".to_string()]);
        assert!(!t.is_empty());
        let owned = t.owned("tenant-a").unwrap();
        assert!(owned.contains("github"));
        assert!(!owned.contains("aws-acct-b"));
        assert!(t.owned("nobody").is_none());
    }
}
