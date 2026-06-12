//! hackamore control plane: short-lived policy-bound token minting, the credential vault,
//! and the audit sink. The data plane ([`gateway`]) holds an `Arc<ControlPlane>` and
//! consults it on every request; the policy engine ([`policy`]) never touches any of
//! this — it stays pure. There is no agent registry: a token *is* a policy binding.

pub mod audit;
pub mod credentials;
pub mod providers;
pub mod tenants;
pub mod tokens;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub use audit::{AuditSink, FileAudit, InMemoryAudit, TracingAudit};
pub use credentials::{CredentialStore, InMemoryCredentials, Secret};
pub use providers::{
    CachingCredentials, CredentialProvider, EksGetTokenProvider, GitHubAppProvider, MintedSecret,
    pkcs8_from_pem, spawn_refresher,
};
pub use tenants::Tenants;
pub use tokens::{SigV4Mint, Tokens};

/// Wall-clock time in Unix epoch milliseconds. The control-plane core takes time as a
/// parameter for testability; this is the production source the binary passes in.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The assembled control plane. Each capability is an independent component; the
/// credential store and audit sink are trait objects so they can be swapped without
/// touching the data plane.
pub struct ControlPlane {
    pub tokens: Tokens,
    pub tenants: Tenants,
    pub credentials: Arc<dyn CredentialStore>,
    pub audit: Arc<dyn AuditSink>,
}

impl ControlPlane {
    /// Assemble a control plane from its components.
    pub fn new(credentials: Arc<dyn CredentialStore>, audit: Arc<dyn AuditSink>) -> Self {
        Self {
            tokens: Tokens::new(),
            tenants: Tenants::new(),
            credentials,
            audit,
        }
    }

    /// A control plane with an in-memory credential store and a `tracing` audit sink —
    /// the production default. The returned credential store handle lets the caller seed
    /// secrets after construction.
    pub fn with_defaults() -> (Self, Arc<InMemoryCredentials>) {
        let credentials = Arc::new(InMemoryCredentials::new());
        let plane = Self::new(credentials.clone(), Arc::new(TracingAudit));
        (plane, credentials)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn now_ms_is_nonzero() {
        assert!(now_ms() > 0);
    }

    #[test]
    fn with_defaults_wires_components() {
        let (plane, creds) = ControlPlane::with_defaults();
        creds.insert("github-app", Secret::new("tok"));
        assert!(plane.credentials.resolve("github-app").is_some());
    }
}
