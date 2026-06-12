//! Minting, rotating credential providers.
//!
//! The base [`crate::credentials::InMemoryCredentials`] vault is static: an id maps to a
//! pre-provisioned secret. Real upstreams instead want *short-lived* credentials minted on
//! demand and rotated before they expire — an AWS EKS `get-token` (a presigned STS URL,
//! ~15 min) or a GitHub-App installation token (~1 h). This module adds that without
//! changing the data plane: a [`CredentialProvider`] mints a secret, and
//! [`CachingCredentials`] caches the latest minted value behind the *synchronous*
//! [`CredentialStore`] the gateway already calls on the request path. A background refresher
//! ([`CachingCredentials::refresh_due`], driven by [`spawn_refresher`]) re-mints before
//! expiry, so `resolve` stays fast and never blocks — and **fails closed**: until a value is
//! minted, `resolve` returns `None` and the request is denied.

use crate::credentials::{CredentialStore, Secret};
use base64::Engine;
use parking_lot::RwLock;
use ring::{digest, hmac, rand, signature};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A freshly minted secret and when it expires (epoch ms).
#[derive(Clone)]
pub struct MintedSecret {
    pub secret: Secret,
    pub expires_at_ms: u64,
}

/// Mints a short-lived upstream credential, and re-mints it on rotation. Async because real
/// minters call out (the GitHub-App exchange is HTTP; the EKS presign is local but shares
/// the signature). Returns the secret and its expiry; an error fails closed (the cache keeps
/// the previous value until it too expires).
pub trait CredentialProvider: Send + Sync {
    /// Mint a fresh secret as of `now_ms`.
    fn mint(
        &self,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<MintedSecret, String>> + Send + '_>>;

    /// Re-mint this many milliseconds *before* the cached secret expires, to rotate without
    /// a gap. Defaults to one minute.
    fn refresh_skew_ms(&self) -> u64 {
        60_000
    }
}

/// A credential store that serves the latest minted value for each provider-backed id, and
/// pre-seeded static secrets for the rest. The data plane calls [`CredentialStore::resolve`]
/// (sync); minting happens out of band in [`Self::refresh_due`].
pub struct CachingCredentials {
    static_secrets: RwLock<HashMap<String, Secret>>,
    providers: HashMap<String, Arc<dyn CredentialProvider>>,
    cache: RwLock<HashMap<String, MintedSecret>>,
}

impl CachingCredentials {
    /// A store with the given static secrets and minting providers. Ids must be disjoint;
    /// a provider id shadows a static one of the same name.
    pub fn new(
        static_secrets: HashMap<String, Secret>,
        providers: HashMap<String, Arc<dyn CredentialProvider>>,
    ) -> Self {
        Self {
            static_secrets: RwLock::new(static_secrets),
            providers,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Register or replace a static secret (used in tests and for late-bound config).
    pub fn insert_static(&self, id: impl Into<String>, secret: Secret) {
        self.static_secrets.write().insert(id.into(), secret);
    }

    /// Mint every provider-backed credential whose cached value is missing or within its
    /// refresh skew of expiry. Returns the ids (re)minted. Errors are logged and skipped so
    /// one failing provider doesn't stall the others.
    pub async fn refresh_due(&self, now_ms: u64) -> Vec<String> {
        let mut refreshed = Vec::new();
        for (id, provider) in &self.providers {
            if !self.needs_refresh(id, provider.as_ref(), now_ms) {
                continue;
            }
            match provider.mint(now_ms).await {
                Ok(minted) => {
                    self.cache.write().insert(id.clone(), minted);
                    refreshed.push(id.clone());
                }
                Err(e) => tracing::warn!(credential = %id, "credential mint failed: {e}"),
            }
        }
        refreshed
    }

    fn needs_refresh(&self, id: &str, provider: &dyn CredentialProvider, now_ms: u64) -> bool {
        match self.cache.read().get(id) {
            None => true,
            Some(m) => now_ms.saturating_add(provider.refresh_skew_ms()) >= m.expires_at_ms,
        }
    }
}

impl CredentialStore for CachingCredentials {
    fn resolve(&self, id: &str) -> Option<Secret> {
        if let Some(s) = self.static_secrets.read().get(id) {
            return Some(s.clone());
        }
        // Provider-backed: serve the cached minted value (the refresher keeps it fresh).
        // Absent ⇒ not yet minted ⇒ fail closed.
        self.cache.read().get(id).map(|m| m.secret.clone())
    }
}

/// Spawn a background task that calls [`CachingCredentials::refresh_due`] every
/// `interval`, using `clock` for the current time. Priming and rotation both flow through
/// it. The task lives for the process; it is dropped when the runtime shuts down.
pub fn spawn_refresher(
    creds: Arc<CachingCredentials>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    interval: std::time::Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let refreshed = creds.refresh_due(clock()).await;
            if !refreshed.is_empty() {
                tracing::debug!(?refreshed, "rotated credentials");
            }
        }
    });
}

// ---------------------------------------------------------------------------------------
// AWS EKS get-token provider
// ---------------------------------------------------------------------------------------

/// Mints an EKS `get-token` credential: a presigned STS `GetCallerIdentity` URL (SigV4
/// query auth, scoped to the cluster via the signed `x-k8s-aws-id` header), base64url-
/// encoded with the `k8s-aws-v1.` prefix — exactly what `aws eks get-token` produces and
/// what the kubelet/`kubectl` send as a bearer token. Fully local: no network, just the
/// account credential and the SigV4 primitives.
pub struct EksGetTokenProvider {
    pub access_key_id: String,
    pub secret_access_key: Secret,
    pub region: String,
    pub cluster_name: String,
}

/// EKS tokens are valid for 15 minutes; mint with that window.
const EKS_TOKEN_TTL_MS: u64 = 15 * 60 * 1000;
/// STS presign expiry (seconds) baked into the URL.
const EKS_PRESIGN_EXPIRES: u64 = 900;

impl EksGetTokenProvider {
    /// Build the `k8s-aws-v1.<base64url(presigned-url)>` token for `now_ms`.
    pub fn token(&self, now_ms: u64) -> String {
        let url = self.presigned_url(now_ms);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes());
        format!("k8s-aws-v1.{encoded}")
    }

    fn presigned_url(&self, now_ms: u64) -> String {
        let host = format!("sts.{}.amazonaws.com", self.region);
        let (amz_date, datestamp) = format_amz_datetime(now_ms);
        let scope = format!("{datestamp}/{}/sts/aws4_request", self.region);
        let signed_headers = "host;x-k8s-aws-id";
        // Query params that participate in the signature (everything but X-Amz-Signature),
        // already in sorted order (uppercase 'A' params sort before lowercase 'k'/'V').
        let credential = format!("{}/{scope}", self.access_key_id);
        let expires = EKS_PRESIGN_EXPIRES.to_string();
        let params = [
            ("Action", "GetCallerIdentity"),
            ("Version", "2011-06-15"),
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", credential.as_str()),
            ("X-Amz-Date", amz_date.as_str()),
            ("X-Amz-Expires", expires.as_str()),
            ("X-Amz-SignedHeaders", signed_headers),
        ];
        let canonical_query = canonical_query(&params);
        let canonical_headers = format!("host:{host}\nx-k8s-aws-id:{}\n", self.cluster_name);
        let payload_hash = sha256_hex(b"");
        let canonical_request = format!(
            "GET\n/\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signing_key = derive_signing_key(
            self.secret_access_key.expose(),
            &datestamp,
            &self.region,
            "sts",
        );
        let signature = to_hex(&hmac256(&signing_key, string_to_sign.as_bytes()));
        format!("https://{host}/?{canonical_query}&X-Amz-Signature={signature}")
    }
}

impl CredentialProvider for EksGetTokenProvider {
    fn mint(
        &self,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<MintedSecret, String>> + Send + '_>> {
        let token = self.token(now_ms);
        Box::pin(async move {
            Ok(MintedSecret {
                secret: Secret::new(token),
                expires_at_ms: now_ms.saturating_add(EKS_TOKEN_TTL_MS),
            })
        })
    }
}

// ---------------------------------------------------------------------------------------
// GitHub App installation-token provider
// ---------------------------------------------------------------------------------------

/// Mints a GitHub-App installation token: sign a short-lived RS256 JWT with the app's
/// private key, then exchange it at `POST /app/installations/{id}/access_tokens` for an
/// installation token (~1 h). The JWT signing is local; the exchange is one HTTP call.
pub struct GitHubAppProvider {
    pub app_id: String,
    pub installation_id: String,
    /// The app's RSA private key in PKCS#8 DER (parse from PEM with [`pkcs8_from_pem`]).
    pub private_key_pkcs8_der: Vec<u8>,
    /// API base, e.g. `https://api.github.com` (override for GHES or a test mock).
    pub api_base: String,
    pub client: reqwest::Client,
}

/// GitHub installation tokens last an hour; refresh well before then.
const GH_TOKEN_TTL_MS: u64 = 55 * 60 * 1000;

impl GitHubAppProvider {
    /// Build the signed app JWT for `now_ms` (valid 60 s in the past to 9 min ahead, per
    /// GitHub's guidance to tolerate clock skew). Public for testing.
    pub fn app_jwt(&self, now_ms: u64) -> Result<String, String> {
        let now_s = now_ms / 1000;
        let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = b64url(
            format!(
                r#"{{"iat":{},"exp":{},"iss":"{}"}}"#,
                now_s.saturating_sub(60),
                now_s + 540,
                self.app_id
            )
            .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");
        let key = signature::RsaKeyPair::from_pkcs8(&self.private_key_pkcs8_der)
            .map_err(|e| format!("invalid app private key: {e}"))?;
        let mut sig = vec![0u8; key.public().modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &rand::SystemRandom::new(),
            signing_input.as_bytes(),
            &mut sig,
        )
        .map_err(|e| format!("jwt signing failed: {e}"))?;
        Ok(format!("{signing_input}.{}", b64url(&sig)))
    }
}

impl CredentialProvider for GitHubAppProvider {
    fn mint(
        &self,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<MintedSecret, String>> + Send + '_>> {
        Box::pin(async move {
            let jwt = self.app_jwt(now_ms)?;
            let url = format!(
                "{}/app/installations/{}/access_tokens",
                self.api_base.trim_end_matches('/'),
                self.installation_id
            );
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&jwt)
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .header(reqwest::header::USER_AGENT, "hackamore")
                .send()
                .await
                .map_err(|e| format!("installation-token request failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("installation-token HTTP {}", resp.status()));
            }
            let body: InstallationToken = resp
                .json()
                .await
                .map_err(|e| format!("installation-token decode failed: {e}"))?;
            Ok(MintedSecret {
                secret: Secret::new(body.token),
                expires_at_ms: now_ms.saturating_add(GH_TOKEN_TTL_MS),
            })
        })
    }
}

#[derive(serde::Deserialize)]
struct InstallationToken {
    token: String,
}

/// Decode a PKCS#8 PEM private key (`-----BEGIN PRIVATE KEY-----`) into DER bytes for
/// [`GitHubAppProvider::private_key_pkcs8_der`].
pub fn pkcs8_from_pem(pem: &str) -> Result<Vec<u8>, String> {
    let begin = "-----BEGIN PRIVATE KEY-----";
    let end = "-----END PRIVATE KEY-----";
    let start = pem.find(begin).ok_or("no PKCS#8 PRIVATE KEY block")?;
    let after = &pem[start + begin.len()..];
    let stop = after.find(end).ok_or("unterminated PRIVATE KEY block")?;
    let body: String = after[..stop].split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| format!("base64 decode key: {e}"))
}

// ---------------------------------------------------------------------------------------
// SigV4 / encoding primitives (kept local to avoid a control→gateway dependency)
// ---------------------------------------------------------------------------------------

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Canonical SigV4 query string from already-sorted `(name, value)` params: URI-encode each
/// (slashes included) and join with `&`.
fn canonical_query(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k.as_bytes()), uri_encode(v.as_bytes())))
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'~' | b'.' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn derive_signing_key(secret: &str, datestamp: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac256(&k_date, region.as_bytes());
    let k_service = hmac256(&k_region, service.as_bytes());
    hmac256(&k_service, b"aws4_request")
}

fn hmac256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn sha256_hex(data: &[u8]) -> String {
    to_hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Format epoch ms as the SigV4 `YYYYMMDDTHHMMSSZ` and `YYYYMMDD` strings (UTC).
fn format_amz_datetime(epoch_ms: u64) -> (String, String) {
    let secs = (epoch_ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, m, d) = civil_from_days(days);
    (
        format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z"),
        format!("{y:04}{m:02}{d:02}"),
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn eks_token_has_expected_shape_and_is_deterministic() {
        let p = EksGetTokenProvider {
            access_key_id: "AKIDTEST".into(),
            secret_access_key: Secret::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            region: "us-east-1".into(),
            cluster_name: "prod-cluster".into(),
        };
        let now = 1_700_000_000_000;
        let token = p.token(now);
        assert!(token.starts_with("k8s-aws-v1."));
        let url_b64 = token.strip_prefix("k8s-aws-v1.").unwrap();
        let url = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(url_b64)
                .unwrap(),
        )
        .unwrap();
        assert!(url.starts_with("https://sts.us-east-1.amazonaws.com/?"));
        assert!(url.contains("Action=GetCallerIdentity"));
        assert!(url.contains("X-Amz-Credential=AKIDTEST%2F"));
        assert!(url.contains("X-Amz-Expires=900"));
        assert!(url.contains("X-Amz-SignedHeaders=host%3Bx-k8s-aws-id"));
        assert!(url.contains("X-Amz-Signature="));
        // The cluster is bound via the signed header, never in the URL query.
        assert!(!url.contains("prod-cluster"));
        // Same inputs → identical token (no hidden randomness).
        assert_eq!(token, p.token(now));
        // A later timestamp produces a different signature/date.
        assert_ne!(token, p.token(now + 86_400_000));
    }

    #[test]
    fn github_app_jwt_is_well_formed_and_signs() {
        let pem = include_str!("../testdata/github_app_key.pem");
        let der = pkcs8_from_pem(pem).unwrap();
        let p = GitHubAppProvider {
            app_id: "123456".into(),
            installation_id: "789".into(),
            private_key_pkcs8_der: der,
            api_base: "https://api.github.com".into(),
            client: reqwest::Client::new(),
        };
        let now = 1_700_000_000_000;
        let jwt = p.app_jwt(now).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "header.claims.signature");
        let header = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0])
                .unwrap(),
        )
        .unwrap();
        assert!(header.contains("RS256"));
        let claims = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .unwrap(),
        )
        .unwrap();
        assert!(claims.contains(r#""iss":"123456""#));
        assert!(claims.contains(r#""iat":1699999940"#)); // now_s - 60
        assert!(claims.contains(r#""exp":1700000540"#)); // now_s + 540
        // RSA-2048 signature is 256 bytes → 342 base64url chars (no padding).
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[2])
                .unwrap()
                .len(),
            256
        );
    }

    /// A trivial provider whose secret encodes its mint time + expiry window, for exercising
    /// the cache/refresh logic deterministically.
    struct StubProvider {
        ttl_ms: u64,
    }
    impl CredentialProvider for StubProvider {
        fn mint(
            &self,
            now_ms: u64,
        ) -> Pin<Box<dyn Future<Output = Result<MintedSecret, String>> + Send + '_>> {
            let ttl = self.ttl_ms;
            Box::pin(async move {
                Ok(MintedSecret {
                    secret: Secret::new(format!("minted@{now_ms}")),
                    expires_at_ms: now_ms + ttl,
                })
            })
        }
        fn refresh_skew_ms(&self) -> u64 {
            1_000
        }
    }

    #[tokio::test]
    async fn caching_store_fails_closed_then_serves_and_rotates() {
        let mut providers: HashMap<String, Arc<dyn CredentialProvider>> = HashMap::new();
        providers.insert("eks".into(), Arc::new(StubProvider { ttl_ms: 10_000 }));
        let mut statics = HashMap::new();
        statics.insert("ghs".to_string(), Secret::new("static-secret"));
        let store = CachingCredentials::new(statics, providers);

        // Static secret resolves immediately; provider-backed fails closed until minted.
        assert_eq!(store.resolve("ghs").unwrap().expose(), "static-secret");
        assert!(store.resolve("eks").is_none());

        // Prime at t=1000 → resolves the minted value.
        let refreshed = store.refresh_due(1_000).await;
        assert_eq!(refreshed, vec!["eks".to_string()]);
        assert_eq!(store.resolve("eks").unwrap().expose(), "minted@1000");

        // Well within TTL → no rotation.
        assert!(store.refresh_due(2_000).await.is_empty());
        assert_eq!(store.resolve("eks").unwrap().expose(), "minted@1000");

        // Within refresh skew of expiry (expires at 11_000, skew 1_000) → rotates.
        let refreshed = store.refresh_due(10_500).await;
        assert_eq!(refreshed, vec!["eks".to_string()]);
        assert_eq!(store.resolve("eks").unwrap().expose(), "minted@10500");
    }

    #[test]
    fn pkcs8_from_pem_round_trips() {
        let pem = include_str!("../testdata/github_app_key.pem");
        let der = pkcs8_from_pem(pem).unwrap();
        assert!(signature::RsaKeyPair::from_pkcs8(&der).is_ok());
        assert!(pkcs8_from_pem("not a key").is_err());
    }
}
